package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzedv1 "github.com/authzed/authzed-go/v1"
	"github.com/ory/dockertest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var zedTestServerContainer = &dockertest.RunOptions{
	Repository:   "quay.io/authzed/spicedb",
	Tag:          "latest",
	Cmd:          []string{"serve-testing"},
	ExposedPorts: []string{"50051/tcp"},
}

type catchallHandler struct {
	t *testing.T
}

func (ah catchallHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "should never appear")
	w.Header().Add("Another-Header", "hiya")
	w.Header().Add("Another-Header", "hello")
	w.WriteHeader(418)
}

func TestMissingQueryParameter(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "", map[string]string{})
	defer res.Body.Close()
	require.Equal(t, 401, res.StatusCode)
}

func TestMissingAuthHeader(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "", map[string]string{
		"dashboard": "foobar",
	})
	defer res.Body.Close()
	require.Equal(t, 401, res.StatusCode)
}

func TestInvalidAuthHeader(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Basic Foo", map[string]string{
		"dashboard": "foobar",
	})
	defer res.Body.Close()
	require.Equal(t, 401, res.StatusCode)
}

func TestInvalidToken(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer sometoken", map[string]string{
		"dashboard": "foobar",
	})
	defer res.Body.Close()
	require.Equal(t, 403, res.StatusCode)
}

func TestValidToken(t *testing.T) {
	client, serverURL := startForTesting(t)

	// Add a relation to make the permission valid.
	_, err := client.WriteRelationships(
		context.Background(),
		&v1.WriteRelationshipsRequest{
			Updates: []*v1.RelationshipUpdate{
				{
					Operation: v1.RelationshipUpdate_OPERATION_CREATE,
					Relationship: &v1.Relationship{
						Resource: &v1.ObjectReference{
							ObjectType: "test/dashboard",
							ObjectId:   "foobar",
						},
						Relation: "viewer",
						Subject: &v1.SubjectReference{Object: &v1.ObjectReference{
							ObjectType: "test/token",
							ObjectId:   "sometoken",
						}},
					},
				},
			},
		},
	)
	require.NoError(t, err)

	// To ensure the written relationship is found.
	time.Sleep(20 * time.Millisecond)

	// Check for the correct token.
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer sometoken", map[string]string{
		"dashboard": "foobar",
	})
	defer res.Body.Close()
	require.Equal(t, 418, res.StatusCode)

	// Ensure the ACAO was reset, but other headers are passed through.
	require.Equal(t, "", res.Header.Get("Access-Control-Allow-Origin"))
	require.Equal(t, []string{"hiya", "hello"}, res.Header.Values("Another-Header"))

	// Check for an incorrect token.
	res = loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer anothertoken", map[string]string{
		"dashboard": "foobar",
	})
	defer res.Body.Close()
	require.Equal(t, 403, res.StatusCode)

	// Check for another dashboard
	res = loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer sometoken", map[string]string{
		"dashboard": "anotherdashboard",
	})
	defer res.Body.Close()
	require.Equal(t, 403, res.StatusCode)
}

func startForTesting(t *testing.T) (*authzedv1.Client, string) {
	tester, err := newTester(zedTestServerContainer, 50051)
	require.NoError(t, err)
	t.Cleanup(tester.cleanup)

	mux := http.NewServeMux()
	mux.Handle("/", catchallHandler{t})

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	client, err := authzedv1.NewClient(fmt.Sprintf("localhost:%s", tester.port), opts...)
	require.NoError(t, err)

	handler := proxyHandler(
		client,
		mux,
		"test/dashboard",
		"dashboard",
		"view",
		"test/token",
		"",
	)

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return client, server.URL
}

func loadURL(t *testing.T, method string, callURL string, authHeader string, parameters map[string]string) *http.Response {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest(method, callURL, nil)
	require.NoError(t, err)

	q := req.URL.Query()
	for key, value := range parameters {
		q.Add(key, value)
	}

	req.URL.RawQuery = q.Encode()
	req.Header.Set("Authorization", authHeader)

	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

type testHandle struct {
	port    string
	cleanup func()
}

const maxAttempts = 5

func newTester(containerOpts *dockertest.RunOptions, portNum uint16) (*testHandle, error) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, fmt.Errorf("Could not connect to docker: %w", err)
	}

	resource, err := pool.RunWithOptions(containerOpts)
	if err != nil {
		return nil, fmt.Errorf("Could not start resource: %w", err)
	}

	port := resource.GetPort(fmt.Sprintf("%d/tcp", portNum))

	cleanup := func() {
		// When you're done, kill and remove the container
		if err = pool.Purge(resource); err != nil {
			log.Fatalf("Could not purge resource: %s", err)
		}
	}

	// Give the service time to boot.
	counter := 0
	for {
		time.Sleep(10 * time.Millisecond)

		var opts []grpc.DialOption
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

		// Create an Authzed client
		client, err := authzedv1.NewClient(fmt.Sprintf("localhost:%s", port), opts...)
		if err != nil {
			return nil, fmt.Errorf("Could not create client: %w", err)
		}

		// Write a basic schema.
		_, err = client.WriteSchema(context.Background(), &v1.WriteSchemaRequest{
			Schema: `definition test/token {}

definition test/dashboard {
	relation viewer: test/token
	permission view = viewer
}
`,
		})
		if err != nil {
			counter++
			if counter > maxAttempts {
				return nil, fmt.Errorf("Failed to start container: %w", err)
			}
			continue
		}

		// Wait for schema to be available
		time.Sleep(50 * time.Millisecond)
		return &testHandle{port: port, cleanup: cleanup}, nil
	}
}
