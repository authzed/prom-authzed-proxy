package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	v0 "github.com/authzed/authzed-go/proto/authzed/api/v0"
	"github.com/authzed/authzed-go/proto/authzed/api/v1alpha1"
	authzedv0 "github.com/authzed/authzed-go/v0"
	authzedv1 "github.com/authzed/authzed-go/v1alpha1"
	"github.com/ory/dockertest"
	"github.com/rs/cors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

var zedTestServerContainer = &dockertest.RunOptions{
	Repository:   "quay.io/authzed/zed-testserver",
	Tag:          "latest",
	Cmd:          []string{"run"},
	ExposedPorts: []string{"50051/tcp"},
}

type catchallHandler struct {
	t *testing.T
}

func (ah catchallHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(418)
}

func TestMissingQueryParameter(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "", map[string]string{})
	require.Equal(t, 400, res.StatusCode)
}

func TestMissingAuthHeader(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "", map[string]string{
		"dashboard": "foobar",
	})
	require.Equal(t, 401, res.StatusCode)
}

func TestInvalidAuthHeader(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Basic Foo", map[string]string{
		"dashboard": "foobar",
	})
	require.Equal(t, 403, res.StatusCode)
}

func TestInvalidToken(t *testing.T) {
	_, serverURL := startForTesting(t)
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer sometoken", map[string]string{
		"dashboard": "foobar",
	})
	require.Equal(t, 403, res.StatusCode)
}

func TestValidToken(t *testing.T) {
	client, serverURL := startForTesting(t)

	// Add a relation to make the permission valid.
	_, err := client.Write(context.Background(), &v0.WriteRequest{
		Updates: []*v0.RelationTupleUpdate{
			{
				Operation: v0.RelationTupleUpdate_CREATE,
				Tuple: &v0.RelationTuple{
					ObjectAndRelation: &v0.ObjectAndRelation{Namespace: "test/dashboard", ObjectId: "foobar", Relation: "viewer"},
					User: &v0.User{UserOneof: &v0.User_Userset{
						Userset: &v0.ObjectAndRelation{Namespace: "test/token", ObjectId: "sometoken", Relation: "..."},
					}},
				},
			},
		},
	})
	require.NoError(t, err)

	// To ensure the written relationship is found.
	time.Sleep(20 * time.Millisecond)

	// Check for the correct token.
	res := loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer sometoken", map[string]string{
		"dashboard": "foobar",
	})
	require.Equal(t, 418, res.StatusCode)

	// Check for an incorrect token.
	res = loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer anothertoken", map[string]string{
		"dashboard": "foobar",
	})
	require.Equal(t, 403, res.StatusCode)

	// Check for another dashboard
	res = loadURL(t, "GET", fmt.Sprintf("%s/something", serverURL), "Bearer sometoken", map[string]string{
		"dashboard": "anotherdashboard",
	})
	require.Equal(t, 403, res.StatusCode)
}

func startForTesting(t *testing.T) (*authzedv0.Client, string) {
	tester, err := newTester(zedTestServerContainer, 50051)
	require.NoError(t, err)
	t.Cleanup(tester.cleanup)

	mux := http.NewServeMux()
	mux.Handle("/", catchallHandler{t})

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())

	client, err := authzedv0.NewClient(fmt.Sprintf("localhost:%s", tester.port), opts...)
	require.NoError(t, err)

	handler := authzedHandler{
		client:          client,
		objectDefPath:   "test/dashboard",
		permission:      "view",
		subjectDefPath:  "test/token",
		subjectRelation: "...",
		queryParameter:  "dashboard",
		labelMux:        mux,
	}

	chandler := cors.Default().Handler(handler)
	server := httptest.NewServer(chandler)
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
		opts = append(opts, grpc.WithInsecure())

		// Create an Authzed client
		client, err := authzedv1.NewClient(fmt.Sprintf("localhost:%s", port), opts...)
		if err != nil {
			return nil, fmt.Errorf("Could not create client: %w", err)
		}

		// Write a basic schema.
		_, err = client.WriteSchema(context.Background(), &v1alpha1.WriteSchemaRequest{
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

		return &testHandle{port: port, cleanup: cleanup}, nil
	}
}
