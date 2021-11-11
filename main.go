package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	v0 "github.com/authzed/authzed-go/proto/authzed/api/v0"
	"github.com/authzed/authzed-go/v0"
	"github.com/authzed/grpcutil"
	"github.com/jzelinskie/cobrautil"
	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

const (
	flagPrefixZerolog = "log"
	flagPrefixMetrics = "metrics"
	flagPrefixHttp    = "http"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "prom-authzed-proxy",
		Short: "Proxy that gates access to Prometheus based on an Authzed Check call",
		PreRunE: cobrautil.CommandStack(
			cobrautil.SyncViperPreRunE("prom-authzed-proxy"),
			cobrautil.ZeroLogPreRunE(flagPrefixZerolog, zerolog.InfoLevel),
		),
		Run: rootRun,
	}

	cobrautil.RegisterZeroLogFlags(rootCmd.Flags(), flagPrefixZerolog)
	cobrautil.RegisterHttpServerFlags(rootCmd.Flags(), flagPrefixMetrics, "metrics", ":9090", true)
	cobrautil.RegisterHttpServerFlags(rootCmd.Flags(), flagPrefixHttp, "http", ":8443", true)

	rootCmd.Flags().StringSlice(flagPrefixHttp+"-cors-allowed-origins", []string{"*"}, "allowed origins for CORS requests")
	rootCmd.Flags().String("upstream-prom-addr", "", "address of the upstream Prometheus")
	rootCmd.Flags().String("object-id-parameter", "", "the name of the query parameter in incoming calls to use as the object ID in Authzed Check calls")

	rootCmd.Flags().String("authzed-endpoint", "grpc.authzed.com:443", "address of the Authzed to use for checking")
	rootCmd.Flags().String("authzed-tls-cert-path", "", "path at which to find a certificate for authzed TLS")
	rootCmd.Flags().String("authzed-token", "", "authzed token to use for checking tenancy")
	rootCmd.Flags().Bool("authzed-insecure", false, "connect to Authzed without TLS")
	rootCmd.Flags().String("authzed-object-definition-path", "", "full object definition path in Authzed to check")
	rootCmd.Flags().String("authzed-permission", "", "permission in Authzed to check")
	rootCmd.Flags().String("authzed-subject-definition-path", "", "full subject definition path in Authzed to check")
	rootCmd.Flags().String("authzed-subject-relation", "...", "subject relation in Authzed to check. Defaults to ...")

	rootCmd.Execute()
}

func metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func rootRun(cmd *cobra.Command, args []string) {
	authzedObjectDefinitionPath := cobrautil.MustGetString(cmd, "authzed-object-definition-path")
	if authzedObjectDefinitionPath == "" {
		log.Fatal().Msg("must specify valid Authzed object definition path")
	}

	authzedSubjectDefinitionPath := cobrautil.MustGetString(cmd, "authzed-subject-definition-path")
	if authzedObjectDefinitionPath == "" {
		log.Fatal().Msg("must specify valid Authzed subject definition path")
	}

	authzedSubjectRelation := cobrautil.MustGetString(cmd, "authzed-subject-relation")
	if authzedSubjectRelation == "" {
		log.Fatal().Msg("must specify valid Authzed subject relation")
	}

	authzedPermission := cobrautil.MustGetString(cmd, "authzed-permission")
	if authzedPermission == "" {
		log.Fatal().Msg("must specify valid Authzed permission")
	}

	authzedEndpoint := cobrautil.MustGetString(cmd, "authzed-endpoint")
	if authzedEndpoint == "" {
		log.Fatal().Msg("must specify valid Authzed endpoint")
	}

	authzedToken := cobrautil.MustGetString(cmd, "authzed-token")
	if authzedToken == "" {
		log.Fatal().Msg("must specify valid Authzed token")
	}

	var opts []grpc.DialOption
	if cobrautil.MustGetBool(cmd, "authzed-insecure") {
		opts = append(opts, grpc.WithInsecure())
		opts = append(opts, grpcutil.WithInsecureBearerToken(authzedToken))
	} else {
		if authzedCertPath := cobrautil.MustGetString(cmd, "authzed-tls-cert-path"); authzedCertPath != "" {
			opts = append(opts, grpcutil.WithCustomCerts(authzedCertPath, grpcutil.VerifyCA))
		} else {
			opts = append(opts, grpcutil.WithSystemCerts(grpcutil.VerifyCA))
		}
		opts = append(opts, grpcutil.WithBearerToken(authzedToken))
	}

	// Create an Authzed client
	authzedClient, err := authzed.NewClient(authzedEndpoint, opts...)
	if err != nil {
		log.Fatal().Err(err).Msg("could not create Authzed client")
	}

	// NOTE: Based on https://github.com/prometheus-community/prom-label-proxy/blob/master/main.go
	// Create the upsteam proxy.
	upstream := cobrautil.MustGetString(cmd, "upstream-prom-addr")
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to build parse upstream URL")
	}

	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		log.Fatal().Interface("url", upstream).Msg("invalid scheme for upstream URL, only 'http' and 'https' are supported")
	}

	queryParameter := cobrautil.MustGetString(cmd, "object-id-parameter")
	if queryParameter == "" {
		log.Fatal().Msg("must specify valid object-id-parameter")
	}

	routes, err := injectproxy.NewRoutes(upstreamURL, queryParameter)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create injectproxy Routes")
	}

	// Start the proxy.
	mux := http.NewServeMux()
	mux.Handle("/", routes)

	handler := authzedHandler{
		client:          authzedClient,
		objectDefPath:   authzedObjectDefinitionPath,
		permission:      authzedPermission,
		subjectDefPath:  authzedSubjectDefinitionPath,
		subjectRelation: authzedSubjectRelation,
		queryParameter:  queryParameter,
		labelMux:        mux,
	}

	debug := log.Logger.GetLevel() <= zerolog.DebugLevel
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   cobrautil.MustGetStringSlice(cmd, "cors-allowed-origins"),
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
		Debug:            debug,
	}).Handler(handler)

	log.Info().
		Interface("cors-allowed-origins", cobrautil.MustGetStringSlice(cmd, "cors-allowed-origins")).
		Str("upstream", upstream).
		Str("authzed-endpoint", authzedEndpoint).
		Str("object-def-path", authzedObjectDefinitionPath).
		Str("permission", authzedPermission).
		Str("subject-def-path", authzedSubjectDefinitionPath).
		Str("subject-relation", authzedSubjectRelation).
		Str("query-parameter", queryParameter).
		Bool("debug", debug).
		Msg("Starting proxy server")

	srv := cobrautil.HttpServerFromFlags(cmd, flagPrefixHttp)
	srv.Handler = corsHandler
	go func() {
		if err := cobrautil.HttpListenFromFlags(cmd, flagPrefixHttp, srv, zerolog.InfoLevel); err != nil {
			log.Fatal().Err(err).Msg("failed while serving http")
		}
	}()
	defer srv.Close()

	metricsSrv := cobrautil.HttpServerFromFlags(cmd, flagPrefixMetrics)
	metricsSrv.Handler = metricsHandler()
	go func() {
		if err := cobrautil.HttpListenFromFlags(cmd, flagPrefixMetrics, metricsSrv, zerolog.InfoLevel); err != nil {
			log.Fatal().Err(err).Msg("failed while serving metrics")
		}
	}()
	defer metricsSrv.Close()

	signalctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-signalctx.Done() // Block until we've received a signal.
	log.Print("Received SIGTERM, exiting gracefully...")
}

var reservedResponseHeaders = []string{"Access-Control-Allow-Origin"}

// newFilteredWriter creates a wrapped http.ResponseWriter that resets any header specified
// in the reservedResponseHeaders slice with the value found when this writer was instantiated.
func newFilteredWriter(w http.ResponseWriter) *filteredWriter {
	savedHeaders := map[string][]string{}
	for _, name := range reservedResponseHeaders {
		savedHeaders[name] = w.Header().Values(name)
	}

	return &filteredWriter{
		w:            w,
		savedHeaders: savedHeaders,
	}
}

type filteredWriter struct {
	w            http.ResponseWriter
	savedHeaders map[string][]string
}

func (s filteredWriter) resetHeaders() {
	for _, name := range reservedResponseHeaders {
		s.w.Header().Del(name)

		for _, value := range s.savedHeaders[name] {
			s.w.Header().Add(name, value)
		}
	}
}

func (s filteredWriter) WriteHeader(code int) {
	s.resetHeaders()
	s.w.WriteHeader(code)
}

func (s filteredWriter) Write(b []byte) (int, error) {
	s.resetHeaders()
	return s.w.Write(b)
}

func (s filteredWriter) Header() http.Header {
	return s.w.Header()
}

type authzedHandler struct {
	client          *authzed.Client
	objectDefPath   string
	permission      string
	subjectDefPath  string
	subjectRelation string
	queryParameter  string
	labelMux        *http.ServeMux
}

func (ah authzedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	log.Debug().Str("method", r.Method).Interface("url", r.URL).Bool("has-auth-header", len(auth) > 0).Msg("Got request to proxy")

	queryValue := r.URL.Query().Get(ah.queryParameter)
	if queryValue == "" {
		http.Error(w, fmt.Sprintf("Bad request. The %q query parameter must be provided.", ah.queryParameter), http.StatusBadRequest)
		return
	}

	if auth == "" {
		log.Debug().Msg("No Authorization header found")
		http.Error(w, fmt.Sprintf("Authorization header is required"), http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		log.Debug().Msg("Invalid Authorization header found")
		http.Error(w, fmt.Sprintf("A Bearer token is required"), 403)
		return
	}

	subjectID := strings.TrimPrefix(auth, "Bearer ")

	resp, err := ah.client.Check(r.Context(), &v0.CheckRequest{
		TestUserset: &v0.ObjectAndRelation{
			Namespace: ah.objectDefPath,
			ObjectId:  queryValue,
			Relation:  ah.permission,
		},
		User: &v0.User{UserOneof: &v0.User_Userset{Userset: &v0.ObjectAndRelation{
			Namespace: ah.subjectDefPath,
			ObjectId:  subjectID,
			Relation:  ah.subjectRelation,
		}}},
	})
	if err != nil {
		log.Warn().Err(err).Str("queryValue", queryValue).Msg("Error when attempting to check permission")
		http.Error(w, fmt.Sprintf("Upsteam service error"), http.StatusServiceUnavailable)
		return
	}

	if resp.GetMembership() != v0.CheckResponse_MEMBER {
		log.Info().Str("queryValue", queryValue).Msg("Check failed")
		http.Error(w, fmt.Sprintf("Authorization failed"), 403)
		return
	}

	log.Debug().Str("queryValue", queryValue).Msg("Check succeeded")

	// Delegate to the label filtering.
	ah.labelMux.ServeHTTP(newFilteredWriter(w), r)
}
