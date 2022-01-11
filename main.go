package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	v1pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/jzelinskie/cobrautil"
	"github.com/jzelinskie/stringz"
	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "prom-authzed-proxy",
		Short:   "Proxy that protects Prometheus queries with SpiceDB",
		PreRunE: cobrautil.SyncViperPreRunE("prom-authzed-proxy"),
		RunE: cobrautil.CommandStack(
			cobrautil.ZeroLogPreRunE("log", zerolog.InfoLevel),
			cobrautil.OpenTelemetryPreRunE("otel", zerolog.InfoLevel),
			rootRunE,
		),
	}

	cobrautil.RegisterZeroLogFlags(rootCmd.Flags(), "log")
	cobrautil.RegisterOpenTelemetryFlags(rootCmd.Flags(), "otel", "prom-authzed-proxy")
	cobrautil.RegisterHttpServerFlags(rootCmd.Flags(), "metrics", "metrics", ":9091", true)

	cobrautil.RegisterHttpServerFlags(rootCmd.Flags(), "proxy", "proxy", ":9090", true)
	rootCmd.Flags().StringSlice("proxy-cors-allowed-origins", []string{"*"}, "allowed origins for CORS requests")

	rootCmd.Flags().String("proxy-upstream-prometheus-addr", "", "address of the upstream Prometheus")
	cobra.MarkFlagRequired(rootCmd.Flags(), "proxy-upstream-prometheus-addr")

	rootCmd.Flags().Bool("proxy-spicedb-insecure", false, "connect to Authzed without TLS")
	rootCmd.Flags().String("proxy-spicedb-endpoint", "grpc.authzed.com:443", "address of the Authzed to use for checking")
	rootCmd.Flags().String("proxy-spicedb-tls-cert-path", "", "path at which to find a certificate for authzed TLS")
	rootCmd.Flags().String("proxy-spicedb-token", "", "authzed token to use for checking tenancy")
	cobra.MarkFlagRequired(rootCmd.Flags(), "proxy-spicedb-token")

	rootCmd.Flags().String("proxy-check-resource-type", "", "resource type to check")
	rootCmd.Flags().String("proxy-check-resource-id-query-param", "", "query parameter used as the Object ID to check")
	rootCmd.Flags().String("proxy-check-permission", "", "permission to check")
	rootCmd.Flags().String("proxy-check-subject-type", "", "subject type to check")
	rootCmd.Flags().String("proxy-check-subject-relation", "", "optional subject relation to check")
	cobra.MarkFlagRequired(rootCmd.Flags(), "proxy-check-resource-type")
	cobra.MarkFlagRequired(rootCmd.Flags(), "proxy-check-resource-id-query-param")
	cobra.MarkFlagRequired(rootCmd.Flags(), "proxy-check-permission")
	cobra.MarkFlagRequired(rootCmd.Flags(), "proxy-check-subject-type")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
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

func spiceDBDialOpts(token, optionalCertPath string, insecure bool) (opts []grpc.DialOption) {
	if insecure {
		opts = append(opts, grpc.WithInsecure())
		opts = append(opts, grpcutil.WithInsecureBearerToken(token))
	} else {
		if optionalCertPath != "" {
			opts = append(opts, grpcutil.WithCustomCerts(optionalCertPath, grpcutil.VerifyCA))
		} else {
			opts = append(opts, grpcutil.WithSystemCerts(grpcutil.VerifyCA))
		}
		opts = append(opts, grpcutil.WithBearerToken(token))
	}
	return
}

func rootRunE(cmd *cobra.Command, args []string) error {
	upstreamURL, err := url.Parse(cobrautil.MustGetString(cmd, "proxy-upstream-prometheus-addr"))
	if err != nil {
		return fmt.Errorf("failed to build parse upstream URL: %w", err)
	}

	if !stringz.SliceContains([]string{"http", "https"}, upstreamURL.Scheme) {
		return errors.New("only 'http' and 'https' schemes are supported for the upstream prometheus URL")
	}

	labelProxyHandler, err := injectproxy.NewRoutes(
		upstreamURL,
		cobrautil.MustGetStringExpanded(cmd, "proxy-check-resource-id-query-param"),
	)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create injectproxy Routes")
	}

	authzedClient, err := authzed.NewClient(
		cobrautil.MustGetStringExpanded(cmd, "proxy-spicedb-endpoint"),
		spiceDBDialOpts(
			cobrautil.MustGetString(cmd, "proxy-spicedb-token"),
			cobrautil.MustGetString(cmd, "proxy-spicedb-tls-cert-path"),
			cobrautil.MustGetBool(cmd, "proxy-spicedb-insecure"),
		)...)
	if err != nil {
		log.Fatal().Err(err).Msg("could not create Authzed client")
	}

	const proxyPrefix = "proxy"
	proxySrv := cobrautil.HttpServerFromFlags(cmd, proxyPrefix)
	proxySrv.Handler = logHandler(cors.New(cors.Options{
		AllowedOrigins:   cobrautil.MustGetStringSlice(cmd, "proxy-cors-allowed-origins"),
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
		Debug:            log.Debug().Enabled(),
	}).Handler(proxyHandler(
		authzedClient,
		labelProxyHandler,
		cobrautil.MustGetStringExpanded(cmd, "proxy-check-resource-type"),
		cobrautil.MustGetStringExpanded(cmd, "proxy-check-resource-id-query-param"),
		cobrautil.MustGetStringExpanded(cmd, "proxy-check-permission"),
		cobrautil.MustGetStringExpanded(cmd, "proxy-check-subject-type"),
		cobrautil.MustGetStringExpanded(cmd, "proxy-check-subject-relation"),
	)))
	go func() {
		if err := cobrautil.HttpListenFromFlags(cmd, proxyPrefix, proxySrv, zerolog.InfoLevel); err != nil {
			log.Fatal().Err(err).Msg("failed while serving proxy")
		}
	}()
	defer proxySrv.Close()

	const metricsPrefix = "metrics"
	metricsSrv := cobrautil.HttpServerFromFlags(cmd, metricsPrefix)
	metricsSrv.Handler = metricsHandler()
	go func() {
		if err := cobrautil.HttpListenFromFlags(cmd, metricsPrefix, metricsSrv, zerolog.InfoLevel); err != nil {
			log.Fatal().Err(err).Msg("failed while serving metrics")
		}
	}()
	defer metricsSrv.Close()

	signalctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	<-signalctx.Done() // Block until we've received a signal.
	log.Info().Msg("received interrupt signal, exiting gracefully")
	return nil
}

func proxyHandler(
	client *authzed.Client,
	labelProxyHandler http.Handler,
	resourceType string,
	resourceIDQueryParam string,
	permission string,
	subjectType string,
	subjectRelation string,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const bearerTokenPrefix = "Bearer "
		bearerToken := r.Header.Get("Authorization")
		if bearerToken == "" || !strings.HasPrefix(bearerToken, bearerTokenPrefix) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return
		}

		resourceID := r.URL.Query().Get(resourceIDQueryParam)
		if resourceID == "" {
			errMsg := fmt.Sprintf(
				"missing required query parameter: %s",
				resourceIDQueryParam,
			)
			http.Error(w, errMsg, http.StatusBadRequest)
			return
		}

		resp, err := client.CheckPermission(r.Context(), &v1pb.CheckPermissionRequest{
			Resource: &v1pb.ObjectReference{
				ObjectType: resourceType,
				ObjectId:   resourceID,
			},
			Permission: permission,
			Subject: &v1pb.SubjectReference{
				Object: &v1pb.ObjectReference{
					ObjectType: subjectType,
					ObjectId:   strings.TrimPrefix(bearerToken, bearerTokenPrefix),
				},
				OptionalRelation: subjectRelation,
			},
		})
		if err != nil {
			http.Error(w, "upsteam failure", http.StatusServiceUnavailable)
			return
		}

		if resp.GetPermissionship() == v1pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
			labelProxyHandler.ServeHTTP(newFilteredWriter(w, "Access-Control-Allow-Origin"), r)
		} else {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	})
}
