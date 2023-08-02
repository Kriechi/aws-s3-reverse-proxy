package main

import (
	"net/http"
	"strings"

	_ "net/http/pprof"

	"github.com/Kriechi/aws-s3-reverse-proxy/pkg/proxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

func main() {
	opts := proxy.NewOptions()

	if len(opts.PprofListenAddr) > 0 && len(strings.Split(opts.PprofListenAddr, ":")) == 2 {
		// avoid leaking pprof to the main application http servers
		pprofMux := http.DefaultServeMux
		http.DefaultServeMux = http.NewServeMux()
		// https://golang.org/pkg/net/http/pprof/
		log.Infof("Listening for pprof connections on %s", opts.PprofListenAddr)
		go func() {
			log.Fatal(
				http.ListenAndServe(opts.PprofListenAddr, pprofMux),
			)
		}()
	}

	p, err := proxy.NewAwsS3ReverseProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	var wrappedHandler http.Handler = p
	if len(opts.MetricsListenAddr) > 0 && len(strings.Split(opts.MetricsListenAddr, ":")) == 2 {
		metricsHandler := http.NewServeMux()
		metricsHandler.Handle("/metrics", promhttp.Handler())

		log.Infof("Listening for secure Prometheus metrics on %s", opts.MetricsListenAddr)
		wrappedHandler = proxy.WrapPrometheusMetrics(p)

		go func() {
			log.Fatal(
				http.ListenAndServe(opts.MetricsListenAddr, metricsHandler),
			)
		}()
	}

	if len(opts.HealthzListenAddr) > 0 && len(strings.Split(opts.HealthzListenAddr, ":")) == 2 {
		healthzHandler := http.NewServeMux()
		healthzHandler.Handle("/healthz", proxy.HealthHandler())

		log.Infof("Listening for healthz probes on %s", opts.HealthzListenAddr)

		go func() {
			log.Fatal(
				http.ListenAndServe(opts.HealthzListenAddr, healthzHandler),
			)
		}()
	}

	if len(opts.CertFile) > 0 || len(opts.KeyFile) > 0 {
		log.Infof("Reading HTTPS certificate from %v and %v.", opts.CertFile, opts.KeyFile)
		log.Infof("Listening for secure HTTPS connections on %s", opts.ListenAddr)
		log.Fatal(
			http.ListenAndServeTLS(opts.ListenAddr, opts.CertFile, opts.KeyFile, wrappedHandler),
		)
	} else {
		log.Infof("Listening for HTTP connections on %s", opts.ListenAddr)
		log.Fatal(
			http.ListenAndServe(opts.ListenAddr, wrappedHandler),
		)
	}
}
