package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Options for aws-s3-reverse-proxy command line arguments
type Options struct {
	Debug                 bool
	ListenAddr            string
	MetricsListenAddr     string
	PprofListenAddr       string
	AllowedSourceEndpoint string
	AllowedSourceSubnet   []string
	AwsCredentials        []string
	Region                string
	UpstreamInsecure      bool
	UpstreamEndpoint      string
	CertFile              string
	KeyFile               string
}

// NewOptions defines and parses the raw command line arguments
func NewOptions() Options {
	var opts Options
	kingpin.Flag("verbose", "enable additional logging").Short('v').BoolVar(&opts.Debug)
	kingpin.Flag("listen-addr", "address:port to listen for requests on").Default(":8099").StringVar(&opts.ListenAddr)
	kingpin.Flag("metrics-listen-addr", "address:port to listen for Prometheus metrics on, empty to disable").Default("").StringVar(&opts.MetricsListenAddr)
	kingpin.Flag("pprof-listen-addr", "address:port to listen for pprof on, empty to disable").Default("").StringVar(&opts.PprofListenAddr)
	kingpin.Flag("allowed-endpoint", "allowed endpoint (Host header) to accept for incoming requests").Required().PlaceHolder("my.host.example.com:8099").StringVar(&opts.AllowedSourceEndpoint)
	kingpin.Flag("allowed-source-subnet", "allowed source IP addresses with netmask").Default("127.0.0.1/32").StringsVar(&opts.AllowedSourceSubnet)
	kingpin.Flag("aws-credentials", "set of AWS credentials").PlaceHolder("\"AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY\"").StringsVar(&opts.AwsCredentials)
	kingpin.Flag("aws-region", "send requests to this AWS S3 region").Default("eu-central-1").StringVar(&opts.Region)
	kingpin.Flag("upstream-insecure", "use insecure HTTP for upstream connections").BoolVar(&opts.UpstreamInsecure)
	kingpin.Flag("upstream-endpoint", "use this S3 endpoint for upstream connections, instead of public AWS S3").StringVar(&opts.UpstreamEndpoint)
	kingpin.Flag("cert-file", "path to the certificate file").Default("").StringVar(&opts.CertFile)
	kingpin.Flag("key-file", "path to the private key file").Default("").StringVar(&opts.KeyFile)
	kingpin.Parse()
	return opts
}

// NewAwsS3ReverseProxy parses all options and creates a new HTTP Handler
func NewAwsS3ReverseProxy(opts Options) (*Handler, error) {
	log.SetLevel(log.InfoLevel)
	if opts.Debug {
		log.SetLevel(log.DebugLevel)
	}

	scheme := "https"
	if opts.UpstreamInsecure {
		scheme = "http"
	}

	var parsedAllowedSourceSubnet []*net.IPNet
	for _, sourceSubnet := range opts.AllowedSourceSubnet {
		_, subnet, err := net.ParseCIDR(sourceSubnet)
		if err != nil {
			return nil, fmt.Errorf("Invalid allowed source subnet: %v", sourceSubnet)
		}
		parsedAllowedSourceSubnet = append(parsedAllowedSourceSubnet, subnet)
	}

	parsedAwsCredentials := make(map[string]string)
	for _, cred := range opts.AwsCredentials {
		d := strings.Split(cred, ",")
		if len(d) != 2 || len(d[0]) < 16 || len(d[1]) < 1 {
			return nil, fmt.Errorf("Invalid AWS credentials. Did you separate them with a ',' or are they too short?")
		}
		parsedAwsCredentials[d[0]] = d[1]
	}

	signers := make(map[string]*v4.Signer)
	for accessKeyID, secretAccessKey := range parsedAwsCredentials {
		signers[accessKeyID] = v4.NewSigner(credentials.NewStaticCredentialsFromCreds(credentials.Value{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
		}))
	}

	upstreamEndpoint := opts.UpstreamEndpoint
	if len(upstreamEndpoint) == 0 {
		upstreamEndpoint = fmt.Sprintf("s3.%s.amazonaws.com", opts.Region)
	}

	url := url.URL{Scheme: scheme, Host: upstreamEndpoint}
	proxy := httputil.NewSingleHostReverseProxy(&url)
	proxy.FlushInterval = 1

	handler := &Handler{
		Debug:                 opts.Debug,
		Region:                opts.Region,
		UpstreamScheme:        scheme,
		UpstreamEndpoint:      upstreamEndpoint,
		AllowedSourceEndpoint: opts.AllowedSourceEndpoint,
		AllowedSourceSubnet:   parsedAllowedSourceSubnet,
		AWSCredentials:        parsedAwsCredentials,
		Signers:               signers,
		Proxy:                 proxy,
	}
	return handler, nil
}

func main() {
	opts := NewOptions()
	handler, err := NewAwsS3ReverseProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Sending requests to upstream AWS S3 %s Region to endpoint %v://%v.", handler.Region, handler.UpstreamScheme, handler.UpstreamEndpoint)
	for _, subnet := range handler.AllowedSourceSubnet {
		log.Infof("Allowing connections from %v.", subnet)
	}
	log.Infof("Accepting incoming requests for this endpoint: %v", handler.AllowedSourceEndpoint)
	log.Infof("Parsed %d AWS credential sets.", len(handler.AWSCredentials))

	if len(opts.PprofListenAddr) > 0 && len(strings.Split(opts.PprofListenAddr, ":")) == 2 {
		// avoid leaking pprof to the main application http servers
		pprofMux := http.DefaultServeMux
		http.DefaultServeMux = http.NewServeMux()
		// https://golang.org/pkg/net/http/pprof/
		log.Infof("Listening for pprof connections on %s", opts.PprofListenAddr)
		go log.Fatal(
			http.ListenAndServe(opts.PprofListenAddr, pprofMux),
		)
	}

	var wrappedHandler http.Handler = handler
	if len(opts.MetricsListenAddr) > 0 && len(strings.Split(opts.MetricsListenAddr, ":")) == 2 {
		metricsHandler := http.NewServeMux()
		metricsHandler.Handle("/metrics", promhttp.Handler())

		log.Infof("Listening for secure Prometheus metrics on %s", opts.MetricsListenAddr)
		go log.Fatal(
			http.ListenAndServe(opts.MetricsListenAddr, metricsHandler),
		)
		wrappedHandler = wrapPrometheusMetrics(handler)
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
