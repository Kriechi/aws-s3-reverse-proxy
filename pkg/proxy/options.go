package proxy

import (
	"time"

	"github.com/alecthomas/kingpin/v2"
)

// Options for aws-s3-reverse-proxy command line arguments
type Options struct {
	Debug                  bool
	ListenAddr             string
	MetricsListenAddr      string
	HealthzListenAddr      string
	PprofListenAddr        string
	AllowedSourceEndpoints []string
	AllowedSourceSubnet    []string
	AwsCredentials         []string
	Region                 string
	UpstreamInsecure       bool
	UpstreamEndpoint       string
	CertFile               string
	KeyFile                string
	MaxCacheItemSize       int64
	CachePath              string
	CacheTTL               time.Duration
}

// NewOptions defines and parses the raw command line arguments
func NewOptions() Options {
	var opts Options
	kingpin.Flag("verbose", "enable additional logging (env - VERBOSE)").Envar("VERBOSE").Short('v').BoolVar(&opts.Debug)
	kingpin.Flag("listen-addr", "address:port to listen for requests on (env - LISTEN_ADDR)").Default(":8099").Envar("LISTEN_ADDR").StringVar(&opts.ListenAddr)
	kingpin.Flag("metrics-listen-addr", "address:port to listen for Prometheus metrics on, empty to disable (env - METRICS_LISTEN_ADDR)").Default("").Envar("METRICS_LISTEN_ADDR").StringVar(&opts.MetricsListenAddr)
	kingpin.Flag("healthz-listen-addr", "address:port to listen for healthz on, empty to disable (env - healthz_LISTEN_ADDR)").Default("").Envar("HEALTHZ_LISTEN_ADDR").StringVar(&opts.HealthzListenAddr)
	kingpin.Flag("pprof-listen-addr", "address:port to listen for pprof on, empty to disable (env - PPROF_LISTEN_ADDR)").Default("").Envar("PPROF_LISTEN_ADDR").StringVar(&opts.PprofListenAddr)
	kingpin.Flag("allowed-endpoint", "allowed endpoint (Host header) to accept for incoming requests (env - ALLOWED_ENDPOINT)").Envar("ALLOWED_ENDPOINT").Required().PlaceHolder("my.host.example.com:8099").StringsVar(&opts.AllowedSourceEndpoints)
	kingpin.Flag("allowed-source-subnet", "allowed source IP addresses with netmask (env - ALLOWED_SOURCE_SUBNET)").Default("127.0.0.1/32").Envar("ALLOWED_SOURCE_SUBNET").StringsVar(&opts.AllowedSourceSubnet)
	kingpin.Flag("aws-credentials", "set of AWS credentials (env - AWS_CREDENTIALS)").PlaceHolder("\"AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY\"").Envar("AWS_CREDENTIALS").StringsVar(&opts.AwsCredentials)
	kingpin.Flag("aws-region", "send requests to this AWS S3 region (env - AWS_REGION)").Envar("AWS_REGION").Default("eu-central-1").StringVar(&opts.Region)
	kingpin.Flag("upstream-insecure", "use insecure HTTP for upstream connections (env - UPSTREAM_INSECURE)").Envar("UPSTREAM_INSECURE").BoolVar(&opts.UpstreamInsecure)
	kingpin.Flag("upstream-endpoint", "use this S3 endpoint for upstream connections, instead of public AWS S3 (env - UPSTREAM_ENDPOINT)").Envar("UPSTREAM_ENDPOINT").StringVar(&opts.UpstreamEndpoint)
	kingpin.Flag("cert-file", "path to the certificate file (env - CERT_FILE)").Envar("CERT_FILE").Default("").StringVar(&opts.CertFile)
	kingpin.Flag("key-file", "path to the private key file (env - KEY_FILE)").Envar("KEY_FILE").Default("").StringVar(&opts.KeyFile)
	kingpin.Flag("max-cache-items", "max item size to cache in memory, in Mb (env MAX_CACHE_ITEMS)").Envar("MAX_CACHE_ITEMS").Default("500").Int64Var(&opts.MaxCacheItemSize)
	kingpin.Flag("cache-path", "path to store the cache (env CACHE_PATH)").Envar("CACHE_PATH").Default("").StringVar(&opts.CachePath)
	kingpin.Flag("cache-ttl", "how long to cache for (env CACHE_TTL)").Envar("CACHE_TTL").Default("1h").DurationVar(&opts.CacheTTL)
	kingpin.Parse()
	return opts
}
