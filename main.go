package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	debug                 = kingpin.Flag("verbose", "enable additional logging").Short('v').Bool()
	port                  = kingpin.Flag("port", "port to listen for requests on").Default(":8099").String()
	allowedSourceEndpoint = kingpin.Flag("allowed-endpoint", "Allowed endpoint (Host header) to accept for incoming requests").Required().PlaceHolder("my.host.example.com:8099").String()
	allowedSourceSubnet   = kingpin.Flag("allowed-source-addr", "Allowed source IP addresses with netmask").Default("127.0.0.1/32").Strings()
	awsCredentials        = kingpin.Flag("aws-credentials", "Set of AWS credentials").PlaceHolder("\"AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY\"").Strings()
	region                = kingpin.Flag("aws-region", "Send requests to this AWS S3 region").Default("eu-central-1").String()
	upstreamInsecure      = kingpin.Flag("aws-insecure", "Use insecure HTTP for upstream connections").Bool()
	certFile              = kingpin.Flag("cert-file", "path to the certificate file").Default("").String()
	keyFile               = kingpin.Flag("key-file", "path to the private key file").Default("").String()
)

func main() {
	kingpin.Parse()

	log.SetLevel(log.InfoLevel)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	scheme := "https"
	if *upstreamInsecure {
		scheme = "http"
		log.Infof("Using INSECURE HTTP upstream connetions!")
	} else {
		log.Infof("Using secured HTTPS upstream connetions.")
	}

	parsedAwsCredentials := make(map[string]string)
	for _, cred := range *awsCredentials {
		d := strings.Split(cred, ",")
		if len(d) != 2 || len(d[0]) < 16 || len(d[1]) < 1 {
			log.Fatal("Invalid AWS credential set. Did you separate them with a \",\"?")
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

	var parsedAllowedSourceSubnet []*net.IPNet
	for _, sourceSubnet := range *allowedSourceSubnet {
		_, subnet, err := net.ParseCIDR(sourceSubnet)
		if err != nil {
			log.Fatalf("Invalid allowed source IP address with netmask: %v", sourceSubnet)
		}
		log.Infof("Allowing connections from %v.", subnet)
		parsedAllowedSourceSubnet = append(parsedAllowedSourceSubnet, subnet)
	}

	upstreamEndpoint := fmt.Sprintf("s3.%s.amazonaws.com", *region)

	url := url.URL{Scheme: scheme, Host: upstreamEndpoint}
	proxy := httputil.NewSingleHostReverseProxy(&url)
	proxy.FlushInterval = 1

	handler := &Handler{
		Region:                *region,
		UpstreamScheme:        scheme,
		UpstreamEndpoint:      upstreamEndpoint,
		AllowedSourceEndpoint: *allowedSourceEndpoint,
		AllowedSourceSubnet:   parsedAllowedSourceSubnet,
		AWSCredentials:        parsedAwsCredentials,
		Signers:               signers,
		Proxy:                 proxy,
	}

	log.Infof("Parsed %d AWS credential sets.", len(parsedAwsCredentials))
	log.Infof("Sending requests to upstream AWS S3 %s region.", handler.Region)
	log.Infof("Accepting incoming requests for this endpoint: %v", handler.AllowedSourceEndpoint)

	server := http.NewServeMux()
	server.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe("127.0.0.1:9001", server)

	wrappedHandler := wrapPrometheusMetrics(handler)

	if len(*certFile) > 0 && len(*keyFile) > 0 {
		log.Infof("Listening for secure HTTPS connections on port %s", *port)
		log.Fatal(
			http.ListenAndServeTLS(*port, *certFile, *keyFile, wrappedHandler),
		)
	} else {
		log.Infof("Listening for HTTP connections on port %s", *port)
		log.Fatal(
			http.ListenAndServe(*port, wrappedHandler),
		)
	}
}
