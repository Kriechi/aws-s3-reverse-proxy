package proxy

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Kriechi/aws-s3-reverse-proxy/pkg/cache"
	"github.com/Kriechi/aws-s3-reverse-proxy/pkg/transport"
	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
	"k8s.io/utils/strings/slices"
)

var (
	ErrInvalidEndpoint                  = errors.New("invalid endpoint specified")
	ErrInvalidSubnet                    = errors.New("invalid allowed source subnet")
	ErrInvalidCreds                     = errors.New("invalid AWS credentials")
	awsAuthorizationCredentialRegexp    = regexp.MustCompile("Credential=([a-zA-Z0-9]+)/[0-9]+/([a-z]+-?[a-z]+-?[0-9]+)/s3/aws4_request")
	awsAuthorizationSignedHeadersRegexp = regexp.MustCompile("SignedHeaders=([a-zA-Z0-9;-]+)")
)

// Handler is a special handler that re-signs any AWS S3 request and sends it upstream
type Handler struct {
	// Print debug information
	Debug bool

	// http or https
	UpstreamScheme string

	// Upstream S3 endpoint URL
	UpstreamEndpoint string

	// Allowed endpoint, i.e., Host header to accept incoming requests from
	AllowedSourceEndpoints []string

	// Allowed source IPs and subnets for incoming requests
	AllowedSourceSubnet []*net.IPNet

	// AWS Signature v4
	Signers map[string]*v4.Signer

	// Reverse Proxy
	Proxy *httputil.ReverseProxy
}

// NewAwsS3ReverseProxy parses all options and creates a new HTTP Handler
func NewAwsS3ReverseProxy(opts Options) (http.Handler, error) {
	log.SetLevel(log.InfoLevel)
	if opts.Debug {
		log.SetLevel(log.DebugLevel)
	}

	h, err := newHandler(&opts)
	if err != nil {
		return nil, err
	}

	h.Proxy = httputil.NewSingleHostReverseProxy(&url.URL{Scheme: h.UpstreamScheme, Host: h.UpstreamEndpoint})

	if opts.CachePath != "" {
		tripper, err := transport.NewTriepper(cache.Options{
			Path:    opts.CachePath,
			MaxSize: opts.MaxCacheItemSize,
			TTL:     opts.CacheTTL,
		})
		if err != nil {
			return nil, err
		}
		h.Proxy.Transport = tripper
	}

	return h, nil
}

func newHandler(opts *Options) (*Handler, error) {
	scheme := "https"
	if opts.UpstreamInsecure {
		scheme = "http"
	}

	var parsedAllowedSourceSubnet []*net.IPNet
	for _, sourceSubnet := range opts.AllowedSourceSubnet {
		_, subnet, err := net.ParseCIDR(sourceSubnet)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSubnet, sourceSubnet)
		}
		parsedAllowedSourceSubnet = append(parsedAllowedSourceSubnet, subnet)
	}

	signers := make(map[string]*v4.Signer)
	for _, cred := range opts.AwsCredentials {
		d := strings.SplitN(cred, ",", 2)
		if len(d) != 2 || len(d[0]) < 16 || len(d[1]) < 1 {
			return nil, fmt.Errorf("%w; Did you separate them with a ',' or are they too short?", ErrInvalidCreds)
		}
		signers[d[0]] = v4.NewSigner(credentials.NewStaticCredentialsFromCreds(credentials.Value{
			AccessKeyID:     d[0],
			SecretAccessKey: d[1],
		}))
	}

	if os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		signers[os.Getenv("AWS_ACCESS_KEY_ID")] = v4.NewSigner(credentials.NewStaticCredentialsFromCreds(credentials.Value{
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		}))
	}

	h := &Handler{
		Debug:               opts.Debug,
		UpstreamScheme:      scheme,
		UpstreamEndpoint:    opts.UpstreamEndpoint,
		AllowedSourceSubnet: parsedAllowedSourceSubnet,
		Signers:             signers,
	}

	if len(opts.UpstreamEndpoint) > 0 {
		log.Infof("Sending requests to upstream AWS S3 to endpoint %s://%s.", scheme, h.UpstreamEndpoint)
	} else {
		log.Infof("Auto-detecting S3 endpoint based on region: %s://s3.{region}.amazonaws.com", scheme)
	}

	for _, subnet := range opts.AllowedSourceSubnet {
		log.Infof("Allowing connections from %v.", subnet)
	}
	for _, endpoint := range opts.AllowedSourceEndpoints {
		var host string
		if u, err := url.Parse(endpoint); err == nil {
			host = u.Host
			if host == "" && u.Path != "" {
				host = u.Path
			}
		}
		if host == "" {
			host = endpoint
		}
		h.AllowedSourceEndpoints = append(h.AllowedSourceEndpoints, host)
		log.Infof("Accepting incoming requests for this endpoint: %v", host)
	}
	log.Infof("Parsed %d AWS credential sets.", len(h.Signers))

	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyReq, err := h.buildUpstreamRequest(r)
	if err != nil {
		log.WithError(err).Error("unable to proxy request")
		w.WriteHeader(http.StatusBadRequest)

		// for security reasons, only write detailed error information in debug mode
		if h.Debug {
			_, _ = w.Write([]byte(err.Error()))
		}
		return
	}

	h.Proxy.ServeHTTP(w, proxyReq)
}

func (h *Handler) sign(signer *v4.Signer, req *http.Request, region string) error {
	return h.signWithTime(signer, req, region, time.Now())
}

func (h *Handler) signWithTime(signer *v4.Signer, req *http.Request, region string, signTime time.Time) error {
	body := bytes.NewReader([]byte{})
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}

	_, err := signer.Sign(req, body, "s3", region, signTime)
	return err
}

func copyHeaderWithoutOverwrite(dst http.Header, src http.Header) {
	for k, v := range src {
		if _, ok := dst[k]; !ok {
			for _, vv := range v {
				dst.Add(k, vv)
			}
		}
	}
}

func (h *Handler) validateSourceEndpoint(req *http.Request) error {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	// host = strings.Split(host, ":")[0]
	if !slices.Contains(h.AllowedSourceEndpoints, host) {
		return fmt.Errorf("%w; %s is not allowed", ErrInvalidEndpoint, host)
	}
	return nil
}

func (h *Handler) validateIncomingSourceIP(req *http.Request) error {
	var allowed bool
	for _, subnet := range h.AllowedSourceSubnet {
		ip, _, _ := net.SplitHostPort(req.RemoteAddr)
		userIP := net.ParseIP(ip)
		if subnet.Contains(userIP) {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("source IP not allowed: %v", req)
	}
	return nil
}

func (h *Handler) validateIncomingHeaders(req *http.Request) (string, string, error) {
	if len(req.Header["X-Amz-Date"]) != 1 {
		return "", "", fmt.Errorf("X-Amz-Date header missing or set multiple times: %v", req)
	}

	authorizationHeader := req.Header["Authorization"]
	if len(authorizationHeader) != 1 {
		return "", "", fmt.Errorf("authorization header missing or set multiple times: %v", req)
	}
	match := awsAuthorizationCredentialRegexp.FindStringSubmatch(authorizationHeader[0])
	if len(match) != 3 {
		return "", "", fmt.Errorf("invalid Authorization header: Credential not found: %v", req)
	}
	receivedAccessKeyID := match[1]
	region := match[2]

	// Validate the received Credential (ACCESS_KEY_ID) is allowed
	for accessKeyID := range h.Signers {
		if subtle.ConstantTimeCompare([]byte(receivedAccessKeyID), []byte(accessKeyID)) == 1 {
			return accessKeyID, region, nil
		}
	}
	return "", "", fmt.Errorf("invalid AccessKeyID in Credential: %v", req)
}

func (h *Handler) generateFakeIncomingRequest(signer *v4.Signer, req *http.Request, region string) (*http.Request, error) {
	fakeReq, err := http.NewRequest(req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	fakeReq.URL.RawPath = req.URL.Path

	// We already validated there there is exactly one Authorization header
	authorizationHeader := req.Header.Get("authorization")
	match := awsAuthorizationSignedHeadersRegexp.FindStringSubmatch(authorizationHeader)
	if len(match) == 2 {
		for _, header := range strings.Split(match[1], ";") {
			fakeReq.Header.Set(header, req.Header.Get(header))
		}
	}

	// Delete a potentially double-added header
	fakeReq.Header.Del("host")
	fakeReq.Host = req.Host

	// The X-Amz-Date header contains a timestamp, such as: 20190929T182805Z
	signTime, err := time.Parse("20060102T150405Z", req.Header["X-Amz-Date"][0])
	if err != nil {
		return nil, fmt.Errorf("error parsing X-Amz-Date %v - %v", req.Header["X-Amz-Date"][0], err)
	}

	// Sign the fake request with the original timestamp
	if err := h.signWithTime(signer, fakeReq, region, signTime); err != nil {
		return nil, err
	}

	return fakeReq, nil
}

func (h *Handler) assembleUpstreamReq(signer *v4.Signer, req *http.Request, region string) (*http.Request, error) {
	upstreamEndpoint := h.UpstreamEndpoint
	if len(upstreamEndpoint) == 0 {
		upstreamEndpoint = fmt.Sprintf("s3.%s.amazonaws.com", region)
		log.Infof("Using %s as upstream endpoint", upstreamEndpoint)
	}

	proxyURL := *req.URL
	proxyURL.Scheme = h.UpstreamScheme
	proxyURL.Host = upstreamEndpoint
	proxyURL.RawPath = req.URL.Path
	proxyReq, err := http.NewRequest(req.Method, proxyURL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	if val, ok := req.Header["Content-Type"]; ok {
		proxyReq.Header["Content-Type"] = val
	}
	if val, ok := req.Header["Content-Md5"]; ok {
		proxyReq.Header["Content-Md5"] = val
	}

	// Sign the upstream request
	if err := h.sign(signer, proxyReq, region); err != nil {
		return nil, err
	}

	// Add origin headers after request is signed (no overwrite)
	copyHeaderWithoutOverwrite(proxyReq.Header, req.Header)

	return proxyReq, nil
}

func (h *Handler) validateSignature(req, proxyReq *http.Request) error {
	// Verify that the fake request and the incoming request have the same signature
	// This ensures it was sent and signed by a client with correct AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
	cmpResult := subtle.ConstantTimeCompare([]byte(proxyReq.Header["Authorization"][0]), []byte(req.Header["Authorization"][0]))
	if cmpResult == 0 {
		v, _ := httputil.DumpRequest(proxyReq, false)
		log.Debugf("Proxy request: %v", string(v))

		v, _ = httputil.DumpRequest(req, false)
		log.Debugf("Incoming request: %v", string(v))
		return fmt.Errorf("invalid signature in Authorization header")
	}

	return nil
}

// Do validates the incoming request and create a new request for an upstream server
func (h *Handler) buildUpstreamRequest(req *http.Request) (*http.Request, error) {
	// Ensure the request was sent from an allowed IP address
	if err := h.validateIncomingSourceIP(req); err != nil {
		return nil, err
	}

	// Ensure the request was sent from an allowed endpoint
	if err := h.validateSourceEndpoint(req); err != nil {
		return nil, err
	}

	// Validate incoming headers and extract AWS_ACCESS_KEY_ID
	accessKeyID, region, err := h.validateIncomingHeaders(req)
	if err != nil {
		return nil, err
	}

	// Get the AWS Signature signer for this AccessKey
	signer := h.Signers[accessKeyID]

	// Assemble a signed fake request to verify the incoming requests signature
	fakeReq, err := h.generateFakeIncomingRequest(signer, req, region)
	if err != nil {
		return nil, err
	}

	if err := h.validateSignature(req, fakeReq); err != nil {
		return nil, err
	}

	if log.GetLevel() == log.DebugLevel {
		initialReqDump, _ := httputil.DumpRequest(req, false)
		log.Debugf("Initial request dump: %v", string(initialReqDump))
	}

	// Assemble a new upstream request
	proxyReq, err := h.assembleUpstreamReq(signer, req, region)
	if err != nil {
		return nil, err
	}

	// Disable Go's "Transfer-Encoding: chunked" madness
	proxyReq.ContentLength = req.ContentLength

	if log.GetLevel() == log.DebugLevel {
		proxyReqDump, _ := httputil.DumpRequest(proxyReq, false)
		log.Debugf("Proxying request: %v", string(proxyReqDump))
	}

	return proxyReq, nil
}
