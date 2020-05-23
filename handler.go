package main

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
)

var awsAuthorizationCredentialRegexp = regexp.MustCompile("Credential=([a-zA-Z0-9]+)/[0-9]+/([a-z]+-[a-z]+-[0-9]+)/s3/aws4_request")
var awsAuthorizationSignedHeadersRegexp = regexp.MustCompile("SignedHeaders=([a-zA-Z0-9;-]+)")

// Handler is a special handler that re-signs any AWS S3 request and sends it upstream
type Handler struct {
	// Print debug information
	Debug bool

	// http or https
	UpstreamScheme string

	// Upstream S3 endpoint URL
	UpstreamEndpoint string

	// Allowed endpoint, i.e., Host header to accept incoming requests from
	AllowedSourceEndpoint string

	// Allowed source IPs and subnets for incoming requests
	AllowedSourceSubnet []*net.IPNet

	// AWS Credentials, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
	AWSCredentials map[string]string

	// AWS Signature v4
	Signers map[string]*v4.Signer

	// Reverse Proxy
	Proxy *httputil.ReverseProxy
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyReq, err := h.buildUpstreamRequest(r)
	if err != nil {
		log.WithError(err).Error("unable to proxy request")
		w.WriteHeader(http.StatusBadRequest)

		// for security reasons, only write detailed error information in debug mode
		if h.Debug {
			w.Write([]byte(err.Error()))
		}
		return
	}

	url := url.URL{Scheme: proxyReq.URL.Scheme, Host: proxyReq.Host}
	proxy := httputil.NewSingleHostReverseProxy(&url)
	proxy.FlushInterval = 1
	proxy.ServeHTTP(w, proxyReq)
}

func (h *Handler) sign(signer *v4.Signer, req *http.Request, region string) error {
	return h.signWithTime(signer, req, region, time.Now())
}

func (h *Handler) signWithTime(signer *v4.Signer, req *http.Request, region string, signTime time.Time) error {
	body := bytes.NewReader([]byte{})
	if req.Body != nil {
		b, err := ioutil.ReadAll(req.Body)
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

func (h *Handler) validateIncomingSourceIP(req *http.Request) error {
	allowed := false
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
	amzDateHeader := req.Header["X-Amz-Date"]
	if len(amzDateHeader) != 1 {
		return "", "", fmt.Errorf("X-Amz-Date header missing or set multiple times: %v", req)
	}

	authorizationHeader := req.Header["Authorization"]
	if len(authorizationHeader) != 1 {
		return "", "", fmt.Errorf("Authorization header missing or set multiple times: %v", req)
	}
	match := awsAuthorizationCredentialRegexp.FindStringSubmatch(authorizationHeader[0])
	if len(match) != 3 {
		return "", "", fmt.Errorf("invalid Authorization header: Credential not found: %v", req)
	}
	receivedAccessKeyID := match[1]
	region := match[2]

	// Validate the received Credential (ACCESS_KEY_ID) is allowed
	for accessKeyID := range h.AWSCredentials {
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
	fakeReq.Host = h.AllowedSourceEndpoint

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

// Do validates the incoming request and create a new request for an upstream server
func (h *Handler) buildUpstreamRequest(req *http.Request) (*http.Request, error) {
	// Ensure the request was sent from an allowed IP address
	err := h.validateIncomingSourceIP(req)
	if err != nil {
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

	// Verify that the fake request and the incoming request have the same signature
	// This ensures it was sent and signed by a client with correct AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
	cmpResult := subtle.ConstantTimeCompare([]byte(fakeReq.Header["Authorization"][0]), []byte(req.Header["Authorization"][0]))
	if cmpResult == 0 {
		v, _ := httputil.DumpRequest(fakeReq, false)
		log.Debugf("Fake request: %v", string(v))

		v, _ = httputil.DumpRequest(req, false)
		log.Debugf("Incoming request: %v", string(v))
		return nil, fmt.Errorf("invalid signature in Authorization header")
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
