package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// func TestMain(m *testing.M) {
// 	log.SetOutput(ioutil.Discard)
// }

func newTestHandler(t *testing.T) *Handler {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	// defer ts.Close()
	tsURL, _ := url.Parse(ts.URL)

	h, err := NewAwsS3ReverseProxy(Options{
		Debug:                 true,
		AllowedSourceEndpoint: "foobar.example.com",
		AllowedSourceSubnet:   []string{"0.0.0.0/0"},
		AwsCredentials:        []string{"fooooooooooooooo,bar"},
		Region:                "eu-test-1",
		UpstreamInsecure:      true,
		UpstreamEndpoint:      tsURL.Host,
	})
	assert.Nil(t, err)
	return h
}

func TestHandlerMissingAmzDate(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 400, resp.Code)
	assert.Contains(t, resp.Body.String(), "X-Amz-Date header missing or set multiple times")
}

func TestHandlerMissingAuthorization(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	req.Header.Set("X-Amz-Date", "20060102T150405Z")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 400, resp.Code)
	assert.Contains(t, resp.Body.String(), "Authorization header missing or set multiple times")
}

func TestHandlerMissingCredential(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	req.Header.Set("X-Amz-Date", "20060102T150405Z")
	req.Header.Set("Authorization", "foobar")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 400, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid Authorization header: Credential not found")
}

func TestHandlerInvalidSignature(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	req.Header.Set("X-Amz-Date", "20060102T150405Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=fooooooooooooooo/20190101/eu-test-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=some-signature")
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 400, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid signature in Authorization header")
}

func TestHandlerValidSignature(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	req.Header.Set("X-Amz-Date", "20060102T150405Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=fooooooooooooooo/20060102/eu-test-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=a0d5e0c0924c1f9298c5f2a3925e202657bf1e239a1d6856235cbe0702855334") // signature computed manually for this test case
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 200, resp.Code)
	assert.Contains(t, resp.Body.String(), "Hello, client")
}

func TestHandlerInvalidCredential(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	req.Header.Set("X-Amz-Date", "20060102T150405Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=XXXooooooooooooo/20060102/eu-test-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=a0d5e0c0924c1f9298c5f2a3925e202657bf1e239a1d6856235cbe0702855334") // signature computed manually for this test case
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 400, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid AccessKeyID in Credential")
}

func TestHandlerInvalidSourceSubnet(t *testing.T) {
	h := newTestHandler(t)
	_, newNet, _ := net.ParseCIDR("172.27.42.0/24")
	h.AllowedSourceSubnet = []*net.IPNet{newNet}

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	req.Header.Set("X-Amz-Date", "20060102T150405Z")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=XXXooooooooooooo/20060102/eu-test-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=a0d5e0c0924c1f9298c5f2a3925e202657bf1e239a1d6856235cbe0702855334") // signature computed manually for this test case
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 400, resp.Code)
	assert.Contains(t, resp.Body.String(), "source IP not allowed")
}

func TestHandlerInvalidAmzDate(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "http://foobar.example.com", nil)
	req.Header.Set("X-Amz-Date", "foobar")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=fooooooooooooooo/20060102/eu-test-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=a0d5e0c0924c1f9298c5f2a3925e202657bf1e239a1d6856235cbe0702855334") // signature computed manually for this test case
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	assert.Equal(t, 400, resp.Code)
	assert.Contains(t, resp.Body.String(), "error parsing X-Amz-Date foobar")
}
