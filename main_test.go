package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOptions(t *testing.T) {
	*region = "eu-central-1"
	*allowedSourceEndpoint = "foobar.endpoint.example.com"
	*allowedSourceSubnet = []string{"127.0.0.1/32", "192.168.1.0/24"}
	*awsCredentials = []string{"fooooooooooooooo,bar", "baaaaaaaaaaaaaar,baz"}

	h, err := NewAwsS3ReverseProxy()
	assert.Nil(t, err)
	assert.Equal(t, "eu-central-1", h.Region)
	assert.Equal(t, "https", h.UpstreamScheme)
	assert.Equal(t, "s3.eu-central-1.amazonaws.com", h.UpstreamEndpoint)
	assert.Equal(t, "foobar.endpoint.example.com", h.AllowedSourceEndpoint)
	assert.Len(t, h.AllowedSourceSubnet, 2)
	assert.Equal(t, "127.0.0.1/32", h.AllowedSourceSubnet[0].String())
	assert.Equal(t, "192.168.1.0/24", h.AllowedSourceSubnet[1].String())
	assert.Len(t, h.AWSCredentials, 2)
	assert.Equal(t, "bar", h.AWSCredentials["fooooooooooooooo"])
	assert.Equal(t, "baz", h.AWSCredentials["baaaaaaaaaaaaaar"])
	assert.Len(t, h.Signers, 2)
	assert.Contains(t, h.Signers, "fooooooooooooooo")
	assert.Contains(t, h.Signers, "baaaaaaaaaaaaaar")
}

func TestParseOptionsBrokenSubnets(t *testing.T) {
	*allowedSourceSubnet = []string{"foobar"}
	_, err := NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	*allowedSourceSubnet = []string{""}
	_, err = NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	*allowedSourceSubnet = []string{"127.0.0.1/XXX"}
	_, err = NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	*allowedSourceSubnet = []string{"127.0.0.1"}
	_, err = NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	*allowedSourceSubnet = []string{"256.0.0.1"}
	_, err = NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")
}

func TestParseOptionsBrokenAWSCredentials(t *testing.T) {
	*awsCredentials = []string{""}
	_, err := NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid AWS credentials")

	*awsCredentials = []string{"foobar"}
	_, err = NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid AWS credentials")

	*awsCredentials = []string{"foooooooooooobar"}
	_, err = NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid AWS credentials")

	*awsCredentials = []string{"foooooooooooobar,"}
	_, err = NewAwsS3ReverseProxy()
	assert.Contains(t, err.Error(), "Invalid AWS credentials")
}
