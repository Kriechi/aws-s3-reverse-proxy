package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOptions(t *testing.T) {
	h, err := NewAwsS3ReverseProxy(Options{
		AllowedSourceEndpoint: "foobar.endpoint.example.com",
		AllowedSourceSubnet:   []string{"127.0.0.1/32", "192.168.1.0/24"},
		AwsCredentials:        []string{"fooooooooooooooo,bar", "baaaaaaaaaaaaaar,baz"},
		Region:                "eu-test-1",
	})
	assert.Nil(t, err)
	assert.Equal(t, "eu-test-1", h.Region)
	assert.Equal(t, "https", h.UpstreamScheme)
	assert.Equal(t, "s3.eu-test-1.amazonaws.com", h.UpstreamEndpoint)
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
	_, err := NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"foobar"},
	})
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{""},
	})
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"127.0.0.1/XXX"},
	})
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"127.0.0.1"},
	})
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"256.0.0.1"},
	})
	assert.Contains(t, err.Error(), "Invalid allowed source subnet")
}

func TestParseOptionsBrokenAWSCredentials(t *testing.T) {
	_, err := NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{""},
	})
	assert.Contains(t, err.Error(), "Invalid AWS credentials")

	_, err = NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{"foobar"},
	})
	assert.Contains(t, err.Error(), "Invalid AWS credentials")

	_, err = NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{"foooooooooooobar"},
	})
	assert.Contains(t, err.Error(), "Invalid AWS credentials")

	_, err = NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{"foooooooooooobar,"},
	})
	assert.Contains(t, err.Error(), "Invalid AWS credentials")
}
