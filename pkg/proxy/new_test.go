package proxy

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOptions(t *testing.T) {
	os.Unsetenv("AWS_ACCESS_KEY_ID")
	os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	h, err := newHandler(&Options{
		AllowedSourceEndpoints: []string{"foobar.endpoint.example.com"},
		AllowedSourceSubnet:    []string{"127.0.0.1/32", "192.168.1.0/24"},
		AwsCredentials:         []string{"fooooooooooooooo,bar", "baaaaaaaaaaaaaar,baz"},
		Region:                 "eu-test-1",
	})
	assert.Nil(t, err)
	assert.Equal(t, "https", h.UpstreamScheme)
	assert.Equal(t, "", h.UpstreamEndpoint)
	assert.Equal(t, "foobar.endpoint.example.com", h.AllowedSourceEndpoints[0])
	assert.Len(t, h.AllowedSourceSubnet, 2)
	assert.Equal(t, "127.0.0.1/32", h.AllowedSourceSubnet[0].String())
	assert.Equal(t, "192.168.1.0/24", h.AllowedSourceSubnet[1].String())
	assert.Len(t, h.Signers, 2)
	creds, err := h.Signers["fooooooooooooooo"].Credentials.Get()
	assert.Nil(t, err)
	assert.Equal(t, "bar", creds.SecretAccessKey)
	creds, err = h.Signers["baaaaaaaaaaaaaar"].Credentials.Get()
	assert.Nil(t, err)
	assert.Equal(t, "baz", creds.SecretAccessKey)
	assert.Len(t, h.Signers, 2)
	assert.Contains(t, h.Signers, "fooooooooooooooo")
	assert.Contains(t, h.Signers, "baaaaaaaaaaaaaar")
}

func TestParseOptionsBrokenSubnets(t *testing.T) {
	_, err := NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"foobar"},
	})
	assert.True(t, errors.Is(err, ErrInvalidSubnet))

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{""},
	})
	assert.True(t, errors.Is(err, ErrInvalidSubnet))

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"127.0.0.1/XXX"},
	})
	assert.True(t, errors.Is(err, ErrInvalidSubnet))

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"127.0.0.1"},
	})
	assert.True(t, errors.Is(err, ErrInvalidSubnet))

	_, err = NewAwsS3ReverseProxy(Options{
		AllowedSourceSubnet: []string{"256.0.0.1"},
	})
	assert.True(t, errors.Is(err, ErrInvalidSubnet))
}

func TestParseOptionsBrokenAWSCredentials(t *testing.T) {
	_, err := NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{""},
	})
	assert.True(t, errors.Is(err, ErrInvalidCreds))

	_, err = NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{"foobar"},
	})
	assert.True(t, errors.Is(err, ErrInvalidCreds))

	_, err = NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{"foooooooooooobar"},
	})
	assert.True(t, errors.Is(err, ErrInvalidCreds))

	_, err = NewAwsS3ReverseProxy(Options{
		AwsCredentials: []string{"foooooooooooobar,"},
	})
	assert.True(t, errors.Is(err, ErrInvalidCreds))
}
