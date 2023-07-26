package transport

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Kriechi/aws-s3-reverse-proxy/pkg/cache"
)

func TestTransport(t *testing.T) {
	expected := "Hello, client"
	thf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, expected)
	})

	ts := httptest.NewServer(thf)
	tsURL, _ := url.Parse(ts.URL)

	dir, err := os.MkdirTemp("", "cache_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	trsp, err := NewTriepper(cache.Options{
		Path:    dir,
		MaxSize: 100,
		TTL:     time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	tc := http.Client{
		Transport: trsp,
	}
	u := tsURL.String() + "/test"
	for i := 1; i <= 5; i++ {
		// when the last request happens the cache should have expired
		time.Sleep(time.Duration(i*100) * time.Millisecond)
		resp, err := tc.Get(u)
		if err != nil {
			t.Error(err)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Error(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
		if string(b) != expected {
			t.Errorf("unexpected body %s", b)
		}
	}
	// calling post will invalidate the cache for this URL
	resp, err := tc.Post(u, "", nil)
	if err != nil {
		t.Error(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Error(err)
	}
	if string(b) != expected {
		t.Errorf("unexpected body %s", b)
	}
	resp, err = tc.Get(u)
	if err != nil {
		t.Error(err)
	}
	b, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Error(err)
	}
	if string(b) != expected {
		t.Errorf("unexpected body %s", b)
	}
}
