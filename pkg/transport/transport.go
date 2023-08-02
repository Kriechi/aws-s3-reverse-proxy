package transport

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/Kriechi/aws-s3-reverse-proxy/pkg/cache"
)

type Tripper struct {
	transport http.RoundTripper
	cache     *cache.Cache
	cacheMap  map[string][]string
	sync.Mutex
}

func NewTriepper(opts cache.Options) (*Tripper, error) {
	cache, err := cache.CreateCache(opts)
	if err != nil {
		return nil, err
	}

	return &Tripper{
		transport: http.DefaultTransport,
		cache:     cache,
		cacheMap:  make(map[string][]string),
	}, nil
}

func (t *Tripper) getUpstream(r *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(r)
	log.Infof("upstream response: %s; method: %s; status: %s", r.URL.String(), r.Method, resp.Status)
	return resp, err
}

// Unique returns the deduplicated version of the given array
func unique[T comparable](in []T) []T {
	inResult := make(map[T]struct{})
	var result []T
	for _, item := range in {
		if _, ok := inResult[item]; !ok {
			inResult[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func (t *Tripper) invalidateCache(pk, key string) {
	t.Lock()
	defer t.Unlock()
	if keys, ok := t.cacheMap[pk]; ok {
		log.Infof("invalidating %v from cache", keys)
		if err := t.cache.Invalidate(keys...); err != nil {
			log.Errorf("invalidating %s from cache: %v", key, err)
		}
	}
	delete(t.cacheMap, pk)
}

func (t *Tripper) updateCacheMap(pk, key string) {
	t.Lock()
	defer t.Unlock()
	t.cacheMap[pk] = unique(append(t.cacheMap[pk], cache.CalcHash(key)))
}

// Implement the RoundTripper interface
func (t *Tripper) RoundTrip(r *http.Request) (*http.Response, error) {
	reqRange := r.Header.Get("Range")
	if reqRange == "" {
		reqRange = "full"
	}
	log.Infof("requested: %s; method: %s; range: %s; agent: %s", r.URL.String(), r.Method, reqRange, r.UserAgent())
	if r.Context().Err() != nil {
		return nil, r.Context().Err()
	}

	pk := cache.CalcHash(r.URL.Path)
	key := r.URL.Path + "?" + r.URL.RawQuery + ":" + r.Method + ":" + reqRange

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// method is not cacheable
		go t.invalidateCache(pk, key)
		return t.getUpstream(r)
	}

	go t.updateCacheMap(pk, key)

	// Cache miss, Load data from requested URL and add to cache
	if ok := t.cache.Has(key); !ok {
		resp, err := t.getUpstream(r)
		if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusPartialContent) {
			// don't cache failures
			return resp, err
		}

		// Store the response in the cache
		dump, err := httputil.DumpResponse(resp, true)
		if err != nil || len(dump) == 0 {
			log.Error("persisting to cache ", err.Error())
			return resp, nil
		}
		var reader io.Reader
		reader = bytes.NewReader(dump)

		err = t.cache.Put(key, &reader, resp.ContentLength)
		if err != nil {
			log.Error("persisting to cache ", err.Error())
		}
		return resp, nil
	}

	// Cache hit, return cached response
	content, err := t.cache.Get(key)
	if err != nil {
		log.Error("serving from cache ", err.Error())
		return t.getUpstream(r)
	}

	// Get response from cached content
	resp, err := http.ReadResponse(bufio.NewReader(content), r)
	if err != nil {
		log.Error("serving from cache ", err.Error())
		return t.getUpstream(r)
	}

	log.Debugf("Content size: %d", resp.ContentLength)

	log.Infof("cached response: %s; method: %s; status: %s", r.URL.String(), r.Method, resp.Status)
	return resp, err
}
