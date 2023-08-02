package cache

// This file was initially taken from https://github.com/hauke96/tiny-http-proxy/blob/master/cache.go
// some extra functionality and fixes have been added:
// Allow invalidating cahce items
// Expiring cached items based on a global TTL
// Simplified locking logic and fixed data race issues

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Cache struct {
	folder      string
	hash        hash.Hash
	knownValues map[string][]byte
	maxSize     int64
	ttl         time.Duration
	sync.RWMutex
}

type Options struct {
	Path    string
	MaxSize int64
	TTL     time.Duration
}

func setDefaults(opts *Options) error {
	if opts.Path == "" {
		dir, err := os.MkdirTemp("", "cache_*")
		if err != nil {
			return err
		}
		opts.Path = dir
	}
	if opts.TTL == 0 {
		opts.TTL = time.Minute
	}
	if opts.MaxSize == 0 {
		opts.MaxSize = 100
	}
	return nil
}

func CreateCache(opts Options) (*Cache, error) {
	if err := setDefaults(&opts); err != nil {
		return nil, err
	}
	fileInfos, err := os.ReadDir(opts.Path)
	if err != nil {
		log.Warnf("Cannot open cache folder '%s': %s", opts.Path, err)
		log.Infof("Create cache folder '%s'", opts.Path)
		if err := os.MkdirAll(opts.Path, os.ModePerm); err != nil {
			return nil, err
		}
	}

	values := make(map[string][]byte, 0)
	// Go through every file an save its name in the map. The content of the file
	// is loaded when needed. This makes sure that we don't have to read
	// the directory content each time the user wants data that's not yet loaded.
	for _, info := range fileInfos {
		if !info.IsDir() {
			values[info.Name()] = nil
		}
	}

	c := &Cache{
		folder:      opts.Path,
		hash:        sha256.New(),
		knownValues: values,
		maxSize:     opts.MaxSize,
		ttl:         opts.TTL,
	}

	// Start the garbage collector to clean up expired cache items.
	go func() {
		interval := c.ttl + (500 * time.Millisecond)
		if c.ttl > time.Minute {
			interval = time.Minute
		}
		log.Infof("running garbage collection every %s; TTL is %s", interval, c.ttl)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			c.garbageCollect()
		}
	}()

	return c, nil
}

func (c *Cache) garbageCollect() {
	log.Info("running garbage collection")
	files, err := c.findFilesOlderThanTTL()
	if err != nil {
		return
	}
	c.Lock()
	for _, file := range files {
		if err := c.deleteFromHash(file.Name()); err != nil {
			log.Errorf("garbage collection error: %v", err)
		}
	}
	c.Unlock()
	log.Infof("garbage collector deleted %d entries", len(files))
}

// Returns true if the resource is found, and false otherwise.
func (c *Cache) Has(key string) bool {
	c.RLock()
	defer c.RUnlock()

	_, found := c.knownValues[CalcHash(key)]
	return found
}

func (c *Cache) Get(key string) (io.ReadCloser, error) {
	c.RLock()
	defer c.RUnlock()
	var response io.ReadCloser
	hashValue := CalcHash(key)

	// Try to get content. Error if not found.
	content, ok := c.knownValues[hashValue]
	if !ok {
		log.Debugf("Cache doesn't know key '%s'", hashValue)
		return nil, fmt.Errorf("key '%s' is not known to cache", hashValue)
	}

	log.Debugf("Cache has key '%s'", hashValue)

	// Key is known, but not loaded into RAM
	if content == nil {
		log.Debugf("Cache item '%s' known but is not stored in memory. Using file.", hashValue)

		file, err := os.Open(filepath.Join(c.folder, hashValue))
		if err != nil {
			log.Errorf("Error reading cached file '%s': %s", hashValue, err)
			// forget the cached item
			_ = c.deleteFromHash(hashValue)
			return nil, err
		}

		response = file

		log.Debugf("Create reader from file %s", hashValue)
	} else { // Key is known and data is already loaded to RAM
		response = io.NopCloser(bytes.NewReader(content))
		log.Debugf("Create reader from %d byte cache content", len(content))
	}

	return response, nil
}

func (c *Cache) Invalidate(hashes ...string) error {
	c.Lock()
	defer c.Unlock()
	for _, hashValue := range hashes {
		if err := c.deleteFromHash(hashValue); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cache) Delete(key string) error {
	c.Lock()
	defer c.Unlock()
	return c.deleteFromHash(CalcHash(key))
}

// WARN: a lock showld be acquired by the caller of this function
func (c *Cache) deleteFromHash(hashValue string) error {
	delete(c.knownValues, hashValue)

	err := os.Remove(filepath.Join(c.folder, hashValue))
	if os.IsNotExist(err) {
		err = nil
	}
	return err
}

func (c *Cache) findFilesOlderThanTTL() ([]fs.DirEntry, error) {
	var files []fs.DirEntry
	tmpfiles, err := os.ReadDir(c.folder)
	if err != nil {
		return files, err
	}

	for _, file := range tmpfiles {
		if file.Type().IsRegular() {
			info, err := file.Info()
			if err != nil {
				return files, err
			}
			if time.Since(info.ModTime()) > c.ttl {
				files = append(files, file)
			}
		}
	}
	return files, err
}

func (c *Cache) Put(key string, content *io.Reader, contentLength int64) error {
	c.Lock()
	defer c.Unlock()
	hashValue := CalcHash(key)

	file, err := os.Create(filepath.Join(c.folder, hashValue))
	if err != nil {
		return err
	}
	defer file.Close()

	if contentLength <= c.maxSize*1024*1024 {
		// Small enough to put it into the in-memory cache
		// persist the cached value into a file and to memory
		r := io.TeeReader(*content, file)
		buffer := &bytes.Buffer{}
		if _, err := io.Copy(buffer, r); err != nil {
			return err
		}
		c.knownValues[hashValue] = buffer.Bytes()
		log.Debugf("Added %s into in-memory cache and wrote content into file", hashValue)
	} else {
		// Too large for in-memory cache, just write to file
		// persist the cached value into a file
		if _, err := io.Copy(file, *content); err != nil {
			return err
		}
		c.knownValues[hashValue] = nil
		log.Debugf("Wrote content of entry %s into file and added nil-entry into in-memory cache", hashValue)
	}

	return file.Sync()
}

func CalcHash(data string) string {
	sha := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sha[:])
}
