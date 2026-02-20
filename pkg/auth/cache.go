package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type AuthResult struct {
	Valid      bool
	ValidUntil time.Time
}

type Cache struct {
	mu    sync.RWMutex
	items map[string]AuthResult
	ttl   time.Duration
}

func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		items: make(map[string]AuthResult),
		ttl:   ttl,
	}
	go c.cleanupLoop()
	return c
}

func (c *Cache) Get(key string) (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		return false, false
	}

	if time.Now().After(item.ValidUntil) {
		return false, false
	}

	return item.Valid, true
}

func (c *Cache) Set(key string, valid bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = AuthResult{
		Valid:      valid,
		ValidUntil: time.Now().Add(c.ttl),
	}
}

func GenerateKey(identifiers ...string) string {
	h := sha256.New()
	for _, id := range identifiers {
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.items {
			if now.After(v.ValidUntil) {
				delete(c.items, k)
			}
		}
		c.mu.Unlock()
	}
}
