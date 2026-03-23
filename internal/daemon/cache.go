package daemon

import (
	"sync"
	"time"
)

// refreshWindow is how long before expiry a credential is considered stale
// and will be re-fetched on the next request.
const refreshWindow = 5 * time.Minute

// CachedCredential holds a cached credential with its expiry time.
type CachedCredential struct {
	Data      []byte    // JSON-encoded credential response
	ExpiresAt time.Time // when the credential expires
	Format    string    // the format used to generate this credential
}

// Valid returns true if the credential has not expired.
func (c *CachedCredential) Valid() bool {
	return time.Now().Before(c.ExpiresAt)
}

// NeedsRefresh returns true if the credential is within the refresh window of expiry.
func (c *CachedCredential) NeedsRefresh() bool {
	return time.Now().After(c.ExpiresAt.Add(-refreshWindow))
}

// Cache is a thread-safe in-memory credential cache keyed by provider+format.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]*CachedCredential

	// fetchMu provides per-key locking so only one fetch happens at a time
	// for a given provider+format combination.
	fetchMu   sync.Mutex
	fetchLock map[string]*sync.Mutex
}

// NewCache creates an empty credential cache.
func NewCache() *Cache {
	return &Cache{
		entries:   make(map[string]*CachedCredential),
		fetchLock: make(map[string]*sync.Mutex),
	}
}

func cacheKey(provider, format string) string {
	return provider + ":" + format
}

// Get returns a cached credential if it exists and is still valid.
// Returns nil if not cached or expired.
func (c *Cache) Get(provider, format string) *CachedCredential {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[cacheKey(provider, format)]
	if !ok || !entry.Valid() {
		return nil
	}
	return entry
}

// Set stores a credential in the cache.
func (c *Cache) Set(provider, format string, cred *CachedCredential) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cacheKey(provider, format)] = cred
}

// Clear removes all cached credentials.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CachedCredential)
}

// FetchLock returns a per-key mutex so that concurrent requests for the
// same provider+format only trigger one actual credential fetch.
func (c *Cache) FetchLock(provider, format string) *sync.Mutex {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	key := cacheKey(provider, format)
	if _, ok := c.fetchLock[key]; !ok {
		c.fetchLock[key] = &sync.Mutex{}
	}
	return c.fetchLock[key]
}

// Status returns a snapshot of all cached entries for the status endpoint.
func (c *Cache) Status() map[string]CacheEntryStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]CacheEntryStatus, len(c.entries))
	for key, entry := range c.entries {
		result[key] = CacheEntryStatus{
			ExpiresAt:    entry.ExpiresAt,
			Valid:        entry.Valid(),
			NeedsRefresh: entry.NeedsRefresh(),
		}
	}
	return result
}

// CacheEntryStatus is the external representation of a cache entry for the status API.
type CacheEntryStatus struct {
	ExpiresAt    time.Time `json:"expires_at"`
	Valid        bool      `json:"valid"`
	NeedsRefresh bool      `json:"needs_refresh"`
}
