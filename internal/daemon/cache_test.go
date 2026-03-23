package daemon

import (
	"testing"
	"time"
)

func TestCache_GetSet(t *testing.T) {
	c := NewCache()

	// Empty cache returns nil.
	if got := c.Get("aws", "credential_process"); got != nil {
		t.Fatal("expected nil from empty cache")
	}

	// Set and retrieve.
	cred := &CachedCredential{
		Data:      []byte(`{"Version":1}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Format:    "credential_process",
	}
	c.Set("aws", "credential_process", cred)

	got := c.Get("aws", "credential_process")
	if got == nil {
		t.Fatal("expected cached credential")
	}
	if string(got.Data) != `{"Version":1}` {
		t.Errorf("data = %s, want {\"Version\":1}", string(got.Data))
	}
}

func TestCache_Expired(t *testing.T) {
	c := NewCache()

	cred := &CachedCredential{
		Data:      []byte(`{}`),
		ExpiresAt: time.Now().Add(-1 * time.Minute), // already expired
		Format:    "credential_process",
	}
	c.Set("aws", "credential_process", cred)

	if got := c.Get("aws", "credential_process"); got != nil {
		t.Fatal("expected nil for expired credential")
	}
}

func TestCache_NeedsRefresh(t *testing.T) {
	cred := &CachedCredential{
		Data:      []byte(`{}`),
		ExpiresAt: time.Now().Add(3 * time.Minute), // within 5-min refresh window
	}
	if !cred.NeedsRefresh() {
		t.Error("expected NeedsRefresh=true for credential expiring in 3 minutes")
	}

	cred2 := &CachedCredential{
		Data:      []byte(`{}`),
		ExpiresAt: time.Now().Add(30 * time.Minute), // well outside refresh window
	}
	if cred2.NeedsRefresh() {
		t.Error("expected NeedsRefresh=false for credential expiring in 30 minutes")
	}
}

func TestCache_Clear(t *testing.T) {
	c := NewCache()
	c.Set("aws", "credential_process", &CachedCredential{
		Data:      []byte(`{}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	c.Set("gcp", "executable", &CachedCredential{
		Data:      []byte(`{}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	c.Clear()

	if got := c.Get("aws", "credential_process"); got != nil {
		t.Error("expected nil after clear")
	}
	if got := c.Get("gcp", "executable"); got != nil {
		t.Error("expected nil after clear")
	}
}

func TestCache_Status(t *testing.T) {
	c := NewCache()
	c.Set("aws", "credential_process", &CachedCredential{
		Data:      []byte(`{}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	status := c.Status()
	if len(status) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(status))
	}
	entry, ok := status["aws:credential_process"]
	if !ok {
		t.Fatal("expected aws:credential_process in status")
	}
	if !entry.Valid {
		t.Error("expected valid=true")
	}
}

func TestCache_DifferentFormats(t *testing.T) {
	c := NewCache()
	c.Set("aws", "credential_process", &CachedCredential{
		Data:      []byte(`{"format":"cp"}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	c.Set("aws", "env", &CachedCredential{
		Data:      []byte(`{"format":"env"}`),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	cp := c.Get("aws", "credential_process")
	env := c.Get("aws", "env")
	if string(cp.Data) == string(env.Data) {
		t.Error("different formats should return different cached values")
	}
}

func TestCache_FetchLock(t *testing.T) {
	c := NewCache()
	mu1 := c.FetchLock("aws", "credential_process")
	mu2 := c.FetchLock("aws", "credential_process")
	if mu1 != mu2 {
		t.Error("same key should return same mutex")
	}

	mu3 := c.FetchLock("gcp", "executable")
	if mu1 == mu3 {
		t.Error("different keys should return different mutexes")
	}
}
