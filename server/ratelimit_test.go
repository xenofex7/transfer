package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPLimiterAllowsBurstThenBlocks(t *testing.T) {
	// 60 per minute -> burst of 60, ~1/sec replenish. We expect the 61st
	// request inside the same instant to be denied.
	l := newIPLimiter(60)
	defer l.Stop()

	for i := 0; i < 60; i++ {
		if !l.Allow("203.0.113.7") {
			t.Fatalf("request %d was unexpectedly denied within burst", i+1)
		}
	}
	if l.Allow("203.0.113.7") {
		t.Fatal("burst+1 request was allowed; expected throttling")
	}
}

func TestIPLimiterIsolatesIPs(t *testing.T) {
	l := newIPLimiter(2)
	defer l.Stop()

	if !l.Allow("198.51.100.1") || !l.Allow("198.51.100.1") {
		t.Fatal("first IP exhausted before reaching its burst")
	}
	if l.Allow("198.51.100.1") {
		t.Fatal("first IP not throttled past its burst")
	}
	// A different IP must still get its own bucket.
	if !l.Allow("198.51.100.2") {
		t.Fatal("second IP unexpectedly throttled")
	}
}

func TestIPLimiterReaperEvictsStaleVisitors(t *testing.T) {
	l := newIPLimiter(10)
	defer l.Stop()
	// Make ttl tiny for the test.
	l.ttl = 50 * time.Millisecond

	_ = l.Allow("198.51.100.10")
	_ = l.Allow("198.51.100.11")

	l.mu.Lock()
	if got := len(l.visitors); got != 2 {
		l.mu.Unlock()
		t.Fatalf("visitors before eviction: got %d, want 2", got)
	}
	l.mu.Unlock()

	// Travel time forward via the injected clock.
	l.now = func() time.Time { return time.Now().Add(time.Second) }
	l.evictStale()

	l.mu.Lock()
	defer l.mu.Unlock()
	if got := len(l.visitors); got != 0 {
		t.Fatalf("visitors after eviction: got %d, want 0", got)
	}
}

func TestIPLimiterWrapReturns429(t *testing.T) {
	l := newIPLimiter(1)
	defer l.Stop()

	handler := l.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "203.0.113.99:1234"

	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", w1.Code)
	}

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", w2.Code)
	}
}
