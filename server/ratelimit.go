/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter throttles requests per client IP using a token-bucket. The bucket
// is sized to accept perMinute requests in steady state, with a burst of the
// same size so legitimate clients are not surprised by sub-second jitter.
//
// Memory bound: every distinct IP gets its own *rate.Limiter; entries that
// have been idle for ttl are dropped by the background reaper.
type ipLimiter struct {
	mu       sync.Mutex
	visitors map[string]*ipVisitor
	rate     rate.Limit
	burst    int
	ttl      time.Duration
	stop     chan struct{}
	now      func() time.Time
}

type ipVisitor struct {
	limiter *rate.Limiter
	seen    time.Time
}

// newIPLimiter returns a per-IP rate limiter that allows perMinute requests
// per minute. Calling Stop is optional; on process exit the goroutine is
// reclaimed by the runtime.
func newIPLimiter(perMinute int) *ipLimiter {
	l := &ipLimiter{
		visitors: make(map[string]*ipVisitor),
		rate:     rate.Limit(float64(perMinute) / 60.0),
		burst:    perMinute,
		ttl:      10 * time.Minute,
		stop:     make(chan struct{}),
		now:      time.Now,
	}
	go l.reap(time.Minute)
	return l
}

// Allow reports whether the given IP can send one more request right now.
// Updates the visitor's last-seen timestamp on every call.
func (l *ipLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.visitors[ip]
	if !ok {
		v = &ipVisitor{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.visitors[ip] = v
	}
	v.seen = l.now()
	return v.limiter.Allow()
}

// Stop ends the reaper goroutine. Safe to call only once.
func (l *ipLimiter) Stop() {
	close(l.stop)
}

func (l *ipLimiter) reap(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.evictStale()
		}
	}
}

func (l *ipLimiter) evictStale() {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := l.now().Add(-l.ttl)
	for ip, v := range l.visitors {
		if v.seen.Before(cutoff) {
			delete(l.visitors, ip)
		}
	}
}

// Wrap returns an http.Handler that enforces this limiter on every request.
// Clients identified via realIPFromRequest; an over-limit caller gets a
// plain 429 response.
func (l *ipLimiter) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(realIPFromRequest(r)) {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}
