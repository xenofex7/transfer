/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	authFailureBurst  = 10
	authFailureWindow = 15 * time.Minute
	tooManyAttempts   = "Too many failed attempts, try again in a few minutes"
)

type authBucket struct {
	tokens  float64
	updated time.Time
}

type authThrottle struct {
	mu       sync.Mutex
	buckets  map[string]*authBucket
	burst    float64
	perToken time.Duration
	swept    time.Time
	now      func() time.Time
}

type authAttempt struct {
	throttle *authThrottle
	keys     []string
}

func newAuthThrottle() *authThrottle {
	return &authThrottle{
		buckets:  make(map[string]*authBucket),
		burst:    authFailureBurst,
		perToken: authFailureWindow / authFailureBurst,
		now:      time.Now,
	}
}

func (t *authThrottle) level(b *authBucket, now time.Time) float64 {
	return min(t.burst, b.tokens+float64(now.Sub(b.updated))/float64(t.perToken))
}

func (t *authThrottle) begin(keys ...string) (*authAttempt, bool) {
	if t == nil {
		return nil, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.sweep(now)
	for _, k := range keys {
		if b, ok := t.buckets[k]; ok && t.level(b, now) < 1 {
			return nil, false
		}
	}
	for _, k := range keys {
		b, ok := t.buckets[k]
		if !ok {
			b = &authBucket{tokens: t.burst, updated: now}
			t.buckets[k] = b
		}
		b.tokens = t.level(b, now) - 1
		b.updated = now
	}
	return &authAttempt{throttle: t, keys: keys}, true
}

func (a *authAttempt) succeeded() {
	if a == nil {
		return
	}
	t := a.throttle
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, k := range a.keys {
		if b, ok := t.buckets[k]; ok {
			b.tokens = min(t.burst, t.level(b, now)+1)
			b.updated = now
		}
	}
}

func (t *authThrottle) sweep(now time.Time) {
	if now.Sub(t.swept) < time.Minute {
		return
	}
	t.swept = now
	for k, b := range t.buckets {
		if t.level(b, now) >= t.burst {
			delete(t.buckets, k)
		}
	}
}

func throttleDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

func ipKey(r *http.Request) string {
	return "ip:" + realIPFromRequest(r)
}

func userKey(name string) string {
	return "user:" + throttleDigest(name)
}

func fileKey(token, filename string) string {
	return "file:" + throttleDigest(token+"/"+filename)
}

func (s *Server) passwordAuthAllowed(username string) bool {
	if s.userMeta == nil {
		return true
	}
	m, _ := s.userMeta.Get(username)
	return !m.TOTPEnabled && !s.authRequireTOTP
}
