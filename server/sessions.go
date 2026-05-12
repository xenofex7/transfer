/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Session-related constants. The cookie name is part of our public
// surface — changing it logs every active user out. TTLs are sliding:
// LastSeenAt is bumped on every authenticated request, and we expire
// idleSessionTTL after the last hit (capped by maxSessionLifetime so a
// stolen cookie can't live forever).
const (
	sessionCookieName = "transfer_session"
	sessionIDBytes    = 32 // 256 bits, base64-url encoded → 43 chars

	defaultIdleSessionTTL = 8 * time.Hour
	maxSessionLifetime    = 30 * 24 * time.Hour
	sessionGCInterval     = 5 * time.Minute
)

var (
	errSessionNotFound = errors.New("session not found")
)

// session is the authenticated state we associate with a cookie. We
// keep it server-side rather than signing the data into the cookie
// itself so logout/revocation works instantly and rotating the secret
// never strands users mid-flow.
//
// PendingMFA is true between the password step and the TOTP step. A
// pending session may not call protected handlers; it only lets the
// TOTP form know who's verifying.
type session struct {
	ID         string
	Username   string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	PendingMFA bool
}

// sessionStore is the in-memory session table. Single-instance only,
// since restarts wipe the map. That's an intentional trade-off: it
// keeps the code small and avoids a serialisation/encryption story
// for sensitive Username material. If we ever need cross-restart
// persistence we'll bolt on an opaque encrypted file.
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*session
	idle     time.Duration
	maxLife  time.Duration

	now    func() time.Time // injectable for tests
	stopCh chan struct{}
	once   sync.Once
}

func newSessionStore(idle, maxLife time.Duration) *sessionStore {
	if idle <= 0 {
		idle = defaultIdleSessionTTL
	}
	if maxLife <= 0 {
		maxLife = maxSessionLifetime
	}
	return &sessionStore{
		sessions: map[string]*session{},
		idle:     idle,
		maxLife:  maxLife,
		now:      func() time.Time { return time.Now().UTC() },
		stopCh:   make(chan struct{}),
	}
}

// Start kicks off the background GC goroutine. Idempotent — calling
// twice is a no-op so server bootstrapping can be liberal about it.
// The returned stop function shuts the GC down cleanly; callers (and
// tests) should defer it.
func (s *sessionStore) Start() func() {
	s.once.Do(func() {
		go s.gcLoop()
	})
	return func() {
		select {
		case <-s.stopCh:
			// already stopped
		default:
			close(s.stopCh)
		}
	}
}

func (s *sessionStore) gcLoop() {
	t := time.NewTicker(sessionGCInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *sessionStore) sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > s.maxLife {
			delete(s.sessions, id)
		}
	}
}

// Create issues a fresh session. PendingMFA marks half-authenticated
// sessions (password OK, TOTP outstanding) so the auth middleware can
// route them to the TOTP form instead of granting access.
func (s *sessionStore) Create(username string, pendingMFA bool) (*session, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	now := s.now()
	sess := &session{
		ID:         id,
		Username:   username,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(s.idle),
		PendingMFA: pendingMFA,
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get looks up a session by ID and bumps LastSeenAt/ExpiresAt when the
// session is still live. Returns errSessionNotFound for unknown,
// expired, or past-max-lifetime IDs and removes them from the map.
func (s *sessionStore) Get(id string) (*session, error) {
	if id == "" {
		return nil, errSessionNotFound
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, errSessionNotFound
	}
	if now.After(sess.ExpiresAt) || now.Sub(sess.CreatedAt) > s.maxLife {
		delete(s.sessions, id)
		return nil, errSessionNotFound
	}
	sess.LastSeenAt = now
	sess.ExpiresAt = now.Add(s.idle)
	cp := *sess
	return &cp, nil
}

// Promote upgrades a PendingMFA session into a fully authenticated
// session by minting a fresh ID. Mid-flight ID rotation prevents
// session fixation: an attacker who somehow plants the pending cookie
// can't ride it into a logged-in state.
func (s *sessionStore) Promote(id string) (*session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.sessions[id]
	if !ok {
		return nil, errSessionNotFound
	}
	newID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	now := s.now()
	upgraded := &session{
		ID:         newID,
		Username:   old.Username,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(s.idle),
		PendingMFA: false,
	}
	delete(s.sessions, id)
	s.sessions[newID] = upgraded
	cp := *upgraded
	return &cp, nil
}

// Destroy invalidates a session by ID. Always safe to call, even with
// a missing or empty ID — keeps the logout handler simple.
func (s *sessionStore) Destroy(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// DestroyAllFor removes every session belonging to username. Use after
// a password reset or a 2FA-disable so existing cookies stop working.
func (s *sessionStore) DestroyAllFor(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.Username == username {
			delete(s.sessions, id)
		}
	}
}

// Count returns the live session count, post-sweep. Exposed for tests
// and a possible future admin diagnostic.
func (s *sessionStore) Count() int {
	s.sweep()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func newSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// requestIsHTTPS decides whether to mark cookies Secure. We trust
// r.TLS first (direct connection) and X-Forwarded-Proto second (behind
// a reverse proxy). Refusing to set Secure on plain HTTP is intended:
// the cookie would never be sent back, and silently downgrading would
// hide the misconfiguration from the operator.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}
	return false
}

// setSessionCookie writes the session ID to the response. maxAge=0
// (called with a zero session for logout) emits a Max-Age=-1 deletion.
func setSessionCookie(w http.ResponseWriter, r *http.Request, id string, ttl time.Duration) {
	c := &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	}
	if id == "" {
		c.MaxAge = -1
	} else if ttl > 0 {
		c.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, c)
}

// readSessionCookie pulls the session ID out of the request. Returns
// "" when the cookie is missing or empty so callers can treat both
// the same.
func readSessionCookie(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
