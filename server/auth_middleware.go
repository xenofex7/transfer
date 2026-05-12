/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"context"
	"net/http"
	"net/url"
)

// authContextKey is an unexported type so other packages cannot
// collide with the key we stuff the authenticated user into.
type authContextKey struct{}

// withAuthUser returns a child context tagging the request as
// authenticated for username. We carry just the name; everything else
// the handler needs (TOTP state, tokens) is one meta-store lookup
// away.
func withAuthUser(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, authContextKey{}, username)
}

// authUserFromContext pulls the authenticated username back out.
// Returns "" if the request was not tagged — callers should treat
// that as anonymous.
func authUserFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(authContextKey{}).(string); ok {
		return v
	}
	return ""
}

// currentUserFromRequest is the migration-friendly accessor for
// handlers that used to read r.BasicAuth(): it prefers the context
// value (set by basicAuthHandler / webAuthHandler) and falls back to
// the raw Basic Auth header so any unconverted handler keeps working
// while the rollout is in progress.
func currentUserFromRequest(r *http.Request) string {
	if name := authUserFromContext(r.Context()); name != "" {
		return name
	}
	name, _, _ := r.BasicAuth()
	return name
}

// sessionForRequest is the inverse of webAuthHandler's tagging step:
// it pulls the authenticated session back out from the cookie so a
// handler can read sess.ID for CSRF binding without re-implementing
// the gate. Returns false if the cookie is missing/expired or the
// session is only half-authenticated; in those cases webAuthHandler
// would have redirected before we ever got here, but defensive code
// still has to handle it (e.g. direct test invocation).
func (s *Server) sessionForRequest(r *http.Request) (*session, bool) {
	if s.sessions == nil {
		return nil, false
	}
	sess, err := s.sessions.Get(readSessionCookie(r))
	if err != nil || sess.PendingMFA {
		return nil, false
	}
	return sess, true
}

// webAuthHandler gates a route on a fully-authenticated session
// cookie. Unauthenticated and PendingMFA requests are 303'd to
// /login with the original URL stuffed into ?next= so the post-login
// redirect lands where the user was trying to go.
//
// On success the username is tagged onto the request context via
// withAuthUser so downstream handlers don't have to re-parse the
// cookie or read r.BasicAuth().
func (s *Server) webAuthHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessions == nil {
			// No session store wired — fall through to basic auth so
			// the server stays usable in single-user setups that
			// never enabled the cookie flow.
			s.basicAuthHandler(h).ServeHTTP(w, r)
			return
		}
		sess, err := s.sessions.Get(readSessionCookie(r))
		if err != nil || sess.PendingMFA {
			next := url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, "/login?"+loginRedirectParam+"="+next, http.StatusSeeOther)
			return
		}
		r = r.WithContext(withAuthUser(r.Context(), sess.Username))
		h.ServeHTTP(w, r)
	}
}
