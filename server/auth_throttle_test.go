/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

func TestAuthThrottlePolicy(t *testing.T) {
	if authFailureBurst != 10 || authFailureWindow != 15*time.Minute {
		t.Fatalf("documented policy is 10 failures per 15 minutes, got %d per %v", authFailureBurst, authFailureWindow)
	}
	if got := newAuthThrottle().perToken; got != 90*time.Second {
		t.Fatalf("expected one attempt to refill every 90s, got %v", got)
	}
}

func TestAuthThrottleBucketRefillsAndRefunds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	th := newAuthThrottle()
	th.now = func() time.Time { return now }

	for i := 0; i < authFailureBurst; i++ {
		if _, ok := th.begin("k"); !ok {
			t.Fatalf("attempt %d refused inside the burst", i+1)
		}
	}
	if _, ok := th.begin("k"); ok {
		t.Fatal("attempt past the burst was allowed")
	}

	now = now.Add(89 * time.Second)
	if _, ok := th.begin("k"); ok {
		t.Fatal("attempt allowed before a full refill interval")
	}
	now = now.Add(time.Second)
	a, ok := th.begin("k")
	if !ok {
		t.Fatal("attempt refused after one refill interval")
	}
	a.succeeded()
	if _, ok := th.begin("k"); !ok {
		t.Fatal("a successful attempt must hand its slot back")
	}
}

func TestAuthThrottleBlockedKeyDoesNotChargeOthers(t *testing.T) {
	th := newAuthThrottle()
	for i := 0; i < authFailureBurst; i++ {
		th.begin("ip:a")
	}
	for i := 0; i < authFailureBurst*3; i++ {
		th.begin("ip:a", "user:x")
	}
	if _, ok := th.begin("ip:b", "user:x"); !ok {
		t.Fatal("refused attempts must not drain the other keys")
	}
}

func TestAuthThrottleSweepDropsFullBuckets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	th := newAuthThrottle()
	th.now = func() time.Time { return now }
	th.begin("k1")
	th.begin("k2")
	now = now.Add(authFailureWindow)
	th.begin("k3")
	if _, ok := th.buckets["k1"]; ok || len(th.buckets) != 1 {
		t.Fatalf("expected only k3 to remain after the window, got %d buckets", len(th.buckets))
	}
}

func TestAuthThrottleKeysAreFixedSize(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	if got := len(userKey(long)); got != len(userKey("x")) {
		t.Fatalf("user key grows with the input: %d bytes", got)
	}
	if got := len(fileKey(long, long)); got != len(fileKey("t", "f")) {
		t.Fatalf("file key grows with the input: %d bytes", got)
	}
}

func TestNewEnablesAuthThrottle(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if s.authThrottle == nil {
		t.Fatal("New must wire the auth throttle")
	}
}

func TestLoginThrottleHoldsUnderConcurrency(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)

	const workers = 60
	var wg sync.WaitGroup
	var mu sync.Mutex
	checked := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := loginAttempt(a, "203.0.113.7:1000", "alice", "wrong")
			for _, c := range rec.Result().Cookies() {
				if c.Name == "auth_flash_err" && strings.Contains(c.Value, "Invalid credentials") {
					mu.Lock()
					checked++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if checked != authFailureBurst {
		t.Fatalf("expected exactly %d password checks under concurrency, got %d", authFailureBurst, checked)
	}
}

func TestLoginSuccessDoesNotUseUpBudget(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)

	for i := 0; i < authFailureBurst*2; i++ {
		if id := sessionIDFromResponse(loginAttempt(a, "203.0.113.8:1000", "alice", "longenoughpw")); id == "" {
			t.Fatalf("successful login %d was refused", i+1)
		}
	}
}

func TestBasicAuthTokenGuessesAreThrottledPerIP(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)
	wire, _, err := s.userMeta.CreateAPIToken("alice", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	bogus := wire[:len(wire)-4] + "zzzz"

	statusFrom := func(remote, pass string) int {
		req := httptest.NewRequest("PUT", "/x.txt", nil)
		req.RemoteAddr = remote
		req.SetBasicAuth("alice", pass)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < authFailureBurst; i++ {
		if got := statusFrom("198.51.100.20:1", bogus); got != http.StatusUnauthorized {
			t.Fatalf("token guess %d: expected 401, got %d", i+1, got)
		}
	}
	if got := statusFrom("198.51.100.20:1", wire); got != http.StatusTooManyRequests {
		t.Fatalf("guessing IP: expected 429, got %d", got)
	}
	if got := statusFrom("198.51.100.21:1", wire); got != http.StatusOK {
		t.Fatalf("token guesses must not lock the account for other IPs, got %d", got)
	}
}

func TestBasicAuthPasswordGuessesDoNotLockOutTokens(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)
	wire, _, err := s.userMeta.CreateAPIToken("alice", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < authFailureBurst; i++ {
		req := httptest.NewRequest("PUT", "/x.txt", nil)
		req.RemoteAddr = "198.51.100.66:1"
		req.SetBasicAuth("alice", "wrong")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest("PUT", "/x.txt", nil)
	req.RemoteAddr = "203.0.113.9:1"
	req.SetBasicAuth("alice", wire)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid API token from another IP must still work, got %d", rec.Code)
	}
}

func TestAccountTOTPReauthIsThrottled(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	startTestThrottle(t, a.server)
	enrolTOTP(t, a.server, "alice")

	for _, path := range []string{"/account/2fa/disable", "/account/2fa/recovery/regenerate"} {
		a.server.authThrottle = newAuthThrottle()
		for i := 0; i < authFailureBurst; i++ {
			form := url.Values{"csrf": {csrfTokenFor(sess.ID)}, "code": {"notacode"}}
			postForm(a.handler, path, form, cookieFor(sess.ID))
		}
		if _, ok := a.server.authThrottle.begin(userKey("alice")); ok {
			t.Fatalf("%s: wrong codes must use up the account budget", path)
		}
		form := url.Values{"csrf": {csrfTokenFor(sess.ID)}, "code": {"notacode"}}
		rec := postForm(a.handler, path, form, cookieFor(sess.ID))
		var flash string
		for _, c := range rec.Result().Cookies() {
			if c.Name == "auth_flash_err" {
				flash = c.Value
			}
		}
		if !strings.Contains(flash, "Too many failed attempts") {
			t.Fatalf("%s: expected the throttle message, got %q", path, flash)
		}
	}
}

func lockedGet(s *Server, path, pw string, cookies ...*http.Cookie) int {
	req := fileRequest("GET", path, "")
	if pw != "" {
		req.Header.Set(passwordHeader, pw)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.getHandler(rec, req)
	return rec.Code
}

func TestPasswordHeaderThrottleAnswers429(t *testing.T) {
	s, path := seedProtected(t)
	startTestThrottle(t, s)

	for i := 0; i < authFailureBurst; i++ {
		if got := lockedGet(s, path, "wrong"); got != http.StatusUnauthorized {
			t.Fatalf("guess %d: expected 401, got %d", i+1, got)
		}
	}
	if got := lockedGet(s, path, "s3cret"); got != http.StatusTooManyRequests {
		t.Fatalf("throttled file: expected 429, got %d", got)
	}
}

func TestLockedFileVisitsWithoutPasswordAreNotCounted(t *testing.T) {
	s, path := seedProtected(t)
	startTestThrottle(t, s)

	for i := 0; i < authFailureBurst*2; i++ {
		lockedGet(s, path, "")
	}
	rec := httptest.NewRecorder()
	s.unlockHandler(rec, fileRequest("POST", path, url.Values{"password": {"s3cret"}}.Encode()))
	if rec.Code != http.StatusOK {
		t.Fatalf("unlock after plain visits: expected 200, got %d", rec.Code)
	}
}

func TestUnlockCookieWorksWhileFileIsThrottled(t *testing.T) {
	s, path := seedProtected(t)
	startTestThrottle(t, s)

	rec := httptest.NewRecorder()
	s.unlockHandler(rec, fileRequest("POST", path, url.Values{"password": {"s3cret"}}.Encode()))
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected the unlock cookie, got %+v", cookies)
	}
	for i := 0; i < authFailureBurst; i++ {
		lockedGet(s, path, "wrong")
	}
	if got := lockedGet(s, path, "", cookies[0]); got != http.StatusOK {
		t.Fatalf("a valid unlock cookie must still work, got %d", got)
	}
}

func TestArchiveMismatchesDoNotChargeTheClientIP(t *testing.T) {
	s, store := adminTestServer(t)
	startTestThrottle(t, s)
	hash, err := hashUploadPassword("other")
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"tokaaa", "tokbbb", "tokccc"} {
		seedFile(t, store, tok, "f.txt", "x", metadata{ContentType: "text/plain", MaxDownloads: -1, PasswordHash: hash})
	}
	for i := 0; i < authFailureBurst; i++ {
		req := httptest.NewRequest("GET", "/(tokaaa/f.txt,tokbbb/f.txt,tokccc/f.txt).zip", nil)
		req.Header.Set(passwordHeader, "wrong")
		req = mux.SetURLVars(req, map[string]string{"files": "tokaaa/f.txt,tokbbb/f.txt,tokccc/f.txt"})
		s.zipHandler(httptest.NewRecorder(), req)
	}
	probe := httptest.NewRequest("GET", "/", nil)
	if _, ok := s.authThrottle.begin(ipKey(probe)); !ok {
		t.Fatal("archive password mismatches must not lock out the client IP")
	}
}

func TestRealIPRejectsNonIPXRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Real-Ip", strings.Repeat("x", 4096))
	if got := realIPFromRequest(req); got != "10.0.0.5" {
		t.Fatalf("expected RemoteAddr fallback, got %q", got)
	}
}

func basicAuthFrom(h http.Handler, remote, user, pass string) int {
	req := httptest.NewRequest("PUT", "/x.txt", nil)
	req.RemoteAddr = remote
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestBasicAuthSuccessDoesNotUseUpBudget(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)
	wire, _, err := s.userMeta.CreateAPIToken("alice", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pass := range []string{"longenoughpw", wire} {
		for i := 0; i < authFailureBurst*2; i++ {
			if got := basicAuthFrom(h, "198.51.100.30:1", "alice", pass); got != http.StatusOK {
				t.Fatalf("successful request %d: expected 200, got %d", i+1, got)
			}
		}
	}
}

func TestBasicAuthThrottlesPerUserAcrossIPs(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)
	for i := 0; i < authFailureBurst; i++ {
		basicAuthFrom(h, fmt.Sprintf("198.51.100.%d:1", i+40), "alice", "wrong")
	}
	if got := basicAuthFrom(h, "203.0.113.40:1", "alice", "longenoughpw"); got != http.StatusTooManyRequests {
		t.Fatalf("distributed password guessing must throttle the account, got %d", got)
	}
}

func TestBasicAuthTOTPRejectionDoesNotUseUpBudget(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)
	enrolTOTP(t, s, "alice")
	for i := 0; i < authFailureBurst+1; i++ {
		if got := basicAuthFrom(h, "198.51.100.50:1", "alice", "longenoughpw"); got != http.StatusUnauthorized {
			t.Fatalf("request %d: expected 401, got %d", i+1, got)
		}
	}
}

func TestBasicAuthAllowlistedIPIsNotCharged(t *testing.T) {
	s, h := buildAuthTestServer(t)
	startTestThrottle(t, s)
	s.authIPFilterOptions = &IPFilterOptions{AllowedIPs: []string{"198.51.100.7"}, BlockByDefault: true}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.7:1"
	for i := 0; i < authFailureBurst; i++ {
		s.authThrottle.begin(ipKey(req))
	}
	if got := basicAuthFrom(h, "198.51.100.7:1", "", ""); got != http.StatusOK {
		t.Fatalf("allowlisted IP must pass without touching the throttle, got %d", got)
	}
}

func totpLogin(a *authTestSetup, remote, code string) *httptest.ResponseRecorder {
	sess, _ := a.server.sessions.Create("alice", true)
	form := url.Values{"csrf": {csrfTokenFor(sess.ID)}, "code": {code}}
	req := httptest.NewRequest("POST", "/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remote
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)
	return rec
}

func TestLoginTOTPThrottlesPerUserAcrossIPs(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)
	enrolTOTP(t, a.server, "alice")
	for i := 0; i < authFailureBurst; i++ {
		totpLogin(a, fmt.Sprintf("198.51.100.%d:1", i+60), "notacode")
	}
	if _, ok := a.server.authThrottle.begin(userKey("alice")); ok {
		t.Fatal("TOTP guesses from many IPs must use up the account budget")
	}
}

func TestLoginTOTPThrottlesPerIP(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)
	enrolTOTP(t, a.server, "alice")
	for i := 0; i < authFailureBurst; i++ {
		totpLogin(a, "203.0.113.60:1", "notacode")
	}
	probe := httptest.NewRequest("GET", "/", nil)
	probe.RemoteAddr = "203.0.113.60:1"
	if _, ok := a.server.authThrottle.begin(ipKey(probe)); ok {
		t.Fatal("TOTP guesses must use up the client IP budget")
	}
}

func TestLoginTOTPSuccessDoesNotUseUpBudget(t *testing.T) {
	a := newAuthTestSetup(t)
	startTestThrottle(t, a.server)
	enr, err := a.server.startTOTPEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.server.finishTOTPEnrollment("alice", enr.Secret, currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < authFailureBurst*2; i++ {
		rec := totpLogin(a, "203.0.113.61:1", currentTOTPCode(t, enr.Secret))
		if id := sessionIDFromResponse(rec); id == "" {
			t.Fatalf("valid code %d was refused (Location %q)", i+1, rec.Header().Get("Location"))
		}
	}
}

func TestAccountReauthRefundsSuccessAndEmptySubmits(t *testing.T) {
	a, sess := newAccountTestSetup(t)
	startTestThrottle(t, a.server)
	enr, err := a.server.startTOTPEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.server.finishTOTPEnrollment("alice", enr.Secret, currentTOTPCode(t, enr.Secret)); err != nil {
		t.Fatal(err)
	}
	post := func(path, code string) {
		form := url.Values{"csrf": {csrfTokenFor(sess.ID)}, "code": {code}}
		postForm(a.handler, path, form, cookieFor(sess.ID))
	}
	for i := 0; i < authFailureBurst*2; i++ {
		post("/account/2fa/recovery/regenerate", currentTOTPCode(t, enr.Secret))
		post("/account/2fa/recovery/regenerate", "")
		post("/account/2fa/disable", "")
	}
	if _, ok := a.server.authThrottle.begin(userKey("alice")); !ok {
		t.Fatal("successful or empty re-auth submits must not use up the account budget")
	}
}

func TestDownloadSuccessDoesNotUseUpBudget(t *testing.T) {
	s, path := seedProtected(t)
	startTestThrottle(t, s)
	for i := 0; i < authFailureBurst*2; i++ {
		if got := lockedGet(s, path, "s3cret"); got != http.StatusOK {
			t.Fatalf("download %d: expected 200, got %d", i+1, got)
		}
		rec := httptest.NewRecorder()
		s.unlockHandler(rec, fileRequest("POST", path, url.Values{"password": {"s3cret"}}.Encode()))
		if rec.Code != http.StatusOK || len(rec.Result().Cookies()) != 1 {
			t.Fatalf("unlock %d: expected 200 with cookie, got %d", i+1, rec.Code)
		}
	}
}

func TestThrottledFileAnswers429OnEveryReadPath(t *testing.T) {
	s, path := seedProtected(t)
	startTestThrottle(t, s)
	for i := 0; i < authFailureBurst; i++ {
		lockedGet(s, path, "wrong")
	}
	for name, h := range map[string]http.HandlerFunc{
		"get":     s.getHandler,
		"head":    s.headHandler,
		"preview": s.previewHandler,
	} {
		req := fileRequest("GET", path, "")
		req.Header.Set(passwordHeader, "s3cret")
		req.Header.Set("Accept", "text/html")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s: expected 429, got %d", name, rec.Code)
		}
		if name == "preview" && !strings.Contains(rec.Body.String(), "Too many failed attempts") {
			t.Errorf("preview: the locked page must explain the throttle")
		}
	}
}

func TestFileKeyIsScopedToOneFile(t *testing.T) {
	if fileKey("t", "a") == fileKey("t", "b") || fileKey("t", "a") == fileKey("u", "a") {
		t.Fatal("file keys must differ per token and per filename")
	}
}
