package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func seedProtected(t *testing.T) (*Server, string) {
	t.Helper()
	s, store := adminTestServer(t)
	hash, err := hashUploadPassword("s3cret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	seedFile(t, store, "tok123", "doc.txt", "hello", metadata{ContentType: "text/plain", MaxDownloads: -1, PasswordHash: hash})
	return s, "/tok123/doc.txt"
}

func fileRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return mux.SetURLVars(req, map[string]string{"token": "tok123", "filename": "doc.txt"})
}

func TestProtectedUploadRequiresPassword(t *testing.T) {
	s, path := seedProtected(t)

	rec := httptest.NewRecorder()
	s.getHandler(rec, fileRequest("GET", path, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET without password: expected 401, got %d", rec.Code)
	}

	req := fileRequest("GET", path, "")
	req.Header.Set(passwordHeader, "wrong")
	rec = httptest.NewRecorder()
	s.getHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET with wrong password: expected 401, got %d", rec.Code)
	}

	req = fileRequest("GET", path, "")
	req.Header.Set(passwordHeader, "s3cret")
	rec = httptest.NewRecorder()
	s.getHandler(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "hello" {
		t.Fatalf("GET with password: expected 200 hello, got %d %q", rec.Code, rec.Body.String())
	}

	m, err := s.checkMetadata(req.Context(), "tok123", "doc.txt", false)
	if err != nil || m.Downloads != 1 {
		t.Fatalf("expected exactly one counted download, got %d (err %v)", m.Downloads, err)
	}
}

func TestUnlockHandlerSetsCookieForPreviewAndGet(t *testing.T) {
	s, path := seedProtected(t)

	rec := httptest.NewRecorder()
	s.unlockHandler(rec, fileRequest("POST", path, url.Values{"password": {"nope"}}.Encode()))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Wrong password") {
		t.Fatalf("wrong password: expected 401 locked page, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	s.unlockHandler(rec, fileRequest("POST", path, url.Values{"password": {"s3cret"}}.Encode()))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Direct URL") {
		t.Fatalf("unlock: expected the preview page, got %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != unlockCookieName("tok123") {
		t.Fatalf("unlock: expected unlock cookie, got %+v", cookies)
	}

	req := fileRequest("GET", path, "")
	req.Header.Set("Accept", "text/html")
	rec = httptest.NewRecorder()
	s.previewHandler(rec, req)
	if !strings.Contains(rec.Body.String(), "Unlock") {
		t.Fatal("preview without cookie should render the locked page")
	}

	req = fileRequest("GET", path, "")
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()
	s.getHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with cookie: expected 200, got %d", rec.Code)
	}
}

func TestUploadOptionsHandler(t *testing.T) {
	s, store := adminTestServer(t)
	seedFile(t, store, "tok123", "doc.txt", "hello", metadata{ContentType: "text/plain", MaxDownloads: -1, DeletionToken: "del456"})

	patch := func(deletionToken, body string) int {
		req := httptest.NewRequest("PATCH", "/tok123/doc.txt/"+deletionToken, strings.NewReader(body))
		req = mux.SetURLVars(req, map[string]string{"token": "tok123", "filename": "doc.txt", "deletionToken": deletionToken})
		rec := httptest.NewRecorder()
		s.uploadOptionsHandler(rec, req)
		return rec.Code
	}

	if code := patch("wrong", `{"maxDownloads":3,"password":"pw"}`); code != http.StatusNotFound {
		t.Fatalf("wrong deletion token: expected 404, got %d", code)
	}
	if code := patch("del456", `{"maxDownloads":3,"password":"pw"}`); code != http.StatusNoContent {
		t.Fatalf("set options: expected 204, got %d", code)
	}
	m, err := s.checkMetadata(context.Background(), "tok123", "doc.txt", false)
	if err != nil || m.MaxDownloads != 3 || !m.passwordMatches("pw") {
		t.Fatalf("options not applied: max %d, password ok %v, err %v", m.MaxDownloads, m.passwordMatches("pw"), err)
	}

	if code := patch("del456", `{"maxDownloads":5}`); code != http.StatusNoContent {
		t.Fatalf("keep password: expected 204, got %d", code)
	}
	m, _ = s.checkMetadata(context.Background(), "tok123", "doc.txt", false)
	if m.MaxDownloads != 5 || !m.passwordMatches("pw") {
		t.Fatalf("omitted password not kept: max %d, password ok %v", m.MaxDownloads, m.passwordMatches("pw"))
	}

	if code := patch("del456", `{"maxDownloads":0,"password":""}`); code != http.StatusNoContent {
		t.Fatalf("clear options: expected 204, got %d", code)
	}
	m, _ = s.checkMetadata(context.Background(), "tok123", "doc.txt", false)
	if m.MaxDownloads != -1 || m.PasswordHash != "" {
		t.Fatalf("options not cleared: max %d, hash %q", m.MaxDownloads, m.PasswordHash)
	}
}
