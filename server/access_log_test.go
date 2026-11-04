package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccessLogWritesForwardedClientIP(t *testing.T) {
	var buf bytes.Buffer
	h := accessLog(log.New(&buf, "", 0), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "172.18.0.5:41234"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Real-Ip", "203.0.113.7")
	h(httptest.NewRecorder(), req)

	if !strings.HasPrefix(buf.String(), "203.0.113.7 - - [") {
		t.Fatalf("expected the forwarded client IP first, got %q", buf.String())
	}
}

func TestAccessLogRedactsDeletionToken(t *testing.T) {
	for _, c := range []struct{ method, path, want string }{
		{"DELETE", "/abc123/file.txt/secretdeltoken", `"DELETE /abc123/file.txt/REDACTED `},
		{"PATCH", "/abc123/file.txt/secretdeltoken", `"PATCH /abc123/file.txt/REDACTED `},
		{"GET", "/abc123/file.txt", `"GET /abc123/file.txt `},
		{"DELETE", "/admin/branding/logo", `"DELETE /admin/branding/logo `},
	} {
		var buf bytes.Buffer
		h := accessLog(log.New(&buf, "", 0), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		h(httptest.NewRecorder(), httptest.NewRequest(c.method, c.path, nil))
		if !strings.Contains(buf.String(), c.want) || strings.Contains(buf.String(), "secretdeltoken") {
			t.Errorf("%s %s: log line %q, want it to contain %q", c.method, c.path, buf.String(), c.want)
		}
	}
}

func TestPanicRecoverHidesPanicText(t *testing.T) {
	h := panicRecover(log.New(&bytes.Buffer{}, "", 0), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("runtime error: index out of range [1] with length 1")
	}))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "index out of range") {
		t.Fatalf("got %d %q, want a generic 500", rec.Code, rec.Body.String())
	}
}

func TestArchiveEntryRejectsTraversalAndMalformedKeys(t *testing.T) {
	for _, key := range []string{"..", "../x", "../etc/passwd", "abc", "", "/file.txt", "a.b/file.txt", "abc/..", "abc/."} {
		if token, filename, ok := archiveEntry(key, ""); ok {
			t.Errorf("%q accepted as %q/%q", key, token, filename)
		}
	}
	if token, filename, ok := archiveEntry("/Ab12/report.pdf", ""); !ok || token != "Ab12" || filename != "report.pdf" {
		t.Errorf("valid key rejected: %q %q %v", token, filename, ok)
	}
}

func TestAccessLogKeepsRedactedPathEscaped(t *testing.T) {
	var buf bytes.Buffer
	h := accessLog(log.New(&buf, "", 0), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h(httptest.NewRecorder(), httptest.NewRequest("DELETE", "/tok/a%0A1.2.3.4%20%22GET/deltoken", nil))
	if line := buf.String(); strings.Count(line, "\n") != 1 || strings.Contains(line, `"GET`) || strings.Contains(line, "deltoken") {
		t.Fatalf("log line must stay on one escaped line without the token, got %q", line)
	}
}
