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
