package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(t *testing.T, headers map[string]string, remoteAddr string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestRealIPFromXForwardedForUsesRightmostPublicHop(t *testing.T) {
	r := newReq(t, map[string]string{
		"X-Forwarded-For": "203.0.113.5, 10.0.0.2, 192.168.1.1",
	}, "10.0.0.2:1234")

	if got := realIPFromRequest(r); got != "203.0.113.5" {
		t.Errorf("got %q, want public hop 203.0.113.5", got)
	}
}

func TestRealIPIgnoresSpoofedLeadingXForwardedForEntry(t *testing.T) {
	r := newReq(t, map[string]string{
		"X-Forwarded-For": "198.51.100.1, 203.0.113.5",
	}, "172.17.0.1:1234")

	if got := realIPFromRequest(r); got != "203.0.113.5" {
		t.Errorf("got %q, want proxy-appended hop 203.0.113.5", got)
	}
}

func TestRealIPIgnoresForwardedHeadersFromPublicRemote(t *testing.T) {
	r := newReq(t, map[string]string{
		"X-Forwarded-For": "198.51.100.1",
		"X-Real-Ip":       "198.51.100.2",
	}, "203.0.113.99:5500")

	if got := realIPFromRequest(r); got != "203.0.113.99" {
		t.Errorf("got %q, want RemoteAddr 203.0.113.99 for untrusted peer", got)
	}
}

func TestRealIPSkipsAllPrivateXForwardedFor(t *testing.T) {
	r := newReq(t, map[string]string{
		"X-Forwarded-For": "10.0.0.2, 192.168.1.1",
		"X-Real-Ip":       "198.51.100.7",
	}, "10.0.0.2:1234")

	if got := realIPFromRequest(r); got != "198.51.100.7" {
		t.Errorf("got %q, want X-Real-Ip fallback 198.51.100.7", got)
	}
}

func TestRealIPFallsBackToRemoteAddr(t *testing.T) {
	r := newReq(t, nil, "203.0.113.99:5500")
	if got := realIPFromRequest(r); got != "203.0.113.99" {
		t.Errorf("got %q, want host portion 203.0.113.99", got)
	}
}

func TestRealIPHandlesIPv6RemoteAddr(t *testing.T) {
	r := newReq(t, nil, "[2001:db8::1]:9000")
	if got := realIPFromRequest(r); got != "2001:db8::1" {
		t.Errorf("got %q, want bracket-stripped 2001:db8::1", got)
	}
}

func TestRealIPIgnoresEmptyXForwardedForChunks(t *testing.T) {
	r := newReq(t, map[string]string{
		"X-Forwarded-For": ", , 198.51.100.10",
	}, "10.0.0.2:1234")
	if got := realIPFromRequest(r); got != "198.51.100.10" {
		t.Errorf("got %q, want 198.51.100.10", got)
	}
}
