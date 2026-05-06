/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUmamiSendEndpoint(t *testing.T) {
	cases := []struct {
		in, out string
		wantErr bool
	}{
		{"https://umami.example.com/script.js", "https://umami.example.com/api/send", false},
		{"https://example.com/u/script.js", "https://example.com/u/api/send", false},
		{"http://localhost:3000/script.js", "http://localhost:3000/api/send", false},
		// no scheme/host → error
		{"script.js", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := umamiSendEndpoint(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("umamiSendEndpoint(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("umamiSendEndpoint(%q): %v", c.in, err)
			continue
		}
		if got != c.out {
			t.Errorf("umamiSendEndpoint(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestUmamiScriptDisabledByDefault(t *testing.T) {
	activeUmami.Store(nil)
	if got := umamiScript(); got != "" {
		t.Fatalf("expected empty script when disabled, got %q", got)
	}
}

func TestUmamiScriptRendersWhenConfigured(t *testing.T) {
	t.Cleanup(func() { activeUmami.Store(nil) })
	(&umamiConfig{
		scriptURL: "https://umami.example.com/script.js",
		websiteID: "abc-123",
	}).install()
	got := umamiScript()
	if !strings.Contains(got, `src="https://umami.example.com/script.js"`) {
		t.Errorf("missing src: %q", got)
	}
	if !strings.Contains(got, `data-website-id="abc-123"`) {
		t.Errorf("missing website-id: %q", got)
	}
}

func TestUmamiInstallRequiresBothFields(t *testing.T) {
	t.Cleanup(func() { activeUmami.Store(nil) })
	(&umamiConfig{scriptURL: "https://umami.example.com/script.js"}).install()
	if activeUmami.Load() != nil {
		t.Fatal("install should reject missing website-id")
	}
	(&umamiConfig{websiteID: "abc"}).install()
	if activeUmami.Load() != nil {
		t.Fatal("install should reject missing script URL")
	}
}

func TestUmamiHeartbeatPosts(t *testing.T) {
	var hits int32
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/send" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &Server{
		umamiHeartbeat: true,
		umamiScriptURL: srv.URL + "/script.js",
		umamiWebsiteID: "site-1",
		logger:         log.New(io.Discard, "", 0),
	}
	endpoint, err := umamiSendEndpoint(s.umamiScriptURL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.sendUmamiHeartbeat(ctx, &http.Client{Timeout: 2 * time.Second}, endpoint)

	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly one beat, got %d", hits)
	}
	if got["type"] != "event" {
		t.Errorf("type: got %v", got["type"])
	}
	payload, _ := got["payload"].(map[string]any)
	if payload["website"] != "site-1" {
		t.Errorf("website: got %v", payload["website"])
	}
	if payload["url"] != "/heartbeat" {
		t.Errorf("url: got %v", payload["url"])
	}
}
