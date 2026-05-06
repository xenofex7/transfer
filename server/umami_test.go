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

func TestHeartbeatSendPosts(t *testing.T) {
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

	s := &Server{logger: log.New(io.Discard, "", 0)}
	endpoint, err := umamiSendEndpoint(srv.URL + "/script.js")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.sendHeartbeat(ctx, &http.Client{Timeout: 2 * time.Second}, endpoint, "site-1")

	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected exactly one beat, got %d", hits)
	}
	payload, _ := got["payload"].(map[string]any)
	if payload["website"] != "site-1" {
		t.Errorf("website: got %v", payload["website"])
	}
	if payload["url"] != "/heartbeat" {
		t.Errorf("url: got %v", payload["url"])
	}
}

// freshSettingsStore swaps activeSettings so HeartbeatActive can read
// the toggle without persisting anything to disk.
func freshSettingsStore(t *testing.T, persisted *bool) {
	t.Helper()
	prev := activeSettings.Load()
	t.Cleanup(func() { activeSettings.Store(prev) })

	tmp := t.TempDir() + "/settings.json"
	store, err := newSettingsStore(tmp, Settings{Theme: DefaultTheme})
	if err != nil {
		t.Fatal(err)
	}
	if persisted != nil {
		s := store.Get()
		s.HeartbeatEnabled = persisted
		if err := store.Set(s); err != nil {
			t.Fatal(err)
		}
	}
	activeSettings.Store(store)
}

func TestHeartbeatActiveResolution(t *testing.T) {
	tru, fal := true, false

	cases := []struct {
		name      string
		override  HeartbeatOverride
		persisted *bool
		want      bool
		source    string
	}{
		{"default-on with no override and no persisted choice", HeartbeatOverrideUnset, nil, true, "default"},
		{"persisted false beats default", HeartbeatOverrideUnset, &fal, false, "settings"},
		{"persisted true is honoured", HeartbeatOverrideUnset, &tru, true, "settings"},
		{"env on wins over persisted false", HeartbeatOverrideOn, &fal, true, "env"},
		{"env off wins over persisted true", HeartbeatOverrideOff, &tru, false, "env"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			freshSettingsStore(t, c.persisted)
			s := &Server{umamiHeartbeatOverride: c.override}
			active, source := s.HeartbeatActive()
			if active != c.want || source != c.source {
				t.Errorf("got (%v, %q), want (%v, %q)", active, source, c.want, c.source)
			}
		})
	}
}

func TestHeartbeatTargetFallsBackToBuiltIn(t *testing.T) {
	s := &Server{}
	url, id := s.heartbeatTarget()
	if url != defaultHeartbeatScriptURL || id != defaultHeartbeatWebsiteID {
		t.Errorf("expected baked-in defaults, got (%q, %q)", url, id)
	}

	s = &Server{umamiHeartbeatURL: "https://x.example/u/script.js", umamiHeartbeatID: "site-9"}
	url, id = s.heartbeatTarget()
	if url != "https://x.example/u/script.js" || id != "site-9" {
		t.Errorf("operator override ignored: got (%q, %q)", url, id)
	}
}

func TestHeartbeatPayloadIsAnonymous(t *testing.T) {
	p := heartbeatPayload("site-x")
	pp := p["payload"].(map[string]any)
	for _, banned := range []string{"ip", "remote_addr", "user", "username", "email"} {
		if _, ok := pp[banned]; ok {
			t.Errorf("payload should not include %q", banned)
		}
		if _, ok := p[banned]; ok {
			t.Errorf("envelope should not include %q", banned)
		}
	}
	data, _ := pp["data"].(map[string]any)
	for k := range data {
		if k != "version" {
			t.Errorf("payload.data should only carry version, found %q", k)
		}
	}
}
