/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Built-in heartbeat target. Forks publish to the upstream "transfer
// instances" Umami site so the maintainer can see how many copies of
// the project are alive in the wild. Operators can override the URL /
// website-id via env (advanced) or disable the beat entirely from the
// admin settings.
const (
	defaultHeartbeatScriptURL = "https://umami.pac-build.ch/script.js"
	defaultHeartbeatWebsiteID = "64a322f9-08e7-4992-a6aa-aac6a27af62f"
)

// HeartbeatOverride represents an explicit env-level toggle that wins
// over the persisted operator choice. "" means no override; the
// operator-set value (or the built-in default) is used instead.
type HeartbeatOverride string

const (
	HeartbeatOverrideUnset HeartbeatOverride = ""
	HeartbeatOverrideOn    HeartbeatOverride = "on"
	HeartbeatOverrideOff   HeartbeatOverride = "off"
)

// activeUmami carries the operator-configured page-view tracker config
// to the template helpers. nil disables visitor tracking entirely.
// This is independent of the server-side heartbeat.
var activeUmami atomic.Pointer[umamiConfig]

type umamiConfig struct {
	scriptURL string
	websiteID string
}

func (u *umamiConfig) install() {
	if u == nil || u.scriptURL == "" || u.websiteID == "" {
		activeUmami.Store(nil)
		return
	}
	activeUmami.Store(u)
}

// umamiScript returns the script tag for the visitor-side Umami
// tracker, or an empty string when tracking is not configured. Used by
// user-facing templates; admin pages must omit the call.
func umamiScript() string {
	cfg := activeUmami.Load()
	if cfg == nil {
		return ""
	}
	return fmt.Sprintf(
		`<script defer src=%q data-website-id=%q></script>`,
		cfg.scriptURL, cfg.websiteID,
	)
}

// heartbeatTarget returns the (URL, ID) pair the heartbeat goroutine
// should ping. Operator-supplied env values win, otherwise the
// built-in defaults apply.
func (s *Server) heartbeatTarget() (string, string) {
	url := s.umamiHeartbeatURL
	if url == "" {
		url = defaultHeartbeatScriptURL
	}
	id := s.umamiHeartbeatID
	if id == "" {
		id = defaultHeartbeatWebsiteID
	}
	return url, id
}

// HeartbeatActive returns the resolved on/off state plus a short label
// describing the source of that decision. Resolution order:
//
//  1. Env override (UMAMI_HEARTBEAT=on|off)
//  2. Persisted operator choice in settings.json
//  3. Built-in default (on)
func (s *Server) HeartbeatActive() (active bool, source string) {
	switch s.umamiHeartbeatOverride {
	case HeartbeatOverrideOn:
		return true, "env"
	case HeartbeatOverrideOff:
		return false, "env"
	}
	if cfg := activeSettings.Load(); cfg != nil {
		if v := cfg.Get().HeartbeatEnabled; v != nil {
			return *v, "settings"
		}
	}
	return true, "default"
}

// startHeartbeat fires one immediate beat (after a 30 s settle delay)
// and then one every 24 h until ctx is cancelled. Honours runtime
// changes to the operator toggle by re-checking before each send.
func (s *Server) startHeartbeat(ctx context.Context) {
	url, id := s.heartbeatTarget()
	endpoint, err := umamiSendEndpoint(url)
	if err != nil {
		s.logger.Printf("umami: heartbeat disabled, cannot derive send endpoint: %v", err)
		return
	}

	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		s.maybeSendHeartbeat(ctx, client, endpoint, id)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.maybeSendHeartbeat(ctx, client, endpoint, id)
			}
		}
	}()
}

func (s *Server) maybeSendHeartbeat(ctx context.Context, client *http.Client, endpoint, websiteID string) {
	if active, _ := s.HeartbeatActive(); !active {
		return
	}
	s.sendHeartbeat(ctx, client, endpoint, websiteID)
}

func (s *Server) sendHeartbeat(ctx context.Context, client *http.Client, endpoint, websiteID string) {
	body, err := json.Marshal(heartbeatPayload(websiteID))
	if err != nil {
		s.logger.Printf("umami: marshal heartbeat: %v", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		s.logger.Printf("umami: build heartbeat request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "transfer/"+BuildVersion+" heartbeat")
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Printf("umami: heartbeat post: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		s.logger.Printf("umami: heartbeat returned %d", resp.StatusCode)
	}
}

// heartbeatPayload returns the JSON we would POST. It is deliberately
// stripped of any per-instance identifier: the only carried field is
// the running version. The Umami operator still sees the source IP at
// the HTTP layer; that's documented in the README.
func heartbeatPayload(websiteID string) map[string]any {
	return map[string]any{
		"type": "event",
		"payload": map[string]any{
			"website":  websiteID,
			"hostname": "transfer",
			"language": "en",
			"url":      "/heartbeat",
			"name":     "server-heartbeat",
			"data": map[string]any{
				"version": BuildVersion,
			},
		},
	}
}

// umamiSendEndpoint converts a script URL like
// `https://umami.example.com/script.js` into the matching ingestion
// endpoint `https://umami.example.com/api/send`. Custom paths to
// `script.js` are honoured (the file name is replaced, the prefix
// kept), so reverse-proxy setups still work.
func umamiSendEndpoint(scriptURL string) (string, error) {
	u, err := url.Parse(scriptURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("script url missing scheme or host: %q", scriptURL)
	}
	path := u.Path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		path = path[:idx+1]
	} else {
		path = "/"
	}
	u.Path = path + "api/send"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
