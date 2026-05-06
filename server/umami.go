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

// activeUmami carries the operator-configured tracker config to the
// template helpers. nil disables tracking entirely.
var activeUmami atomic.Pointer[umamiConfig]

type umamiConfig struct {
	scriptURL string
	websiteID string
}

// install publishes the config so the template func can read it without
// holding a per-request reference to the Server.
func (u *umamiConfig) install() {
	if u == nil || u.scriptURL == "" || u.websiteID == "" {
		activeUmami.Store(nil)
		return
	}
	activeUmami.Store(u)
}

// umamiScript returns the script tag for the Umami tracker, or an empty
// string when tracking is not configured. Used by user-facing templates;
// admin pages must omit the call.
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

// startUmamiHeartbeat fires one immediate beat and then one every 24
// hours until ctx is cancelled. Each beat is a POST to Umami's
// `/api/send` so the operator can count live forks at a glance.
func (s *Server) startUmamiHeartbeat(ctx context.Context) {
	if !s.umamiHeartbeat || s.umamiScriptURL == "" || s.umamiWebsiteID == "" {
		return
	}
	endpoint, err := umamiSendEndpoint(s.umamiScriptURL)
	if err != nil {
		s.logger.Printf("umami: heartbeat disabled, cannot derive send endpoint: %v", err)
		return
	}

	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		// Stagger the first beat so the container has time to wire up its
		// reverse proxy and avoids racing the listener readiness probe.
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		s.sendUmamiHeartbeat(ctx, client, endpoint)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sendUmamiHeartbeat(ctx, client, endpoint)
			}
		}
	}()
}

func (s *Server) sendUmamiHeartbeat(ctx context.Context, client *http.Client, endpoint string) {
	payload := map[string]any{
		"type": "event",
		"payload": map[string]any{
			"website":  s.umamiWebsiteID,
			"hostname": "transfer",
			"language": "en",
			"url":      "/heartbeat",
			"name":     "server-heartbeat",
			"data": map[string]any{
				"version": BuildVersion,
			},
		},
	}
	body, err := json.Marshal(payload)
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
