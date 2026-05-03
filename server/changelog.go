/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"encoding/json"
	"net/http"
	"sync"

	blackfriday "github.com/russross/blackfriday/v2"
	"github.com/microcosm-cc/bluemonday"
)

// Changelog is the embedded CHANGELOG.md, set by main at startup. The
// changelog handler renders it once and caches the HTML for subsequent
// requests so we are not re-running blackfriday on every page load.
var Changelog []byte

var (
	changelogOnce sync.Once
	changelogHTML []byte
	changelogErr  error
)

func renderChangelog() ([]byte, error) {
	changelogOnce.Do(func() {
		if len(Changelog) == 0 {
			changelogHTML = []byte("")
			return
		}
		unsafe := blackfriday.Run(Changelog)
		changelogHTML = bluemonday.UGCPolicy().SanitizeBytes(unsafe)
	})
	return changelogHTML, changelogErr
}

// changelogHandler returns the rendered + sanitized changelog as JSON so
// the client-side modal can drop it into the DOM as innerHTML.
func (s *Server) changelogHandler(w http.ResponseWriter, _ *http.Request) {
	body, err := renderChangelog()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(body) == 0 {
		http.Error(w, "changelog not embedded", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"version": BuildVersion,
		"html":    string(body),
	})
}
