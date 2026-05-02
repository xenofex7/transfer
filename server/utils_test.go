package server

import (
	"net/http"
	"testing"
)

func TestAcceptsHTML(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"absent", "", false},
		{"plain text/html", "text/html", true},
		{"text/html with quality", "text/html;q=0.9", true},
		{"browser-style chain", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", true},
		{"json only", "application/json", false},
		{"plain text", "text/plain", false},
		{"wildcard only", "*/*", false},
		{"text/html with leading whitespace", "  text/html  ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.header != "" {
				h.Set("Accept", tc.header)
			}
			if got := acceptsHTML(h); got != tc.want {
				t.Errorf("acceptsHTML(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
