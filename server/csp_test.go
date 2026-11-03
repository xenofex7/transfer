package server

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dutchcoders/transfer.sh/web"
)

func TestSecurityHeadersSetHSTSAndCSP(t *testing.T) {
	rec := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HSTS = %q", got)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "style-src 'self'", "frame-ancestors 'self'", "base-uri 'self'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q misses %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP allows unsafe sources: %q", csp)
	}
}

func TestCSPAllowsThemeBootstrapByHash(t *testing.T) {
	rendered := string(themeBootstrap())
	body := strings.TrimSuffix(strings.TrimPrefix(rendered, "<script>"), "</script>")
	sum := sha256.Sum256([]byte(body))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(contentSecurityPolicy(), "script-src 'self' "+want) {
		t.Errorf("CSP %q does not allow the rendered bootstrap %q", contentSecurityPolicy(), want)
	}
}

func TestCSPAllowsConfiguredUmamiOrigin(t *testing.T) {
	t.Cleanup(func() { activeUmami.Store(nil) })
	if strings.Contains(contentSecurityPolicy(), "umami") {
		t.Fatal("CSP names an Umami origin without tracking configured")
	}
	(&umamiConfig{scriptURL: "https://umami.example.com/script.js", websiteID: "abc"}).install()
	csp := contentSecurityPolicy()
	for _, want := range []string{"script-src 'self' " + themeBootstrapHash + " https://umami.example.com;", "connect-src 'self' https://umami.example.com;"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q misses %q", csp, want)
		}
	}
}

func TestTemplatesHaveNoInlineScriptsOrStyles(t *testing.T) {
	entries, err := fs.ReadDir(web.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		data, err := fs.ReadFile(web.FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		html := string(data)
		for _, bad := range []string{"<script>", "<style", ` style="`, ` onclick=`, ` onload=`} {
			if strings.Contains(html, bad) {
				t.Errorf("%s contains %q, which the CSP blocks", e.Name(), bad)
			}
		}
	}
}

func TestCSPAllowsNonHTTPSUmamiOrigins(t *testing.T) {
	t.Cleanup(func() { activeUmami.Store(nil) })
	for script, origin := range map[string]string{
		"http://umami.lan:3000/script.js": "http://umami.lan:3000",
		"//umami.example.com/script.js":   "umami.example.com",
	} {
		(&umamiConfig{scriptURL: script, websiteID: "abc"}).install()
		if csp := contentSecurityPolicy(); !strings.Contains(csp, " "+origin+"; style-src") || !strings.Contains(csp, "connect-src 'self' "+origin+";") {
			t.Errorf("%s: CSP %q does not allow %q", script, csp, origin)
		}
	}
}
