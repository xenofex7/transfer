package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

var (
	_ = Suite(&suiteRedirectPassthrough{})
)

type suiteRedirectPassthrough struct {
	handler http.HandlerFunc
}

func (s *suiteRedirectPassthrough) SetUpTest(c *C) {
	srvr, err := New()
	c.Assert(err, IsNil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "Hello, client")
	})

	s.handler = srvr.RedirectHandler(handler)
}

func (s *suiteRedirectPassthrough) TestHTTP(c *C) {
	req := httptest.NewRequest("GET", "http://127.0.0.1/test", nil)

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
}

func (s *suiteRedirectPassthrough) TestHTTPs(c *C) {
	req := httptest.NewRequest("GET", "https://127.0.0.1/test", nil)

	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	c.Assert(resp.StatusCode, Equals, http.StatusOK)
}

func TestPreviewRequestedSurvivesMalformedReferer(t *testing.T) {
	cases := map[string]bool{
		"":                         true,
		"%zz":                      true,
		"http://[::1":              true,
		"https://other.example/x":  true,
		"https://host.example/a/b": false,
	}
	for referer, want := range cases {
		req := httptest.NewRequest("GET", "https://host.example/a/b", nil)
		req.Header.Set("Accept", "text/html")
		if referer != "" {
			req.Header.Set("Referer", referer)
		}
		if got := previewRequested(req, nil); got != want {
			t.Errorf("previewRequested(referer=%q) = %v, want %v", referer, got, want)
		}
	}
}
