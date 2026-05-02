/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"
)

// panicRecover wraps a handler so that a panic in the request handler is
// turned into a 500 response rather than crashing the entire server.
func panicRecover(logger *log.Logger, h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if logger != nil {
					logger.Printf("panic: %v\n%s", rec, debug.Stack())
				}
				http.Error(w, fmt.Sprintf("%s", rec), http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	}
}

// statusRecorder remembers the status code and the number of bytes written so
// that accessLog can include them after the inner handler returns.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// accessLog writes one log line per request in a format close to Apache's
// combined log format, the same one the original PuerkitoBio/ghost
// LogHandler used.
func accessLog(logger *log.Logger, h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		h.ServeHTTP(rec, r)

		contentLength := ""
		if cl := rec.Header().Get("Content-Length"); cl != "" {
			contentLength = cl
		} else if rec.bytes > 0 {
			contentLength = fmt.Sprintf("%d", rec.bytes)
		}

		logger.Printf(
			`%s - - [%s] "%s %s %s" %d %s "%s" "%s"`,
			r.RemoteAddr,
			start.Format(time.RFC3339),
			r.Method,
			r.RequestURI,
			r.Proto,
			rec.status,
			contentLength,
			r.Referer(),
			r.UserAgent(),
		)
	}
}
