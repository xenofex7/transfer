/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"net"
	"net/http"
	"strings"
)

// realIPPrivateBlocks lists CIDR ranges that should not be returned as the
// client's real IP. The upstream proxy will appear in one of these (or in
// X-Real-Ip), and when an X-Forwarded-For chain is present we want the
// first non-private hop in it.
var realIPPrivateBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // localhost
		"10.0.0.0/8",     // RFC 1918 24-bit block
		"172.16.0.0/12",  // RFC 1918 20-bit block
		"192.168.0.0/16", // RFC 1918 16-bit block
		"169.254.0.0/16", // link-local
		"::1/128",        // IPv6 localhost
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	} {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			realIPPrivateBlocks = append(realIPPrivateBlocks, n)
		}
	}
}

// realIPFromRequest returns the client's IP address. It prefers the first
// non-private hop from X-Forwarded-For, falls back to X-Real-Ip, and finally
// to the request's RemoteAddr (without the port).
func realIPFromRequest(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	for _, addr := range strings.Split(xff, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if ip := net.ParseIP(addr); ip != nil && !isPrivateIP(ip) {
			return addr
		}
	}

	if real := r.Header.Get("X-Real-Ip"); real != "" {
		return real
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range realIPPrivateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
