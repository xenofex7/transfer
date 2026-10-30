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
// client's real IP. A RemoteAddr in one of these is treated as the upstream
// proxy, and when an X-Forwarded-For chain is present we want the right-most
// non-private hop in it.
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

// realIPFromRequest returns the client's IP address. Forwarded headers are
// only honored when RemoteAddr is a private or loopback address (the reverse
// proxy); then it prefers the right-most non-private hop from
// X-Forwarded-For, falls back to X-Real-Ip, and finally to RemoteAddr
// (without the port).
func realIPFromRequest(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	if ip := net.ParseIP(remote); ip == nil || !isPrivateIP(ip) {
		return remote
	}

	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr := strings.TrimSpace(hops[i])
		if ip := net.ParseIP(addr); ip != nil && !isPrivateIP(ip) {
			return addr
		}
	}

	if real := r.Header.Get("X-Real-Ip"); real != "" {
		return real
	}

	return remote
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range realIPPrivateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
