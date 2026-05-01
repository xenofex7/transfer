// Package web embeds the static front-end assets shipped with transfer.sh.
//
// The bundled HTML templates, CSS, JavaScript and images live under public/
// and are exposed as a single fs.FS rooted at that directory. The Go server
// reads templates and serves static files straight from this embedded
// filesystem, so the binary is self-contained.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
)

//go:embed all:public
var content embed.FS

// FS exposes the public/ directory as a flat filesystem (paths do not include
// the "public/" prefix).
var FS fs.FS

// Version is a short fingerprint of the embedded assets. It changes whenever
// any file under public/ changes and is intended to be appended to static
// asset URLs as a cache-busting query parameter.
var Version string

func init() {
	sub, err := fs.Sub(content, "public")
	if err != nil {
		panic(err)
	}
	FS = sub
	Version = computeVersion()
}

func computeVersion() string {
	h := sha256.New()
	_ = fs.WalkDir(FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, readErr := fs.ReadFile(FS, path)
		if readErr != nil {
			return readErr
		}
		_, _ = h.Write([]byte(path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}
