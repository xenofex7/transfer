// Package web embeds the static front-end assets shipped with transfer.sh.
//
// The bundled HTML templates, CSS, JavaScript and images live under public/
// and are exposed as a single fs.FS rooted at that directory. The Go server
// reads templates and serves static files straight from this embedded
// filesystem, so the binary is self-contained.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:public
var content embed.FS

// FS exposes the public/ directory as a flat filesystem (paths do not include
// the "public/" prefix).
var FS fs.FS

func init() {
	sub, err := fs.Sub(content, "public")
	if err != nil {
		panic(err)
	}
	FS = sub
}
