/*
The MIT License (MIT)

Copyright (c) 2026 xenofex7
*/

package server

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dutchcoders/transfer.sh/web"
)

// BrandingSlot identifies a customisable image asset.
type BrandingSlot string

const (
	BrandingLogo    BrandingSlot = "logo"
	BrandingFavicon BrandingSlot = "favicon"
)

// allowedBrandingExt maps slot to the file extensions accepted on upload.
// Anything outside this map is rejected to keep the served content-type
// predictable.
var allowedBrandingExt = map[BrandingSlot]map[string]string{
	BrandingLogo: {
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".svg":  "image/svg+xml",
		".webp": "image/webp",
		".gif":  "image/gif",
	},
	BrandingFavicon: {
		".ico": "image/x-icon",
		".png": "image/png",
		".svg": "image/svg+xml",
	},
}

// MaxBrandingBytes caps any single uploaded asset.
const MaxBrandingBytes = 1 * 1024 * 1024 // 1 MiB

// brandingFile is the cached state for one slot.
type brandingFile struct {
	exists      bool
	path        string
	contentType string
	mtime       time.Time
}

// brandingStore manages the per-slot custom files in basedir/.branding/.
type brandingStore struct {
	dir string

	mu      sync.RWMutex
	logo    brandingFile
	favicon brandingFile
}

// activeBranding is the package-level handle the template functions read.
// Each Server.New installation writes a fresh store here. Tests that build
// a Server replace it; production runs single-instance so no contention.
var activeBranding atomic.Pointer[brandingStore]

func newBrandingStore(dir string) (*brandingStore, error) {
	b := &brandingStore{dir: dir}
	if dir == "" {
		return b, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	b.refresh()
	return b, nil
}

// refresh rescans the branding dir for the current state of each slot.
func (b *brandingStore) refresh() {
	if b == nil || b.dir == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.logo = scanSlot(b.dir, BrandingLogo)
	b.favicon = scanSlot(b.dir, BrandingFavicon)
}

func scanSlot(dir string, slot BrandingSlot) brandingFile {
	for ext, ct := range allowedBrandingExt[slot] {
		path := filepath.Join(dir, string(slot)+ext)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return brandingFile{exists: true, path: path, contentType: ct, mtime: info.ModTime()}
		}
	}
	return brandingFile{}
}

// Get returns the cached state for a slot.
func (b *brandingStore) Get(slot BrandingSlot) brandingFile {
	if b == nil {
		return brandingFile{}
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	switch slot {
	case BrandingLogo:
		return b.logo
	case BrandingFavicon:
		return b.favicon
	}
	return brandingFile{}
}

// LogoURL returns the URL the homepage should link to for the logo. Custom
// uploads take precedence and carry a mtime-based cache-bust query so a
// fresh upload is picked up immediately.
func (b *brandingStore) LogoURL() string {
	if f := b.Get(BrandingLogo); f.exists {
		return "/branding/logo?v=" + strconv.FormatInt(f.mtime.Unix(), 10)
	}
	return "/images/logo.png?v=" + web.Version
}

// FaviconURL returns the URL for the <link rel="icon"> tag.
func (b *brandingStore) FaviconURL() string {
	if f := b.Get(BrandingFavicon); f.exists {
		return "/branding/favicon?v=" + strconv.FormatInt(f.mtime.Unix(), 10)
	}
	return "/favicon.ico?v=" + web.Version
}

// Save writes a new file for slot. ext is taken verbatim from the upload's
// filename or content-type and must be in allowedBrandingExt[slot] or the
// call returns an error. Any previous file for the slot (regardless of
// extension) is removed first.
func (b *brandingStore) Save(slot BrandingSlot, ext string, src io.Reader) error {
	if b == nil || b.dir == "" {
		return errors.New("branding store not configured")
	}
	ext = strings.ToLower(ext)
	allowed, ok := allowedBrandingExt[slot]
	if !ok {
		return errors.New("unknown branding slot")
	}
	contentType, ok := allowed[ext]
	if !ok {
		return errors.New("unsupported file extension for " + string(slot))
	}

	if err := os.MkdirAll(b.dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(b.dir, ".upload-*"+ext)
	if err != nil {
		return err
	}
	written, err := io.Copy(tmp, io.LimitReader(src, MaxBrandingBytes+1))
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if written > MaxBrandingBytes {
		_ = os.Remove(tmp.Name())
		return errors.New("file too large; max 1 MiB")
	}

	// Drop any previous slot file (different ext) before installing the new one.
	for prevExt := range allowed {
		_ = os.Remove(filepath.Join(b.dir, string(slot)+prevExt))
	}
	dest := filepath.Join(b.dir, string(slot)+ext)
	if err := os.Rename(tmp.Name(), dest); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	_ = os.Chmod(dest, 0o644)
	_ = contentType // currently unused beyond validation
	b.refresh()
	return nil
}

// Delete removes any custom file for slot, restoring the embedded fallback.
func (b *brandingStore) Delete(slot BrandingSlot) error {
	if b == nil || b.dir == "" {
		return nil
	}
	allowed, ok := allowedBrandingExt[slot]
	if !ok {
		return errors.New("unknown branding slot")
	}
	for ext := range allowed {
		_ = os.Remove(filepath.Join(b.dir, string(slot)+ext))
	}
	b.refresh()
	return nil
}

// brandingHandler serves the custom asset for one slot, 404ing when the
// admin has not uploaded one. The fallback to the embedded asset is done
// at template-URL time, not here.
func (s *Server) brandingHandler(slot BrandingSlot) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.branding == nil {
			http.NotFound(w, r)
			return
		}
		f := s.branding.Get(slot)
		if !f.exists {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", f.contentType)
		// Long cache - the URL itself carries the mtime so a new upload
		// invalidates the cache via a different query string.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeFile(w, r, f.path)
	}
}
