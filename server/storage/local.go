package storage

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LocalStorage is a local storage
type LocalStorage struct {
	Storage
	basedir string
	logger  *log.Logger
}

// NewLocalStorage is the factory for LocalStorage
func NewLocalStorage(basedir string, logger *log.Logger) (*LocalStorage, error) {
	return &LocalStorage{basedir: basedir, logger: logger}, nil
}

// Type returns the storage type
func (s *LocalStorage) Type() string {
	return "local"
}

// Head retrieves content length of a file from storage
func (s *LocalStorage) Head(_ context.Context, token string, filename string) (contentLength uint64, err error) {
	path := filepath.Join(s.basedir, token, filename)

	var fi os.FileInfo
	if fi, err = os.Lstat(path); err != nil {
		return
	}

	contentLength = uint64(fi.Size())

	return
}

// Get retrieves a file from storage
func (s *LocalStorage) Get(_ context.Context, token string, filename string, rng *Range) (reader io.ReadCloser, contentLength uint64, err error) {
	path := filepath.Join(s.basedir, token, filename)

	var file *os.File

	// content type , content length
	if file, err = os.Open(path); err != nil {
		return
	}
	reader = file

	var fi os.FileInfo
	if fi, err = os.Lstat(path); err != nil {
		return
	}

	contentLength = uint64(fi.Size())
	if rng != nil {
		contentLength = rng.AcceptLength(contentLength)
		if _, err = file.Seek(int64(rng.Start), 0); err != nil {
			return
		}
	}

	return
}

// Delete removes a file from storage
func (s *LocalStorage) Delete(_ context.Context, token string, filename string) (err error) {
	metadata := filepath.Join(s.basedir, token, fmt.Sprintf("%s.metadata", filename))
	_ = os.Remove(metadata)

	path := filepath.Join(s.basedir, token, filename)
	err = os.Remove(path)
	return
}

// Purge cleans up the storage
func (s *LocalStorage) Purge(_ context.Context, days time.Duration) (err error) {
	err = filepath.Walk(s.basedir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			if info.ModTime().Before(time.Now().Add(-1 * days)) {
				err = os.Remove(path)
				return err
			}

			return nil
		})

	return
}

// IsNotExist indicates if a file doesn't exist on storage
func (s *LocalStorage) IsNotExist(err error) bool {
	if err == nil {
		return false
	}

	return os.IsNotExist(err)
}

// Put saves a file on storage
func (s *LocalStorage) Put(_ context.Context, token string, filename string, reader io.Reader, contentType string, contentLength uint64) error {
	var f io.WriteCloser
	var err error

	path := filepath.Join(s.basedir, token)

	if err = os.MkdirAll(path, 0700); err != nil && !os.IsExist(err) {
		return err
	}

	f, err = os.OpenFile(filepath.Join(path, filename), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer CloseCheck(f)

	if err != nil {
		return err
	}

	if _, err = io.Copy(f, reader); err != nil {
		return err
	}

	return nil
}

func (s *LocalStorage) IsRangeSupported() bool { return true }

// List walks basedir and returns one entry per uploaded file (skipping the
// adjacent .metadata files). The metadata blob is included verbatim; caller
// decodes it into whatever shape it needs.
func (s *LocalStorage) List(_ context.Context) ([]ListEntry, error) {
	entries := make([]ListEntry, 0, 64)

	tokenDirs, err := os.ReadDir(s.basedir)
	if err != nil {
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, err
	}

	for _, d := range tokenDirs {
		if !d.IsDir() {
			continue
		}
		token := d.Name()
		tokenPath := filepath.Join(s.basedir, token)

		files, ferr := os.ReadDir(tokenPath)
		if ferr != nil {
			s.logger.Printf("list: skipping %s: %v", tokenPath, ferr)
			continue
		}

		for _, f := range files {
			name := f.Name()
			if f.IsDir() || strings.HasSuffix(name, ".metadata") {
				continue
			}
			info, infoErr := f.Info()
			if infoErr != nil {
				continue
			}

			// Best-effort metadata read; missing metadata is fine.
			var meta []byte
			if b, mErr := os.ReadFile(filepath.Join(tokenPath, name+".metadata")); mErr == nil {
				meta = b
			}

			entries = append(entries, ListEntry{
				Token:      token,
				Filename:   name,
				Size:       info.Size(),
				UploadedAt: info.ModTime(),
				Metadata:   meta,
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].UploadedAt.After(entries[j].UploadedAt)
	})
	return entries, nil
}
