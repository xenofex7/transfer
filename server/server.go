/*
The MIT License (MIT)

Copyright (c) 2014-2017 DutchCoders [https://github.com/dutchcoders/]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package server

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	iofs "io/fs"
	"log"
	"math/rand"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	gorillaHandlers "github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/tg123/go-htpasswd"

	"github.com/dutchcoders/transfer.sh/server/storage"
	"github.com/dutchcoders/transfer.sh/web"
)

// parse request with maximum memory of _24Kilobits
const _24K = (1 << 3) * 24

// parse request with maximum memory of _5Megabytes
const _5M = (1 << 20) * 5

// OptionFn is the option function type
type OptionFn func(*Server)

// ClamavHost sets clamav host
func ClamavHost(s string) OptionFn {
	return func(srvr *Server) {
		srvr.ClamAVDaemonHost = s
	}
}

// PerformClamavPrescan enables clamav prescan on upload
func PerformClamavPrescan(b bool) OptionFn {
	return func(srvr *Server) {
		srvr.performClamavPrescan = b
	}
}

// ClamavScanTimeout sets the per-stream scan timeout in seconds.
// Values <= 0 are ignored and the built-in default is kept.
func ClamavScanTimeout(seconds int) OptionFn {
	return func(srvr *Server) {
		if seconds > 0 {
			srvr.clamavScanTimeout = time.Duration(seconds) * time.Second
		}
	}
}

// Listener set listener
func Listener(s string) OptionFn {
	return func(srvr *Server) {
		srvr.ListenerString = s
	}

}

// CorsDomains sets CORS domains
func CorsDomains(s string) OptionFn {
	return func(srvr *Server) {
		srvr.CorsDomains = s
	}

}

// EmailContact sets email contact
func EmailContact(emailContact string) OptionFn {
	return func(srvr *Server) {
		srvr.emailContact = emailContact
	}
}

// Tagline sets the bootstrap homepage tagline. The actual tagline served at
// runtime can be overridden via the admin settings panel and persisted to
// the settings file in basedir.
func Tagline(s string) OptionFn {
	return func(srvr *Server) {
		srvr.tagline = s
	}
}

// SettingsPath wires the runtime-mutable settings store. Pass an empty path
// to keep the store in memory only (admin edits won't survive a restart).
func SettingsPath(path string) OptionFn {
	return func(srvr *Server) {
		srvr.settingsPath = path
	}
}

// BrandingDir is the directory that holds operator-uploaded branding assets
// (logo, favicon). Empty disables custom branding (admin upload UI shows
// nothing to do).
func BrandingDir(dir string) OptionFn {
	return func(srvr *Server) {
		srvr.brandingDir = dir
	}
}

// WebPath sets web path
func WebPath(s string) OptionFn {
	return func(srvr *Server) {
		if s[len(s)-1:] != "/" {
			s = filepath.Join(s, "")
		}

		srvr.webPath = s
	}
}

// ProxyPath sets proxy path
func ProxyPath(s string) OptionFn {
	return func(srvr *Server) {
		if s[len(s)-1:] != "/" {
			s = filepath.Join(s, "")
		}

		srvr.proxyPath = s
	}
}

// ProxyPort sets proxy port
func ProxyPort(s string) OptionFn {
	return func(srvr *Server) {
		srvr.proxyPort = s
	}
}

// TempPath sets temp path
func TempPath(s string) OptionFn {
	return func(srvr *Server) {
		if s[len(s)-1:] != "/" {
			s = filepath.Join(s, "")
		}

		srvr.tempPath = s
	}
}

// LogFile sets log file
func LogFile(logger *log.Logger, s string) OptionFn {
	return func(srvr *Server) {
		f, err := os.OpenFile(s, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			logger.Fatalf("error opening file: %v", err)
		}

		logger.SetOutput(f)
		srvr.logger = logger
	}
}

// Logger sets logger
func Logger(logger *log.Logger) OptionFn {
	return func(srvr *Server) {
		srvr.logger = logger
	}
}

// MaxUploadSize sets max upload size
func MaxUploadSize(kbytes int64) OptionFn {
	return func(srvr *Server) {
		srvr.maxUploadSize = kbytes * 1024
	}

}

// RateLimit set rate limit
func RateLimit(requests int) OptionFn {
	return func(srvr *Server) {
		srvr.rateLimitRequests = requests
	}
}

// RandomTokenLength sets random token length
func RandomTokenLength(length int) OptionFn {
	return func(srvr *Server) {
		srvr.randomTokenLength = length
	}
}

// Purge sets purge days and option
func Purge(days, interval int) OptionFn {
	return func(srvr *Server) {
		srvr.purgeDays = time.Duration(days) * time.Hour * 24
		srvr.purgeInterval = time.Duration(interval) * time.Hour
	}
}

// UseStorage set storage to use
func UseStorage(s storage.Storage) OptionFn {
	return func(srvr *Server) {
		srvr.storage = s
	}
}

// HTTPAuthCredentials sets basic http auth credentials
func HTTPAuthCredentials(user string, pass string) OptionFn {
	return func(srvr *Server) {
		srvr.authUser = user
		srvr.authPass = pass
	}
}

// HTTPAuthHtpasswd sets basic http auth htpasswd file
func HTTPAuthHtpasswd(htpasswdPath string) OptionFn {
	return func(srvr *Server) {
		srvr.authHtpasswd = htpasswdPath
	}
}

// HTTPAUTHFilterOptions sets basic http auth ips whitelist
func HTTPAUTHFilterOptions(options IPFilterOptions) OptionFn {
	for i, allowedIP := range options.AllowedIPs {
		options.AllowedIPs[i] = strings.TrimSpace(allowedIP)
	}

	return func(srvr *Server) {
		srvr.authIPFilterOptions = &options
	}
}

// FilterOptions sets ip filtering
func FilterOptions(options IPFilterOptions) OptionFn {
	for i, allowedIP := range options.AllowedIPs {
		options.AllowedIPs[i] = strings.TrimSpace(allowedIP)
	}

	for i, blockedIP := range options.BlockedIPs {
		options.BlockedIPs[i] = strings.TrimSpace(blockedIP)
	}

	return func(srvr *Server) {
		srvr.ipFilterOptions = &options
	}
}

// Server is the main application
type Server struct {
	authUser            string
	authPass            string
	authHtpasswd        string
	authIPFilterOptions *IPFilterOptions

	htpasswdFile *htpasswd.File
	authIPFilter *ipFilter

	logger *log.Logger

	locks sync.Map

	maxUploadSize     int64
	rateLimitRequests int

	purgeDays     time.Duration
	purgeInterval time.Duration

	storage storage.Storage

	randomTokenLength int

	ipFilterOptions *IPFilterOptions

	ClamAVDaemonHost     string
	performClamavPrescan bool
	clamavScanTimeout    time.Duration

	tempPath string

	webPath      string
	proxyPath    string
	proxyPort    string
	emailContact string
	tagline      string
	settings     *settingsStore
	settingsPath string
	branding     *brandingStore
	brandingDir  string

	uploadWebhookURL string
	webhookToken     string

	deletions *deletionLog

	CorsDomains    string
	ListenerString string
}

// UseDeletionLog wires a basedir-scoped append-only deletions log. Pass an
// empty string to disable.
func UseDeletionLog(path string) OptionFn {
	return func(srvr *Server) {
		if path == "" {
			srvr.deletions = nil
			return
		}
		srvr.deletions = newDeletionLog(path)
	}
}

// UploadWebhookURL configures a URL that receives JSON POSTs for upload,
// download and delete events. Empty disables the webhook.
func UploadWebhookURL(s string) OptionFn {
	return func(srvr *Server) {
		srvr.uploadWebhookURL = s
	}
}

// WebhookToken sets a bearer token sent as Authorization on every webhook
// POST. Empty disables the header.
func WebhookToken(s string) OptionFn {
	return func(srvr *Server) {
		srvr.webhookToken = s
	}
}

// New is the factory fot Server
func New(options ...OptionFn) (*Server, error) {
	s := &Server{
		locks:             sync.Map{},
		clamavScanTimeout: 60 * time.Second,
		tagline:           DefaultTagline,
	}

	for _, optionFn := range options {
		optionFn(s)
	}

	store, err := newSettingsStore(s.settingsPath, Settings{
		Tagline:      s.tagline,
		EmailContact: s.emailContact,
	})
	if err != nil {
		return nil, err
	}
	s.settings = store

	branding, err := newBrandingStore(s.brandingDir)
	if err != nil {
		return nil, err
	}
	s.branding = branding
	activeBranding.Store(branding)

	return s, nil
}

var theRand *rand.Rand

func init() {
	var seedBytes [8]byte
	if _, err := cryptoRand.Read(seedBytes[:]); err != nil {
		panic("cannot obtain cryptographically secure seed")
	}

	theRand = rand.New(rand.NewSource(int64(binary.LittleEndian.Uint64(seedBytes[:]))))
}

var loadEmbeddedTemplatesOnce sync.Once

// loadEmbeddedTemplates walks the bundled web/public filesystem once and
// parses every *.html and *.txt file into the package-level template trees.
// html/template trees mutate during the first execution (escaping is
// applied once), so re-parsing later would corrupt the parsed state.
func loadEmbeddedTemplates(logger *log.Logger) {
	loadEmbeddedTemplatesOnce.Do(func() {
		err := iofs.WalkDir(web.FS, ".", func(p string, d iofs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			body, readErr := iofs.ReadFile(web.FS, p)
			if readErr != nil {
				return readErr
			}
			if strings.HasSuffix(p, ".html") {
				if _, e := htmlTemplates.New(p).Parse(string(body)); e != nil && logger != nil {
					logger.Println("Unable to parse html template", e)
				}
			}
			if strings.HasSuffix(p, ".txt") {
				if _, e := textTemplates.New(p).Parse(string(body)); e != nil && logger != nil {
					logger.Println("Unable to parse text template", e)
				}
			}
			return nil
		})
		if err != nil && logger != nil {
			logger.Printf("Unable to walk embedded web assets: %s", err)
		}
	})
}

// Run starts Server
func (s *Server) Run() {
	listening := false

	r := mux.NewRouter()

	var fileSys http.FileSystem

	if s.webPath != "" {
		s.logger.Println("Using static file path: ", s.webPath)

		fileSys = http.Dir(s.webPath)

		htmlTemplates, _ = htmlTemplates.ParseGlob(filepath.Join(s.webPath, "*.html"))
		textTemplates, _ = textTemplates.ParseGlob(filepath.Join(s.webPath, "*.txt"))
	} else {
		fileSys = http.FS(web.FS)
		loadEmbeddedTemplates(s.logger)
	}

	staticHandler := http.FileServer(fileSys)

	// Long-lived cache for fingerprinted asset bundles. The HTML templates
	// append a content hash via {{asset ...}} so cache invalidation is
	// transparent across releases. Robots/favicon are linked without a
	// cache-buster, so use a shorter max-age there.
	cachedAssets := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		staticHandler.ServeHTTP(w, r)
	})
	cachedShort := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		staticHandler.ServeHTTP(w, r)
	})

	r.PathPrefix("/images/").Handler(cachedAssets).Methods("GET")
	r.PathPrefix("/styles/").Handler(cachedAssets).Methods("GET")
	r.PathPrefix("/scripts/").Handler(cachedAssets).Methods("GET")
	r.PathPrefix("/fonts/").Handler(cachedAssets).Methods("GET")
	r.PathPrefix("/ico/").Handler(cachedShort).Methods("GET")
	r.HandleFunc("/favicon.ico", cachedShort.ServeHTTP).Methods("GET")
	r.HandleFunc("/robots.txt", cachedShort.ServeHTTP).Methods("GET")
	r.HandleFunc("/llms.txt", cachedShort.ServeHTTP).Methods("GET")

	r.HandleFunc("/{filename:(?:favicon\\.ico|robots\\.txt|health\\.html)}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")

	r.HandleFunc("/health.html", healthHandler).Methods("GET")
	r.Handle("/admin/files", s.basicAuthHandler(http.HandlerFunc(s.adminFilesHandler))).Methods("GET")
	r.Handle("/admin/settings", s.basicAuthHandler(http.HandlerFunc(s.adminSettingsGetHandler))).Methods("GET")
	r.Handle("/admin/settings", s.basicAuthHandler(http.HandlerFunc(s.adminSettingsPostHandler))).Methods("POST")
	r.Handle("/admin/branding/{slot:logo|favicon}", s.basicAuthHandler(http.HandlerFunc(s.adminBrandingUploadHandler))).Methods("POST")
	r.Handle("/admin/branding/{slot:logo|favicon}", s.basicAuthHandler(http.HandlerFunc(s.adminBrandingDeleteHandler))).Methods("DELETE")
	r.Handle("/branding/logo", s.brandingHandler(BrandingLogo)).Methods("GET")
	r.Handle("/branding/favicon", s.brandingHandler(BrandingFavicon)).Methods("GET")
	r.HandleFunc("/", s.viewHandler).Methods("GET")

	r.HandleFunc("/({files:.*}).zip", s.zipHandler).Methods("GET")
	r.HandleFunc("/({files:.*}).tar", s.tarHandler).Methods("GET")
	r.HandleFunc("/({files:.*}).tar.gz", s.tarGzHandler).Methods("GET")

	r.HandleFunc("/{token}/{filename}", s.headHandler).Methods("HEAD")
	r.HandleFunc("/{action:(?:download|get|inline)}/{token}/{filename}", s.headHandler).Methods("HEAD")

	r.HandleFunc("/{token}/{filename}", s.previewHandler).MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) (match bool) {
		// The file will show a preview page when opening the link in browser directly or
		// from external link. If the referer url path and current path are the same it will be
		// downloaded.
		if !acceptsHTML(r.Header) {
			return false
		}

		match = r.Referer() == ""

		u, err := url.Parse(r.Referer())
		if err != nil {
			s.logger.Fatal(err)
			return
		}

		match = match || (u.Path != r.URL.Path)
		return
	}).Methods("GET")

	var getHandlerFn http.Handler = http.HandlerFunc(s.getHandler)
	if s.rateLimitRequests > 0 {
		getHandlerFn = newIPLimiter(s.rateLimitRequests).Wrap(getHandlerFn)
	}

	r.Handle("/{token}/{filename}", getHandlerFn).Methods("GET")
	r.Handle("/{action:(?:download|get|inline)}/{token}/{filename}", getHandlerFn).Methods("GET")

	r.HandleFunc("/{filename}/scan", s.scanHandler).Methods("PUT")
	r.HandleFunc("/put/{filename}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")
	r.HandleFunc("/upload/{filename}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")
	r.HandleFunc("/{filename}", s.basicAuthHandler(http.HandlerFunc(s.putHandler))).Methods("PUT")
	r.HandleFunc("/", s.basicAuthHandler(http.HandlerFunc(s.postHandler))).Methods("POST")
	// r.HandleFunc("/{page}", viewHandler).Methods("GET")

	r.HandleFunc("/{token}/{filename}/{deletionToken}", s.deleteHandler).Methods("DELETE")

	r.NotFoundHandler = http.HandlerFunc(s.notFoundHandler)

	_ = mime.AddExtensionType(".md", "text/x-markdown")

	if s.tempPath != "" {
		if err := os.MkdirAll(s.tempPath, 0o755); err != nil {
			s.logger.Fatalf("could not create temp folder %s: %v", s.tempPath, err)
		}
	}

	s.logger.Printf("Transfer.sh server started.\nusing temp folder: %s\nusing storage provider: %s", s.tempPath, s.storage.Type())

	var cors func(http.Handler) http.Handler
	if len(s.CorsDomains) > 0 {
		cors = gorillaHandlers.CORS(
			gorillaHandlers.AllowedHeaders([]string{"*"}),
			gorillaHandlers.AllowedOrigins(strings.Split(s.CorsDomains, ",")),
			gorillaHandlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}),
		)
	} else {
		cors = func(h http.Handler) http.Handler {
			return h
		}
	}

	h := securityHeaders(
		panicRecover(s.logger,
			ipFilterHandler(
				accessLog(s.logger,
					LoveHandler(
						s.RedirectHandler(cors(r))),
				),
				s.ipFilterOptions,
			),
		),
	)

	listening = true
	s.logger.Printf("starting to listen on: %v\n", s.ListenerString)

	go func() {
		srvr := &http.Server{
			Addr:    s.ListenerString,
			Handler: h,
		}

		if err := srvr.ListenAndServe(); err != nil {
			s.logger.Fatal(err)
		}
	}()

	s.logger.Printf("---------------------------")

	if s.purgeDays > 0 {
		go s.purgeHandler()
	}

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt)
	signal.Notify(term, syscall.SIGTERM)

	if listening {
		<-term
	} else {
		s.logger.Printf("No listener active.")
	}

	s.logger.Printf("Server stopped.")
}
