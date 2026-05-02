# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.4] - 2026-05-02

### Added
- Upload webhook to notify external services on new uploads
- Token-bucket `ipLimiter` replacing the third-party `VojtechVitek/ratelimit` middleware

### Changed
- Replaced third-party middleware dependencies with in-tree implementations
- Bumped `cloudflare/circl` and `golang.org/x/net` to patch govulncheck CVEs
- Bumped govulncheck CI job to Go 1.25

### Removed
- `flake.nix` and `flake.lock` Nix flake files

## [1.0.3] - 2026-05-01

### Added
- Table of contents in README for easier navigation
- `SECURITY.md` with vulnerability disclosure policy and `llms.txt` for LLM crawlers
- govulncheck job in CI to scan dependencies for known vulnerabilities
- Security headers (CSP, X-Frame-Options, Referrer-Policy) and cache-control headers on responses
- `noindex` meta tag to prevent search engine indexing of the web UI

### Changed
- Improved accessibility with `focus-visible` outlines and `prefers-reduced-motion` support

### Removed
- `extras/` directory dropped as part of repository cleanup

### Fixed
- Critical findings from the project audit addressed

## [1.0.2] - 2026-05-01

### Added
- Deploy script and `/deploy` command for releasing new versions
- CHANGELOG file to track project history

### Changed
- Embedded CSS and JS assets are now cache-busted via content hash

## [1.0.1] - 2026-05-01

### Added
- Embedded vanilla web frontend (HTML/CSS/JS) replacing the upstream
  Bootstrap/jQuery/Grunt stack; dark theme matching the project logo
- Project logo and favicon shipped under `assets/` and `web/public/`
- `scripts/deploy.sh` and `.claude/commands/deploy.md` for one-command
  releases (auto patch-bump, tests, changelog, tag, GitHub release)

### Changed
- Web assets are now embedded via Go 1.16 `embed.FS` (drops the
  `dutchcoders/transfer.sh-web` and `elazarl/go-bindata-assetfs`
  dependencies)
- Compose stack splits into an `internal` network and an external
  `proxy` network so it slots into an existing reverse-proxy stack
- Default container image is `ghcr.io/xenofex7/transfer.sh:latest`
- ClamAV connection prepends `tcp://` when the host has no scheme,
  and uploads are streamed via `INSTREAM` so clamd does not need
  filesystem access to the transfer.sh container
- Auto-create the temp folder on startup so any `TEMP_PATH` value
  works without pre-creating directories
- CI moved to Node.js 24 toolchain (`actions/checkout@v6`,
  `actions/setup-go@v6`, `golangci/golangci-lint-action@v9` with
  golangci-lint v2 config)
- README rewritten for the slim fork (633 -> 313 lines); examples.md
  trimmed and hostnames made generic
- Tightened `docker-compose.yml`: pinned ClamAV image, dropped fixed
  container names, switched to `mem_limit`, fail-fast bind mount for
  the htpasswd file, `no-new-privileges` on both services

### Fixed
- `errcheck` lint warning on the deferred `f.Close` in `performScan`
- Various `staticcheck` quickfixes (`fmt.Fprintf` instead of
  `Write([]byte(fmt.Sprintf...))`, `strings.ReplaceAll` instead of
  `strings.Replace(..., -1)`, redundant embedded-field selectors)

### Removed
- Upstream Code of Conduct (irrelevant for this fork)

## [1.0.0] - 2026-04-30

Initial release of the slim, self-hosted fork.

### Added
- Local filesystem storage backend (only)
- ClamAV pre-scan integration
- htpasswd basic auth
- IP whitelist / blacklist filtering
- Auto-purge with a default of 360 days and a 24 h sweep interval
- Multi-arch container image published to GHCR via GitHub Actions
  (linux/amd64 and linux/arm64) with semver, `latest`, `edge` and
  short-sha tags
- Project roadmap, deployment compose stack and `.env.example`

### Removed
- S3, Google Drive and Storj storage backends
- VirusTotal integration
- Built-in TLS / Let's Encrypt support (delegated to a reverse proxy)
- pprof profiler endpoint
- Google Analytics and UserVoice frontend keys
- Vagrantfile, Bower configuration, manifest.json
- Multi-OS binary release workflow (we ship containers only)

[Unreleased]: https://github.com/xenofex7/transfer.sh/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/xenofex7/transfer.sh/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/xenofex7/transfer.sh/releases/tag/v1.0.0
