<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/transfer_logo_dark.png">
    <img src="assets/transfer_logo.png" alt="transfer" width="360">
  </picture>
</p>

<h1 align="center">transfer</h1>

<p align="center">
  Self-hosted file transfer service: uploads via browser or <code>curl</code>, one-time secrets, htpasswd users with TOTP, admin UI.
</p>

<p align="center">
  <a href="https://github.com/xenofex7/transfer/tags"><img src="https://img.shields.io/github/v/tag/xenofex7/transfer?sort=semver&label=version" alt="latest tag"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/xenofex7/transfer" alt="license"></a>
  <img src="https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white" alt="go 1.26">
  <a href="https://github.com/xenofex7/transfer/pkgs/container/transfer"><img src="https://img.shields.io/badge/docker-ghcr.io-2496ed?logo=docker&logoColor=white" alt="container image"></a>
  <a href="https://github.com/xenofex7/transfer/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/xenofex7/transfer/test.yml?branch=main&label=tests" alt="tests"></a>
  <a href="https://github.com/xenofex7/transfer/actions/workflows/docker.yml"><img src="https://img.shields.io/github/actions/workflow/status/xenofex7/transfer/docker.yml?branch=main&label=docker%20build" alt="docker build"></a>
</p>

> Originally based on [dutchcoders/transfer.sh](https://github.com/dutchcoders/transfer.sh);
> this repository is now developed and maintained independently.

---

## Contents

- [Quick start](#quick-start)
- [Self-hosting with docker compose](#self-hosting-with-docker-compose)
- [Admin UI](#admin-ui)
- [Usage](#usage)
- [Configuration](#configuration)
- [Development](#development)
- [Credits](#credits)

---

## Quick start

Pull the published container image and run it with a local data directory:

```bash
docker run --rm \
  -p 8080:8080 \
  -v $(pwd)/data:/data \
  ghcr.io/xenofex7/transfer:latest
```

Then, in another shell:

```bash
curl --upload-file ./hello.txt http://127.0.0.1:8080/hello.txt
```

The response body is the download URL. The `X-Url-Delete` response header
contains the deletion URL - keep both.

> **Heads-up for the bare quick start:** this command starts the
> container with **no authentication** - anything that can reach port
> 8080 can upload (anonymous tier), and nobody can sign in, so the admin
> UI is unreachable. It also fires the
> [anonymous instance heartbeat](#anonymous-instance-heartbeat) after
> 30 s. For anything beyond a local test run, use the
> [docker compose stack](#self-hosting-with-docker-compose) below, which
> wires up htpasswd auth and an external reverse proxy.

The container image presets `LISTENER=:8080`, `BASEDIR=/data`,
`TEMP_PATH=/tmp`, `PURGE_DAYS=360` and `PURGE_INTERVAL=1`; override them via
env or CLI flags as needed.

Multi-arch images (`linux/amd64`, `linux/arm64`) are built on release tags
and published on GHCR as `latest` and semver (`X.Y.Z`, `X.Y`, `X`). Pin to a
specific version in production.

---

## Self-hosting with docker compose

The deployment stack lives in [`docker-compose.yml`](docker-compose.yml).

```bash
# 1. Configuration template
cp .env.example .env
$EDITOR .env

# 2. Auth directory (seed at least one user; more can be managed in the UI)
mkdir -p auth
htpasswd -B -c auth/htpasswd alice
sudo chown -R 65532:65532 auth

# 3. Up
docker compose up -d
```

After the stack is up, sign in at `/login`. With `AUTH_REQUIRE_2FA=true`
(the default) the first sign-in redirects to TOTP enrolment. Then open the
[admin UI](#admin-ui) to manage users, inspect uploads, and change branding.

### Reverse proxy

The transfer container exposes port 8080 only inside the compose network,
which joins the external Docker network named by `PROXY_NETWORK`. TLS and
the public hostname are handled by your reverse proxy (nginx, Caddy,
Traefik). It must:

- forward the original `Host` header and set `X-Forwarded-Proto`; both build
  the returned download URLs, and `X-Forwarded-Proto: https` sets the
  `Secure` cookie flag
- set `X-Forwarded-For` (or `X-Real-Ip`); the client IP for throttling, rate
  limit, IP filters and logs is only taken from these headers when the
  direct peer is a private or loopback address
- allow request bodies of at least `MAX_UPLOAD_SIZE` (given in KB), e.g.
  nginx `client_max_body_size`

### Upgrades and backups

Pin `TRANSFER_IMAGE` in `.env` to a release tag, then
`docker compose pull && docker compose up -d`. Release notes are in
[`CHANGELOG.md`](CHANGELOG.md); migration notes for older layouts are in the
header of [`docker-compose.yml`](docker-compose.yml).

All state lives in two host directories: `DATA_DIR` (uploads plus
`.settings.json`, `.branding/`, `.secrets/`, `.deletions.jsonl`) and
`AUTH_DIR` (`htpasswd` and `htpasswd.meta.json` with TOTP secrets and API
tokens). Back up both.

---

## Admin UI

Browser routes live behind a cookie-based login at `/login`. After
signing in (password + TOTP if 2FA is enabled) the following pages
become reachable. There are no roles: every signed-in user has full admin
access.

| Path | Purpose |
|---|---|
| `/admin/files` | Browse stored uploads, filter, manually delete |
| `/admin/secrets` | List unopened one-time secrets (id, creator, expiry - never the content) and delete them |
| `/admin/settings` | Tagline, contact link, privacy policy link, theme, custom logo / favicon, anonymous-heartbeat toggle |
| `/admin/users` | Add, reset password, delete - read/write to the mounted htpasswd |
| `/account` | Enable / disable TOTP, manage API tokens, regenerate recovery codes |

Branding uploads land in `<BASEDIR>/.branding/`; persisted operator
settings live in `<BASEDIR>/.settings.json`; TOTP secrets, recovery
codes (bcrypt-hashed) and API token records live in
`<htpasswd>.meta.json` next to the htpasswd file.

### Authentication model

- **Passwords**: bcrypt-hashed in the standard htpasswd file. Used at
  the `/login` form. HTTP Basic Auth accepts the password only for
  accounts without TOTP while `--auth-require-2fa=false`; everyone
  else authenticates `curl` / scripts with an API token.
- **TOTP (recommended)**: enrol at `/account/2fa/setup`; works with any
  RFC 6238 authenticator app (Google Authenticator, 1Password, Authy,
  etc.). Ten one-shot recovery codes are issued at enrolment.
- **API tokens**: per-user named tokens for headless clients. Create
  them at `/account` and present them as the password in HTTP Basic
  Auth (`curl --user alice:tk_xxx....`). Each token is independently
  revocable and may carry an expiry of 1 to 3650 days. **Use these
  instead of passwords for `curl` / scripts** - they are the only
  credential allowed to bypass TOTP on the API path.
- **Session cookies**: `httpOnly`, `SameSite=Lax`, marked `Secure`
  whenever the request is HTTPS or `X-Forwarded-Proto: https` is set.
  Sliding 8h idle TTL, capped by a 30d max lifetime; both tunable via
  `--auth-session-ttl` and `--auth-session-max-lifetime`.

Set `--auth-require-2fa=false` if you want to allow password-only
browser sessions (not recommended for publicly reachable instances).

Failed sign-ins are throttled per client IP and per account: after
10 failures within 15 minutes, further password and TOTP attempts
(`/login`, `/login/totp`, the TOTP re-checks on `/account`, HTTP Basic
Auth) are rejected until the budget refills at one attempt every 90
seconds; Basic Auth answers `429`. Wrong API tokens only count against
the client IP, so password guessing cannot lock out a user's tokens.
Wrong passwords for a protected download count per file, from any IP.

---

## Usage

### Upload

```bash
curl --upload-file ./hello.txt https://your-instance.example.com/hello.txt
```

### Download

```bash
curl https://your-instance.example.com/<token>/hello.txt -o hello.txt
```

### Delete

```bash
curl -X DELETE https://your-instance.example.com/<token>/hello.txt/<delete-token>
```

The `<delete-token>` is returned in the `X-Url-Delete` response header on
upload.

### Per-upload limits

```bash
# Auto-delete after N days (overrides the server default)
curl --upload-file ./hello.txt https://your-instance.example.com/hello.txt \
  -H "Max-Days: 7"

# Cap the download count
curl --upload-file ./hello.txt https://your-instance.example.com/hello.txt \
  -H "Max-Downloads: 1"

# Require a password before the download (stored as a bcrypt hash)
curl --upload-file ./hello.txt https://your-instance.example.com/hello.txt \
  -H "X-Password: s3cret"

# Fetch a password protected file; browsers get a password form instead
curl https://your-instance.example.com/<token>/hello.txt -H "X-Password: s3cret" -O
```

Change the download limit, password and retention of an existing upload with
the delete token. `maxDownloads` 0 means unlimited. An empty `password`
removes it, and leaving `password` out keeps the current one. `maxDays` counts
from the upload time and is capped at the tier TTL; 0 resets it to the tier
TTL, leaving it out keeps the current expiry, and a date already in the past
is rejected.

```bash
curl -X PATCH https://your-instance.example.com/<token>/hello.txt/<delete-token> \
  -H "Content-Type: application/json" \
  -d '{"maxDownloads": 3, "password": "s3cret", "maxDays": 7}'
```

### Link aliases

Direct download (skip the preview page):

```
https://your-instance.example.com/get/<token>/hello.txt
```

Inline (open in browser instead of download):

```
https://your-instance.example.com/inline/<token>/hello.txt
```

### One-time secrets

The homepage also shares short texts (passwords, credentials) that can be
opened exactly once. Encryption (AES-256-GCM) happens in the browser and the
key travels in the URL fragment, so the server only stores ciphertext.
Unopened secrets expire after 24 h (anonymous) or 7 days (signed in).

For shell helpers, encryption, bulk archives and more, see [`examples.md`](examples.md).

---

## Configuration

Every option is a CLI flag with a matching environment variable.
`transfer --help` (or `docker run --rm ghcr.io/xenofex7/transfer:latest --help`)
lists all flags with their env names and binary defaults;
[`.env.example`](.env.example) documents the values used by the compose
stack. Note that the binary defaults differ from the compose defaults in a
few places, e.g. `LISTENER` (`127.0.0.1:8080` vs. `:8080`) and
`MAX_UPLOAD_SIZE` (`0` = no limit vs. `10485760` KB = 10 GiB). `BASEDIR` is
required.

### Upload tiers & lifecycle

Uploads work in two tiers. Anonymous visitors can upload without any
credentials (small files, short retention); signed-in users - via the
web login, HTTP Basic Auth or an API token - get the big limits. Every
upload carries its own expiry date; the purge loop deletes expired
files from disk.

| Flag | Env | Default | Description |
|---|---|---|---|
| `--anon-uploads` | `ANON_UPLOADS` | `true` | Allow uploads without credentials; `false` requires a login for every upload |
| `--anon-max-upload-size` | `ANON_MAX_UPLOAD_SIZE` | `51200` (50 MB) | Per-file limit in KB for anonymous uploads |
| `--anon-upload-ttl` | `ANON_UPLOAD_TTL` | `24h` | Retention for anonymous uploads |
| `--max-upload-size` | `MAX_UPLOAD_SIZE` | `0` (no limit) | Per-file limit in KB for signed-in uploads |
| `--auth-upload-ttl` | `AUTH_UPLOAD_TTL` | `720h` (30 days) | Default and maximum retention for signed-in uploads; `0` disables the forced expiry |
| `--purge-days` | `PURGE_DAYS` | `360` | Hard age cap: uploads older than this are purged regardless of expiry; `0` disables the cap, per-upload expiry still applies |
| `--purge-interval` | `PURGE_INTERVAL` | `1` | Hours between purge runs |

A `Max-Days` request header shortens the retention per upload; values
above the tier TTL are capped to it.

Without any authentication configured every upload is anonymous and
gets the anonymous limits. Raise `ANON_MAX_UPLOAD_SIZE` and
`ANON_UPLOAD_TTL` (or set them to `0` for no limit) on such an
instance.

`RATE_LIMIT` caps file downloads per client IP and minute (`0` = off); it
does not apply to uploads.

### Authentication & access control

Multi-user auth uses `HTTP_AUTH_HTPASSWD` (the compose stack sets it to
`/etc/transfer/htpasswd`); `HTTP_AUTH_USER` / `HTTP_AUTH_PASS` remain as a
single-user fallback. `HTTP_AUTH_IP_WHITELIST` lets the listed CIDRs upload
without credentials, `IP_WHITELIST` / `IP_BLACKLIST` filter at the
connection level.

### Webhooks

`UPLOAD_WEBHOOK_URL` receives a best-effort, async, no-retry JSON POST for
upload, download and delete events, optionally with
`Authorization: Bearer <WEBHOOK_TOKEN>`. The body shape is documented in
[`.env.example`](.env.example).

### Analytics

#### Visitor analytics (optional, off by default)

Setting both `UMAMI_SCRIPT_URL` and `UMAMI_WEBSITE_ID` injects the
Umami tracker into user-facing pages (`/`, download views, 404). Admin
pages (`/admin/*`) never carry the tag. Self-hosted Umami works as
well as `umami.is`.

#### Anonymous instance heartbeat

Transfer sends one anonymous heartbeat per day so I can see how many
instances are running and which versions are in the wild. The payload
is just the running version - no user data, no IP, no upload metadata,
no usernames, no request tracking, not even an instance ID. Events go
to a privately-hosted Umami instance.

Caveat: the request unavoidably reveals this server's source IP to the
Umami host at the HTTP layer (that's how every outbound HTTP call
works); IP logging on that Umami is disabled.

To opt out, toggle it off in `/admin/settings`, or set
`UMAMI_HEARTBEAT=off` in your `.env`. The exact JSON the server would
send is exposed at `/admin/settings/heartbeat/payload` for inspection.

To redirect the beat to your own Umami instead, set
`UMAMI_HEARTBEAT_URL` and `UMAMI_HEARTBEAT_WEBSITE_ID`.

---

## Development

Requires Go 1.26+.

```bash
git clone git@github.com:xenofex7/transfer.git
cd transfer
go run . --listener 127.0.0.1:8080 --basedir ./tmp/storage --temp-path ./tmp
```

Or, for a production-style binary (the Go module path is kept on
`dutchcoders/transfer.sh` for compatibility):

```bash
go build -tags netgo \
  -ldflags "-X github.com/dutchcoders/transfer.sh/cmd.Version=dev -s -w" \
  -o transfer ./
```

Run the tests and the linter:

```bash
go test -race ./...
golangci-lint run --config .golangci.yml
```

CI runs both on every push (see `.github/workflows/test.yml`).
The roadmap and planned work live in [`ROADMAP.md`](ROADMAP.md).

---

## Credits

Built on top of the original work by:

- **Remco Verhoef** & **Uvis Grinfelds** - original creators of `transfer.sh`
- **Andrea Spacca** & **Stefan Benten** - long-time upstream maintainers

The upstream copyright notice is kept intact and the project ships under the
same [MIT license](LICENSE).
