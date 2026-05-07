<p align="center">
  <img src="assets/transfer_logo.png" alt="transfer" width="360">
</p>

<h1 align="center">transfer</h1>

<p align="center">
  A small, self-hosted file-drop service. Easy and fast file sharing from the command line.
</p>

<p align="center">
  <a href="https://github.com/xenofex7/transfer/tags"><img src="https://img.shields.io/github/v/tag/xenofex7/transfer?sort=semver&label=version" alt="latest tag"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/xenofex7/transfer" alt="license"></a>
  <img src="https://img.shields.io/badge/go-1.25-00ADD8?logo=go&logoColor=white" alt="go 1.25">
  <a href="https://github.com/xenofex7/transfer/pkgs/container/transfer"><img src="https://img.shields.io/badge/docker-ghcr.io-2496ed?logo=docker&logoColor=white" alt="container image"></a>
  <a href="https://github.com/xenofex7/transfer/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/xenofex7/transfer/test.yml?branch=main&label=tests" alt="tests"></a>
  <a href="https://github.com/xenofex7/transfer/actions/workflows/docker.yml"><img src="https://img.shields.io/github/actions/workflow/status/xenofex7/transfer/docker.yml?branch=main&label=docker%20build" alt="docker build"></a>
  <img src="https://img.shields.io/github/last-commit/xenofex7/transfer" alt="last commit">
  <img src="https://img.shields.io/github/commit-activity/y/xenofex7/transfer" alt="commit activity">
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
> 8080 can upload, download and delete. It also fires the
> [anonymous instance heartbeat](#anonymous-instance-heartbeat-on-by-default-easy-to-disable)
> within 30 s. For anything beyond a local kick-the-tyres run, use the
> [docker compose stack](#self-hosting-with-docker-compose) below, which
> wires up htpasswd auth and an external reverse proxy.

The container image bakes in sensible defaults (`LISTENER=:8080`,
`BASEDIR=/data`, `TEMP_PATH=/tmp`, `PURGE_DAYS=360`,
`PURGE_INTERVAL=24`); override them via env or CLI flags as needed.

Multi-arch images (`linux/amd64`, `linux/arm64`) are published on GHCR with
`latest`, semver (`X.Y.Z`, `X.Y`, `X`) and per-commit (`sha-<short>`) tags.
Pin to a specific version in production.

---

## Self-hosting with docker compose

The deployment stack lives in [`docker-compose.yml`](docker-compose.yml).

```bash
# 1. Configuration template
cp .env.example .env
$EDITOR .env

# 2. Auth file (seed at least one user; more can be managed in the UI)
htpasswd -B -c htpasswd alice

# 3. Up
docker compose up -d
```

After the stack is up, open the [admin UI](#admin-ui) to manage users,
inspect uploads, and tweak branding without touching files by hand.

The transfer container exposes port 8080 only inside the compose network.
TLS and the public hostname are expected to be handled by your reverse proxy
of choice (nginx, Caddy, Traefik). Pass standard proxy headers
(`X-Forwarded-Host`, `X-Forwarded-Proto`) and set `client_max_body_size` to at
least the value of `MAX_UPLOAD_SIZE`.

---

## Admin UI

Three pages live behind the same htpasswd auth as uploads. Authenticate
with any user from the htpasswd file.

| Path | Purpose |
|---|---|
| `/admin/files` | Browse stored uploads, filter, manually delete |
| `/admin/settings` | Tagline, contact email, theme, custom logo / favicon, anonymous-heartbeat toggle |
| `/admin/users` | Add, reset password, delete - read/write to the mounted htpasswd |

Branding uploads land in `<BASEDIR>/.branding/`; persisted operator
settings live in `<BASEDIR>/.settings.json`.

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

For shell helpers, encryption, bulk archives and more, see [`examples.md`](examples.md).

---

## Configuration

All flags can be set via CLI args or the matching environment variable.

### Network

| Flag | Env | Default | Description |
|---|---|---|---|
| `--listener` | `LISTENER` | `127.0.0.1:8080` (binary) / `:8080` (container) | Address the HTTP server binds to |
| `--proxy-path` | `PROXY_PATH` | - | Path prefix when behind a reverse proxy |
| `--proxy-port` | `PROXY_PORT` | - | External port of the reverse proxy |
| `--cors-domains` | `CORS_DOMAINS` | - | Comma-separated list of CORS origins |

### Storage

| Flag | Env | Default | Description |
|---|---|---|---|
| `--basedir` | `BASEDIR` | *required* (the container image presets it to `/data`) | Path to the local storage directory |
| `--temp-path` | `TEMP_PATH` | OS temp dir (`/tmp` in the container) | Path used for in-flight uploads |

### Lifecycle

| Flag | Env | Default | Description |
|---|---|---|---|
| `--purge-days` | `PURGE_DAYS` | `360` | Days after which uploads are purged |
| `--purge-interval` | `PURGE_INTERVAL` | `24` | Hours between purge runs |
| `--max-upload-size` | `MAX_UPLOAD_SIZE` | `0` (no limit) | Per-file limit in KB |
| `--rate-limit` | `RATE_LIMIT` | `0` (off) | Requests per minute |
| `--random-token-length` | `RANDOM_TOKEN_LENGTH` | `10` | URL token length |

### Authentication & access control

| Flag | Env | Description |
|---|---|---|
| `--http-auth-user` / `--http-auth-pass` | `HTTP_AUTH_USER` / `HTTP_AUTH_PASS` | Single-user basic auth |
| `--http-auth-htpasswd` | `HTTP_AUTH_HTPASSWD` | Path to a htpasswd file (multi-user) |
| `--http-auth-ip-whitelist` | `HTTP_AUTH_IP_WHITELIST` | CIDRs that may upload without auth |
| `--ip-whitelist` | `IP_WHITELIST` | CIDRs allowed at the connection level |
| `--ip-blacklist` | `IP_BLACKLIST` | CIDRs denied at the connection level |

### Frontend / misc

| Flag | Env | Description |
|---|---|---|
| `--tagline` | `TAGLINE` | Subtitle shown beneath the hostname on the homepage; empty hides it. The admin UI overrides this at runtime. |
| `--email-contact` | `EMAIL_CONTACT` | Address rendered in the "Contact" link |
| `--web-path` | `WEB_PATH` | Override the bundled web frontend directory (development only) |
| `--log` | `LOG` | Log file path (defaults to stderr) |

### Webhooks

Best-effort, async, no-retry POSTs for upload, download and delete events.

| Flag | Env | Description |
|---|---|---|
| `--upload-webhook-url` | `UPLOAD_WEBHOOK_URL` | URL that receives JSON events. Empty disables webhooks. |
| `--webhook-token` | `WEBHOOK_TOKEN` | Optional bearer token added as `Authorization: Bearer <token>` |

Body shape (`event` is one of `upload`, `download`, `delete`; optional
fields are omitted when empty):

```json
{
  "event": "upload",
  "filename": "hello.txt",
  "content_type": "text/plain",
  "size": 123,
  "url": "https://your-instance.example.com/<token>/hello.txt",
  "delete_url": "https://your-instance.example.com/<token>/hello.txt/<delete-token>",
  "user": "alice",
  "downloads": 0
}
```

### Analytics

#### Visitor analytics (optional, off by default)

Setting both `UMAMI_SCRIPT_URL` and `UMAMI_WEBSITE_ID` injects the
Umami tracker into user-facing pages (`/`, download views, 404). Admin
pages (`/admin/*`) never carry the tag. Self-hosted Umami works as
well as `umami.is`.

| Flag | Env | Description |
|---|---|---|
| `--umami-script-url` | `UMAMI_SCRIPT_URL` | URL to your Umami `script.js` |
| `--umami-website-id` | `UMAMI_WEBSITE_ID` | Umami site UUID (`data-website-id`) |

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

Requires Go 1.25+.

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
