# Roadmap

Tracking & Planung dieses Forks. Ziel: schlanke, selbst-gehostete
transfer-Variante mit lokalem Storage, htpasswd-Auth und
Reverse-Proxy davor.

Status: **v1.1.0 in Production**. Phasen 1–4 und 6 sind durch. Übrig
bleibt eine kurze Liste von Optionals und laufender Wartung.

Legende: `[x]` erledigt · `[ ]` offen · `[~]` in Arbeit

---

## Backlog (offen)

### Optionale Features
- [ ] Storage-Quota pro User (htpasswd-User aus Auth-Header)
- [ ] E-Mail-Benachrichtigung bei Download (optional pro Upload)
- [ ] Rollen (admin/uploader) — aktuell darf jeder eingeloggte User auch
      User verwalten

### Production-Härtung
- [ ] HTTPS-Cert mit SSL Labs gegentesten (nice-to-have)
- [ ] Monitoring (Container-Health, Disk-Usage)
- [ ] Log-Rotation
- [ ] Argon2id-Migration der Passwort-Hashes (bcrypt bleibt vorerst,
      transparenter Rehash beim nächsten Login wäre nett)
- [ ] WebAuthn / Passkeys als optionaler zweiter Faktor neben TOTP

### Maintenance
- [ ] Dependabot für Go-Module aktivieren
- [ ] Upstream-Updates beobachten und cherry-picken (laufend)
- [ ] Go-Version regelmäßig hochziehen (laufend)

---

## Erledigt

### Phase 1 — Cleanup
- [x] Cloud-Storage-Backends entfernt (S3, GDrive, Storj)
- [x] VirusTotal-Integration entfernt
- [x] Eingebauter TLS-Stack + Let's Encrypt entfernt (Reverse-Proxy terminiert TLS)
- [x] pprof-Profiler entfernt
- [x] Google Analytics + UserVoice Frontend-Keys entfernt
- [x] Vagrantfile, Bower-Config, manifest.json entfernt
- [x] cmd.go auf local-only mit sinnvollen Defaults reduziert
- [x] `go mod tidy` — diverse Transitive-Deps weg

### Phase 2 — Deployment-Setup
- [x] Dockerfile: Multi-Stage, Alpine-Final, Non-Root, OCI-Labels, HEALTHCHECK
- [x] PUID/PGID-Logik vereinfacht, alte Args entrümpelt
- [x] Image-Tag-Strategie (semver, `:latest`, `:edge`, `:sha-<short>`)
- [x] `docker-compose.yml` mit `transfersh` + `clamav`-Sidecar, Healthcheck, `.env.example`
- [x] htpasswd-Auth (Datei, Volume-Mount, ENV verdrahtet)
- [x] Reverse-Proxy mit HTTPS-Termination, `client_max_body_size`,
      `proxy_request_buffering off`, Forwarded-Header
- [x] Limits gesetzt: `--max-upload-size`, `--rate-limit`, `--purge-days`,
      `--random-token-length`
- [x] GitHub Actions: GHCR-Build (semver/edge/sha), Multi-Arch (amd64+arm64)
- [x] Docker-Hub-Workflow + Binary-Release-Workflow abgelöst
- [x] `test.yml` modernisiert (Race-Tests, Cache, aktuelle Action-Versionen)
- [x] Erste Tags durchlaufen (v1.0.0 → v1.1.0)

### Phase 3 — README & Dokumentation
- [x] README auf tatsächliches Feature-Set gekürzt
- [x] Fork-Notice + "What's different from upstream"-Tabelle
- [x] Konfigurations-Tabelle thematisch gruppiert, Build-/GHCR-/Lizenz-Badges
- [x] `examples.md` getrimmt (VirusTotal raus, Hostnames generisch)
- [x] `SECURITY.md`, `llms.txt`, Table of Contents

### Phase 4 — Frontend
- [x] Upstream-Web-Frontend komplett ersetzt durch eigenen vanilla Rebuild
      (embedded, kein Submodul, kein bindata mehr)
- [x] Eigenes Logo, Favicon, Farbschema, Title/Meta/OG
- [x] Preview-Seiten neu gebaut (Audio/Video/Image/Markdown/Sandbox)
- [x] Cache-Busting via Content-Hash auf CSS/JS
- [x] Accessibility: focus-visible, reduced motion
- [x] Security-Header + noindex-Meta

### Phase 5 — Optionale Features
- [x] Mini-Dashboard `/admin/files` (htpasswd-protected): Filter, Copy-URL,
      manueller Delete mit Confirm
- [x] `LastDownloadedAt` getrackt, Download-Counter auch für unlimited Files
- [x] Append-only `.deletions.jsonl` Log, letzte 50 Löschungen im Dashboard
- [x] Per-Upload `Max-Days` / `Max-Downloads` Header (UI-Inputs auf Homepage)
- [x] Webhook bei Upload/Download/Delete (`UPLOAD_WEBHOOK_URL`,
      optional Bearer-Token via `WEBHOOK_TOKEN`)

### Phase 6 — Production-Go-Live
- [x] Deploy auf Zielserver, DNS, HTTPS-Cert (Let's Encrypt via Reverse-Proxy)
- [x] End-to-End-Test (Upload + Download, ClamAV-Prescan grün)
- [x] Backup-Strategie (Host-Volume durch Hyper-Backup abgedeckt;
      ClamAV-Signatures via freshclam beim Container-Start)

### Phase 7 — Maintenance (laufend abgearbeitet)
- [x] CI: build + test + golangci-lint + govulncheck
- [x] `.golangci.yml` konfiguriert
- [x] `extras/` (clamd, transfersh) entfernt — nicht gebraucht
- [x] Eigener Token-Bucket-IP-Limiter (Drittabhängigkeit raus)
- [x] CVE-Bumps: cloudflare/circl, golang.org/x/net
- [x] Go-Toolchain auf 1.25 angehoben (Dockerfile + CI)
