# Roadmap

Tracking & Planung dieses Forks. Ziel: schlanke, selbst-gehostete
transfer.sh-Variante mit lokalem Storage, ClamAV-Virenscan, htpasswd-Auth und
Reverse-Proxy davor.

Legende: `[x]` erledigt · `[ ]` offen · `[~]` in Arbeit

---

## Phase 1 — Cleanup (abgeschlossen)

- [x] Cloud-Storage-Backends entfernt (S3, GDrive, Storj)
- [x] VirusTotal-Integration entfernt
- [x] Eingebauter TLS-Stack + Let's Encrypt entfernt (Reverse-Proxy terminiert TLS)
- [x] pprof-Profiler entfernt
- [x] Google Analytics + UserVoice Frontend-Keys entfernt
- [x] Vagrantfile, Bower-Config, manifest.json entfernt
- [x] cmd.go auf local-only mit sinnvollen Defaults reduziert
- [x] `go mod tidy` — diverse Transitive-Deps weg
- [x] Build, `go vet`, Tests, Smoke-Test (Upload/Download/Delete/TTL) grün
- [x] In logische Commits aufgeteilt

---

## Phase 2 — Deployment-Setup

Ziel: Stack ist mit `docker compose up -d` reproduzierbar deploybar. Auth,
Storage-Volume, ClamAV-Sidecar laufen sauber zusammen.

### 2.1 Dockerfile prüfen & anpassen
- [x] Alte Dockerfile-Annahmen mit dem neuen Code abgleichen (PUID/PGID-Logik
      vereinfachen, alte Args entrümpeln)
- [x] Multi-Stage-Build, Alpine-Final, Non-Root-User, OCI-Labels, HEALTHCHECK
- [x] Image-Tag-Strategie festlegen (semver, `:latest`, `:edge`, `:sha-<short>`)
- [ ] Image-Größe nach erstem Build verifizieren

### 2.2 docker-compose.yml schreiben
- [x] Service `transfersh` mit Volume für `basedir`
- [x] Service `clamav` als Sidecar, transfersh redet via `--clamav-host` mit ihm
- [x] Restart-Policy, Healthcheck (`/health.html`), Resource-Limits
- [x] `.env.example` mit allen sinnvollen ENV-Vars
- [ ] Auf Zielserver deployen und Smoke-Test fahren

### 2.3 Auth einrichten
- [ ] `htpasswd`-Datei mit den Team-Usern erzeugen
- [ ] Volume-Mount für die Datei in den Container
- [ ] `--http-auth-htpasswd` als ENV verdrahten
- [ ] Optional: `--http-auth-ip-whitelist` für vertrauenswürdige Netze

### 2.4 Reverse-Proxy
- [ ] HTTPS-Termination am Reverse-Proxy
- [ ] Proxy-Pass auf transfersh-Container
- [ ] `client_max_body_size` passend zur `--max-upload-size` setzen
- [ ] `proxy_request_buffering off` für Streaming-Uploads
- [ ] Proxy-Header: `X-Forwarded-Host`, `X-Forwarded-Proto`

### 2.5 Sinnvolle Limits setzen
- [ ] `--max-upload-size` festlegen
- [ ] `--rate-limit` (Requests pro Minute)
- [ ] Default `--purge-days` (aktuell 360) bestätigen oder anpassen
- [ ] `--random-token-length` ggf. erhöhen

### 2.6 Container-Builds in CI
- [x] GitHub Actions Workflow für GHCR-Build (semver-Tags, edge, sha)
- [x] Multi-Arch (amd64 + arm64)
- [x] Bestehenden Docker-Hub-Workflow ablösen
- [x] Binary-Release-Workflow entfernen (wir liefern nur Container)
- [x] test.yml modernisiert (aktuelle Action-Versionen, race-Tests, Cache)
- [ ] Erstes Tag (`v0.1.0`) setzen, Workflow real durchlaufen lassen

---

## Phase 3 — README & Dokumentation

- [x] README auf das tatsächliche Feature-Set gekürzt (633 → 313 Zeilen)
- [x] Disclaimer aus Upstream entfernt
- [x] Beispiel-curl-Befehle behalten, andere Abschnitte gestrichen
- [x] Setup-Anleitung für den schlanken Stack ergänzt
- [x] Fork-Notice + "What's different from upstream"-Tabelle ergänzt
- [x] Konfigurations-Tabelle nach Themen gruppiert
- [x] Build-Status, GHCR und Lizenz-Badges
- [ ] examples.md prüfen — was bleibt relevant nach Phase 1?

---

## Phase 4 — Frontend-Branding

Web-Assets sind als Go-bindata embedded aus dem Submodul
`dutchcoders/transfer.sh-web`. Branding heißt: eigenen Web-Fork pflegen oder
Patches/Overrides legen.

- [ ] Entscheiden: eigener Web-Fork oder Override via `--web-path`?
- [ ] Logo + Favicon ersetzen
- [ ] Farbschema anpassen
- [ ] Title-Tag, Meta-Beschreibung, OG-Tags
- [ ] Preview-Seite leicht entrümpeln (Upstream-Branding entfernen oder
      Footer-Zeile umschreiben)
- [ ] QR-Code-Logo auswechseln (falls eingebrannt)

---

## Phase 5 — Optionale Features

### 5.1 Mini-Dashboard für File-Übersicht
Aktuell weiß man nach einem Upload nur die URL — wenn man die verliert, ist die
Datei "weg" (kein Listing). Für ein kleines Team ggf. unpraktisch.

- [ ] Endpoint `/admin/files` (hinter htpasswd) der `basedir` listet
- [ ] Anzeige: Upload-Datum, Größe, verbleibende TTL, Download-URL,
      Delete-URL (aus Metadata-Datei lesen)
- [ ] Such-/Filterfunktion
- [ ] Manueller Delete-Button

### 5.2 Erweiterte Auto-Cleanup-Regeln
- [ ] Per-Datei TTL über UI setzbar (statt nur per `Max-Days` Header)
- [ ] Storage-Quota pro User (htpasswd-User aus Auth-Header)

### 5.3 Notifications
- [ ] Webhook bei neuem Upload (z. B. Chat-Integration)
- [ ] E-Mail-Benachrichtigung bei Download (optional pro Upload)

---

## Phase 6 — Production-Go-Live

- [x] Deploy auf Zielserver
- [x] DNS-Record auf Zielserver
- [x] HTTPS-Cert ausgestellt (Let's Encrypt via Reverse-Proxy)
- [x] End-to-End-Test (curl Upload + Download, ClamAV-Prescan grün)
- [x] Backup-Strategie für `basedir` (deckt der bestehende Hyper-Backup-Job
      des Host-Volumes ab; ClamAV-Signatures werden bei Container-Start
      neu via freshclam geladen, kein Backup nötig)
- [ ] HTTPS-Cert mit SSL Labs gegentesten (nice-to-have)
- [ ] Monitoring (Container-Health, Disk-Usage, ClamAV-Updates)
- [ ] Log-Rotation

---

## Phase 7 — Maintenance / Backlog

- [ ] Upstream-Updates beobachten und cherry-picken
- [ ] Go-Version regelmäßig hochziehen
- [ ] Dependabot für Go-Module aktivieren
- [ ] CI-Workflow im Fork: build + test + golangci-lint
- [ ] golangci-lint Config (`.golangci.yml`) prüfen, ggf. strenger setzen
- [ ] Audit der `extras/` (clamd, transfersh) — wird das gebraucht?

---

## Offene Entscheidungen / Diskussion

- **Branding-Strategie:** Eigener Web-Fork (mehr Pflegeaufwand, sauberer) oder
  `--web-path`-Override (schneller, aber Patches synchron halten)?
- **Mini-Dashboard:** Ja/Nein? Falls ja: read-only Listing oder mit Delete-Funktion?
- **Public oder nur LAN?** Aktuell geplant: public mit Auth. Falls Abuse-Risiko
  steigt, wäre IP-Whitelist eine Option.
- **Backups:** Wegwerf-Transfer-Charakter, aber Bind-Mount liegt im
  Host-Backup-Pfad → semi-persistent als Nebenprodukt erledigt.
