# Roadmap — drop.pac-build.ch

Tracking & Planung des Forks. Hosting-Ziel: eigene Instanz im Keller-Docker-Stack
hinter nginx auf `drop.pac-build.ch`. Team: 2–3 Personen, Auth via htpasswd.

Legende: `[x]` erledigt · `[ ]` offen · `[~]` in Arbeit

---

## Phase 1 — Cleanup (abgeschlossen)

- [x] Cloud-Storage-Backends entfernt (S3, GDrive, Storj)
- [x] VirusTotal-Integration entfernt
- [x] Eingebauter TLS-Stack + Let's Encrypt entfernt (nginx terminiert TLS)
- [x] pprof-Profiler entfernt
- [x] Google Analytics + UserVoice Frontend-Keys entfernt
- [x] Vagrantfile, Bower-Config, manifest.json entfernt
- [x] cmd.go auf local-only mit sinnvollen Defaults reduziert
- [x] `go mod tidy` — ~30 Transitive-Deps weg
- [x] Build, `go vet`, Tests, Smoke-Test (Upload/Download/Delete/TTL) grün
- [x] In 6 logische Commits aufgeteilt

Resultat: 13 Dateien geändert, 36 Insertions, 1580 Deletions.

---

## Phase 2 — Deployment-Setup

Ziel: Stack ist auf dem Keller-Server reproduzierbar mit `docker compose up -d`
deploybar. Auth, Storage-Volume, ClamAV-Sidecar laufen sauber zusammen.

### 2.1 Dockerfile prüfen & anpassen
- [ ] Alte Dockerfile-Annahmen mit dem neuen Code abgleichen (PUID/PGID-Logik
      vereinfachen, alte Args entrümpeln)
- [ ] Image-Größe prüfen, Multi-Stage-Build sauber halten
- [ ] Image-Tag-Strategie festlegen (`:dev`, `:latest`, `:v0.x.0`)

### 2.2 docker-compose.yml schreiben
- [ ] Service `transfersh` mit Volume für `basedir`
- [ ] Service `clamav` als Sidecar, transfersh redet via `--clamav-host` mit ihm
- [ ] Restart-Policy, Healthcheck (`/health.html`), Resource-Limits
- [ ] `.env.example` mit allen sinnvollen ENV-Vars
- [ ] In bestehenden Keller-Stack einfügen (Netzwerk, Reverse-Proxy-Labels)

### 2.3 Auth einrichten
- [ ] `htpasswd`-Datei mit den 2–3 Team-Usern erzeugen
- [ ] Volume-Mount für die Datei in den Container
- [ ] `--http-auth-htpasswd` als ENV verdrahten
- [ ] Optional: `--http-auth-ip-whitelist` für Heimnetz (Upload ohne Login)

### 2.4 nginx-Vhost für drop.pac-build.ch
- [ ] HTTPS-Cert vorhanden / via Let's Encrypt im Reverse-Proxy
- [ ] Proxy-Pass auf transfersh-Container
- [ ] `client_max_body_size` passend zur `--max-upload-size` setzen
- [ ] `proxy_request_buffering off` für Streaming-Uploads
- [ ] Proxy-Header: `X-Forwarded-Host`, `X-Forwarded-Proto`

### 2.5 Sinnvolle Limits setzen
- [ ] `--max-upload-size` festlegen (z. B. 5 GB)
- [ ] `--rate-limit` (Requests pro Minute)
- [ ] Default `--purge-days` (aktuell 360) bestätigen oder anpassen
- [ ] `--random-token-length` ggf. erhöhen

---

## Phase 3 — README & Dokumentation

Die alte 24 KB README ist voll mit s3/gdrive/Let's-Encrypt-Beispielen, die für
unseren Use-Case irrelevant sind und Verwirrung stiften.

- [ ] README auf das tatsächliche Feature-Set kürzen
- [ ] Disclaimer aus Upstream entfernen (oder durch eigenen ersetzen)
- [ ] Beispiel-curl-Befehle behalten, andere Abschnitte streichen
- [ ] Setup-Anleitung für unseren Stack ergänzen (docker-compose, nginx, htpasswd)
- [ ] examples.md prüfen, was relevant bleibt

---

## Phase 4 — Frontend-Branding

Web-Assets sind als Go-bindata embedded aus dem Submodul
`dutchcoders/transfer.sh-web`. Branding heißt: eigenen Web-Fork pflegen oder
Patches/Overrides legen.

- [ ] Entscheiden: eigenen Web-Fork oder Override via `--web-path`?
- [ ] Logo + Favicon ersetzen
- [ ] Farbschema (drop.pac-build.ch Identität) anpassen
- [ ] Title-Tag, Meta-Beschreibung, OG-Tags
- [ ] Preview-Seite leicht entrümpeln (DutchCoders-Branding entfernen oder
      Footer-Zeile umschreiben)
- [ ] QR-Code-Logo auswechseln (falls eingebrannt)

---

## Phase 5 — Optionale Features

### 5.1 Mini-Dashboard für File-Übersicht
Aktuell weiß man nach einem Upload nur die URL — wenn man die verliert, ist die
Datei "weg" (kein Listing). Für ein 3er-Team ggf. unpraktisch.

- [ ] Endpoint `/admin/files` (hinter htpasswd) der `basedir` listet
- [ ] Anzeige: Upload-Datum, Größe, verbleibende TTL, Download-URL,
      Delete-URL (aus Metadata-Datei lesen)
- [ ] Such-/Filterfunktion
- [ ] Manueller Delete-Button

### 5.2 Erweiterte Auto-Cleanup-Regeln
- [ ] Per-Datei TTL über UI setzbar (statt nur per `Max-Days` Header)
- [ ] Storage-Quota pro User (htpasswd-User aus Auth-Header)

### 5.3 Notifications
- [ ] Webhook bei neuem Upload (z. B. Slack/Telegram für's Team)
- [ ] E-Mail-Benachrichtigung bei Download (optional pro Upload)

---

## Phase 6 — Production-Go-Live

- [ ] Deploy auf Keller-Server
- [ ] DNS-Record `drop.pac-build.ch` → Keller-Server
- [ ] HTTPS-Cert verifizieren (SSL Labs Test)
- [ ] End-to-End-Test mit Team
- [ ] Backup-Strategie für `basedir` (rsync? snapshots?)
- [ ] Monitoring (Container-Health, Disk-Usage, ClamAV-Updates)
- [ ] Log-Rotation

---

## Phase 7 — Maintenance / Backlog

- [ ] Upstream-Updates beobachten und cherry-picken
- [ ] Go-Version regelmäßig hochziehen (aktuell `1.24` im Dockerfile)
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
- **Backups:** Wie wichtig sind hochgeladene Files? Wegwerf-Transfer (kein Backup)
  oder semi-persistent (mit Backup)?
