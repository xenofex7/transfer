# Security Policy

## Supported versions

Only the latest released container tag (`ghcr.io/xenofex7/transfer.sh:latest`)
and the latest semver tag receive security fixes. Older builds are not
patched.

## Reporting a vulnerability

This is a small self-hosted fork; there is no security team or bounty
programme. If you find an issue:

1. **Do not open a public GitHub issue** for anything that could be
   exploited (auth bypass, RCE, sensitive disclosure, malware
   delivery via uploads, etc.).
2. Open a [private security advisory](https://github.com/xenofex7/transfer.sh/security/advisories/new)
   on this repository, or file a regular issue prefixed with
   `[security]` for low-impact findings (e.g. missing hardening
   header, doc inaccuracies).
3. Include enough detail to reproduce: affected versions, request /
   payload, expected vs. observed behaviour. Working PoCs help, but
   are not required.

You will get a response within a few days. There is no formal SLA.

## Scope

In scope:

- Issues in the Go server code under `cmd/`, `server/`, `web/`
- The published container image (`ghcr.io/xenofex7/transfer.sh`)
- The deployment defaults shipped in `docker-compose.yml`

Out of scope:

- The upstream `dutchcoders/transfer.sh` project (please report there
  instead)
- Issues that require an attacker to already have write access to the
  host or the storage volume
- Self-DOS by an authenticated user (rate limits exist for a reason
  but a logged-in operator can always overload their own instance)
- Configuration mistakes outside of the defaults (e.g. running the
  service open to the internet without an htpasswd file)
