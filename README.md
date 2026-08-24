# OpenGym-go

**(Golang port)**

Go port of the original [OpenGym](https://gitea.com/DuarteSantos/openGym) single-file Node.js server. Same behavior: passkey (WebAuthn) auth, JSON-file storage, signed session cookies, Web Push notifications, rest-timer alerts, daily workout reminders, live "training now" presence, and the admin dashboard.

It will follow frontend releases of upstream repository.

For frontend issues please open ticket in upstream repository [OpenGym](https://gitea.com/DuarteSantos/openGym). This Project is only replicated Backend in golang and provide slim image with all in one.

[![Dev Build](https://github.com/GAS85/openGym-go/actions/workflows/docker-dev.yml/badge.svg?branch=dev)](https://github.com/GAS85/openGym-go/actions/workflows/docker-dev.yml)
[![Release Build and Push to Dockerhub](https://github.com/GAS85/openGym-go/actions/workflows/docker-release.yml/badge.svg)](https://github.com/GAS85/openGym-go/actions/workflows/docker-release.yml?branch=main)
[![codecov](https://codecov.io/gh/GAS85/openGym-go/branch/main/graph/badge.svg)](https://codecov.io/gh/GAS85/openGym-go/)
![Release](https://img.shields.io/github/actions/workflow/status/GAS85/openGym-go/docker-release.yml?label=release&logo=github)
[![Docker hub](https://img.shields.io/badge/Docker--hub-grey?logo=docker)][docker-hub]
[![Docker Pulls][docker-pulls]][docker-hub]
[![Docker Image Size][docker-size]][docker-hub]

[docker-hub]: https://hub.docker.com/r/gas85/opengym-go
[docker-pulls]: https://img.shields.io/docker/pulls/gas85/opengym-go
[docker-size]: https://img.shields.io/docker/image-size/gas85/opengym-go/latest

➡️➡️➡️ [![Support Original Project](https://img.shields.io/badge/Support_original_Project-blue?logo=buymeacoffee)](https://gitea.com/DuarteSantos/openGym) ⬅️⬅️⬅️

## Layout

| File             | Contents                                                                 |
| :--------------- | :----------------------------------------------------------------------- |
| `main.go`        | config, HTTP server, routing, signed session cookies                     |
| `store.go`       | DB types, atomic JSON writes, per-user state files                       |
| `webauthn.go`    | passkey register/login (`github.com/go-webauthn/webauthn`)               |
| `push.go`        | VAPID + RFC 8291 push encryption (stdlib only), rest timers, day reminder|
| `presence.go`    | live "training now" tracking                                             |
| `handlers.go`    | health/config/me, data sync, push subscribe/test, activity heartbeat     |
| `admin.go`       | admin: user list/drill-down/disable, invites                             |

## Notable differences from the JS version

- **Concurrency**: Node is single-threaded; Go handles requests concurrently, so every access to the in-memory `db` goes through a `sync.RWMutex` (`dbMu`) that has no JS equivalent.
- **Web Push**: implemented directly against the standard library (ECDH via `crypto/ecdh`, HKDF hand-rolled over `crypto/hmac`, AES-128-GCM via `crypto/cipher`) rather than a wrapper library, so there's no extra dependency beyond `go-webauthn`. Verified with a round-trip encrypt/decrypt test against RFC 8291 during development.
- Everything else (route table, session/cookie format, invite codes, reminder cadence, presence TTL) mirrors the original 1:1, including a couple of intentionally-preserved original quirks (e.g. the rest-timer seconds clamp always yields ≥1, so the "seconds required" branch is unreachable in both versions).

## Build & run

```bash
cd app
go build -o opengym-api .

PORT=3000 \
DATA_DIR=/data \
RP_ID=localhost \
ORIGIN=http://localhost:8080 \
RP_NAME=openGym \
ADMIN_UIDS= \
INVITE_ONLY=0 \
ALLOW_GUEST=1 \
SESSION_DAYS=90 \
./opengym-api
```

Same environment variables as the Node version, same semantics.

### Docker

```shell
docker run --name opengym-go \
  -v ./data:/data \
  -v ./data/media/img:/usr/share/nginx/html/img \
  -v ./data/media/gif:/usr/share/nginx/html/gif \
  -p 8080:80 \
  --restart always \
  gas85/opengym-go:latest
```

### Docker compose

Please refer to [docker-compose.yml](docker-compose.yml) file.
