# Threat Exchange Service

[Русский](README.md) | **English**

A web service with a REST API for exchanging threat information keyed by a
file's MD5 hash. Written in Go from the OpenAPI specification of the
assignment. The threat model is extended and partially modelled after
[Kaspersky Threat Intelligence Portal](https://opentip.kaspersky.com/): colour
zones, first/last seen, file size, the `X-API-Key` header.

## What is implemented

| Requirement | Implementation |
|---|---|
| REST server from the spec | [`api/openapi.yaml`](api/openapi.yaml) is the single source of truth; `GET /info/{md5}`, `POST /info`, `PUT /info/{md5}` |
| Extended model, validation | 15 new fields ([model](#threat-model)); two-level validation: by the spec (kin-openapi) and business rules in the domain; database constraints as the last line of defence |
| Unit and integration tests | Unit tests for every layer; integration tests with real PostgreSQL, TLS/mTLS and the fully assembled server; `-race`; ~88% coverage excluding generated code |
| Docker | Multi-stage `Dockerfile` (distroless, non-root), `docker-compose.yml` (DB, migrations, certificates, service) |
| DBMS and code generation | PostgreSQL + pgx, goose migrations embedded into the binary; `oapi-codegen` generates models, a strict server and the embedded spec |
| Documentation | This README, [`docs/`](docs/) (architecture, security, decisions, in Russian), godoc comments |
| Extra protection | TLS 1.2+/1.3, optional mTLS, certificate rotation without restart; role-based API keys (only hashes are stored); rate limiting per IP and per key; size limits and timeouts; security headers; separate ops port |

## Quick start

Only Docker is required (Docker Desktop on Windows/macOS).

```bash
docker compose up --build -d --wait
```

Compose starts PostgreSQL, generates development certificates into
`deploy/certs/`, applies migrations and serves on `https://localhost:8443`.

Demo keys (local use only):

| Key | Role |
|---|---|
| `demo-writer-key-change-me` | `writer` — read and write |
| `demo-reader-key-change-me` | `reader` — read only |

```bash
# Create
curl --cacert deploy/certs/ca.crt https://localhost:8443/info \
  -H "X-API-Key: demo-writer-key-change-me" -H "Content-Type: application/json" \
  -d '{"md5":"44d88612fea8a8f36de82e1278abb02f","name":"EICAR-Test-File",
       "types":["other"],"zone":"red","severity":"low"}'

# Read (MD5 is case-insensitive)
curl --cacert deploy/certs/ca.crt -H "X-API-Key: demo-reader-key-change-me" \
  https://localhost:8443/info/44D88612FEA8A8F36DE82E1278ABB02F

# Replace with a version check (ETag from the previous response)
curl --cacert deploy/certs/ca.crt -X PUT https://localhost:8443/info/44d88612fea8a8f36de82e1278abb02f \
  -H "X-API-Key: demo-writer-key-change-me" -H "Content-Type: application/json" \
  -H 'If-Match: "1"' -d '{"name":"EICAR-Test-File","zone":"red","severity":"low","revoked":true}'
```

> **Windows (PowerShell):** use `curl.exe` instead of `curl` and escape the
> JSON quotes, or import `api/openapi.yaml` into Postman/Insomnia. The `curl.exe`
> bundled with Windows cannot check revocation of the development certificate
> (`CERT_TRUST_REVOCATION_STATUS_UNKNOWN`): add `--ssl-no-revoke`; trust in
> `ca.crt` is still verified.

Ops endpoints (localhost only): `http://127.0.0.1:8081/healthz`, `/readyz`,
`/metrics`.

If a port is taken (`ports are not available` error), choose another one via
environment variables or an `.env` file (see `.env.example`): `DB_PORT` for
PostgreSQL (default `5432`), `OPS_PORT` for the ops endpoints (default `8081`).

Stop with `docker compose down` (database data stays in the `pgdata` volume).

## API

See [`api/openapi.yaml`](api/openapi.yaml) for the full contract (it opens in
[Swagger Editor](https://editor.swagger.io/)).

| Method | Path | Role | Responses |
|---|---|---|---|
| `GET` | `/info/{md5}` | reader, writer | 200, 400, 401, 403, 404, 429, 500 |
| `POST` | `/info` | writer | 201, 400, 401, 403, 409, 413, 429, 500 |
| `PUT` | `/info/{md5}` | writer | 200, 400, 401, 403, 404, 412, 413, 429, 500 |

- **Authentication:** `X-API-Key` header; missing or wrong key → `401`,
  insufficient role → `403`.
- **`PUT` is a full replacement:** optional fields omitted from the request are
  reset to defaults. The MD5 comes from the path and is rejected in the body.
- **Optimistic concurrency:** responses carry an `ETag` header with the
  record version number, e.g. `"2"`; with `If-Match`, a concurrent modification
  yields `412`.
- **Compatibility:** a request following the original spec (`md5` + `name`)
  works unchanged.
- **Errors** share one format; `request_id` equals the `X-Request-ID` header
  and the log entry:

```json
{
  "code": "validation_failed",
  "message": "Request validation failed",
  "fields": [{ "field": "last_seen_at", "message": "must not be earlier than first_seen_at" }],
  "request_id": "0f8fad5b-d9cb-469f-a165-70867728950e"
}
```

### Threat model

| Field | Required | Rules |
|---|---|---|
| `md5` | on create | 32 hex characters, any case, stored lower-case. In `PUT` taken from the path |
| `sha1` / `sha256` | no | 40 / 64 hex characters, stored lower-case |
| `name` | on create and replace | 1–255 characters, no surrounding whitespace or control characters (e.g. `Trojan.Win32.Generic`) |
| `description` | no | 1–2000 characters, not whitespace-only |
| `types` | no | up to 12 unique values from the vocabulary, `[]` allowed: `virus, worm, trojan, backdoor, rootkit, exploit, ransomware, banker, downloader, dropper, spyware, stealer, miner, adware, riskware, hacktool, other` |
| `zone` | no | `red` (malicious), `orange` (suspicious), `yellow` (adware/PUA), `green` (clean), `grey` (no data, default) |
| `severity` | no | `unknown` (default), `low`, `medium`, `high`, `critical`; only `unknown` for `green`/`grey` |
| `file_size` | no | integer ≥ 0, bytes |
| `first_seen_at` / `last_seen_at` | no | RFC 3339 with time zone; not in the future; `last ≥ first` |
| `revoked` | no | retraction flag (false positive), default `false` |
| `created_at` / `updated_at` | response only | set by the server |
| `created_by` / `updated_by` | response only | API key ID (audit) |

## Configuration

Everything is configured with environment variables; secrets may be passed as
files (`*_FILE`) for Docker/Kubernetes secrets. Invalid configuration is
reported at start-up and the process exits immediately.

| Variable | Default | Description |
|---|---|---|
| `DB_URL` / `DB_URL_FILE` | — (required) | PostgreSQL connection string |
| `AUTH_API_KEYS` / `AUTH_API_KEYS_FILE` | — (required) | `id:role:sha256hex`, separated by commas or newlines |
| `TLS_ENABLED` | `true` | `false` only behind a TLS-terminating proxy |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | — | server certificate and key (required with TLS) |
| `TLS_CLIENT_CA_FILE` | — | enables mTLS: clients must present a certificate from this CA |
| `TLS_MIN_VERSION` | `1.2` | `1.2` or `1.3` |
| `HTTP_ADDR` / `OPS_ADDR` | `:8443` / `:8081` | API and ops listen addresses |
| `HTTP_MAX_BODY_BYTES` | `65536` | request body size limit |
| `HTTP_READ_HEADER_TIMEOUT`, `HTTP_READ_TIMEOUT`, `HTTP_WRITE_TIMEOUT`, `HTTP_IDLE_TIMEOUT` | `5s`, `10s`, `15s`, `60s` | server timeouts |
| `HTTP_HANDLER_TIMEOUT` | `10s` | request processing deadline (propagates to DB queries) |
| `HTTP_SHUTDOWN_TIMEOUT` | `15s` | grace period on shutdown |
| `HTTP_TRUSTED_PROXIES` | — | CIDRs of proxies whose `X-Forwarded-For` is trusted |
| `RATE_LIMIT_ENABLED` | `true` | enable rate limiting |
| `RATE_LIMIT_IP_RPS` / `RATE_LIMIT_IP_BURST` | `50` / `100` | per-IP limit (before authentication) |
| `RATE_LIMIT_KEY_RPS` / `RATE_LIMIT_KEY_BURST` | `20` / `40` | per-API-key limit |
| `DB_MAX_CONNS`, `DB_MIN_CONNS` | `10`, `1` | connection pool size |
| `DB_STATEMENT_TIMEOUT` | `5s` | server-side SQL statement timeout |
| `MIGRATE_ON_START` | `false` | apply migrations on start (default: separate `migrate` command) |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `json` | log level and format |

### Key management

```bash
docker compose run --rm --no-deps threat-exchange keygen -id partner-a -role writer
# API key (give to the client, shown once): tx_...
# Config entry for AUTH_API_KEYS:        partner-a:writer:5e88...
```

Hand the key to the client over a secure channel; only the hashed entry goes
into the configuration.

## Development

Requires Go 1.27+ and Docker. Main targets (`make help` lists all):

```bash
make generate          # regenerate code from api/openapi.yaml
make test              # unit tests with -race
make db-up             # PostgreSQL on localhost:5432
make test-integration  # unit + integration tests
make cover             # coverage report (coverage.html)
make lint              # golangci-lint
make up / make down    # whole stack in Docker
```

Without `make` (e.g. on Windows):

```bash
go test -race ./...
docker compose up -d --wait db
# PowerShell: $env:TEST_DB_URL="postgres://threats:threats-dev-password@127.0.0.1:5432/threats?sslmode=disable"
TEST_DB_URL=postgres://threats:threats-dev-password@127.0.0.1:5432/threats?sslmode=disable \
  go test -race -tags integration ./...
```

If PostgreSQL runs on another port (`DB_PORT`), use it in `TEST_DB_URL` as well.

Integration tests create a separate temporary database per test and drop it
afterwards, so they run in parallel against a shared server.

### Layout

```
api/openapi.yaml               specification (source of truth) + oapi-codegen config
cmd/threat-exchange/           entry point: serve, migrate, keygen, devcerts, healthcheck
internal/api/                  code generated from the spec (do not edit)
internal/domain/threat/        entity, enums, business validation, errors
internal/service/              use cases (Get/Create/Replace)
internal/storage/postgres/     pgx repository + embedded migrations
internal/storage/memory/       in-memory repository for unit tests
internal/transport/httpapi/    handlers, DTO mapping, middleware
internal/auth/                 API keys, roles
internal/ratelimit/            per-key/IP token bucket
internal/server/               composition root, TLS, ops server, graceful shutdown
internal/config/               environment configuration
internal/devcerts/             development certificate generation (no openssl needed)
docs/                          architecture, security, decisions
```

## Limitations and possible extensions

- Rate limiting state is per process; several replicas need a shared store
  (Redis) or limiting at the API gateway.
- Keys come from configuration; for many partners store them in the database
  with a management API, or switch to OAuth 2.0 (the `auth.Authenticator`
  interface allows plugging in JWT without touching the HTTP layer).
- No lookup by `sha1`/`sha256` and no paginated listing — not in the
  assignment, but the schema allows it.
