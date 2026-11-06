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
| Extended model, validation | 16 new fields ([model](#threat-model)); two-level validation: by the spec (kin-openapi) and business rules in the domain; database constraints as the last line of defence |
| Unit and integration tests | Unit tests for every layer; integration tests with real PostgreSQL, TLS/mTLS and the fully assembled server; `-race`; ~88% coverage excluding generated code; every HTTP test response is checked against the spec; fuzz tests of the parsers |
| Docker | Multi-stage `Dockerfile` (distroless, non-root), `docker-compose.yml` (DB, migrations, certificates, service) |
| DBMS and code generation | PostgreSQL + pgx, goose migrations embedded into the binary; `oapi-codegen` generates models, a strict server and the embedded spec |
| Documentation | This README, [`docs/`](docs/) (architecture, security, decisions, in Russian), godoc comments |
| Extra protection | TLS 1.2+/1.3, optional mTLS, certificate rotation without restart; role-based API keys (only hashes are stored); rate limiting per IP and per key; size limits and timeouts; security headers; separate ops port |

## Technology stack

| Purpose | Technologies |
|---|---|
| Language and HTTP | Go 1.27, standard `net/http` |
| API and code generation | OpenAPI 3.0, `oapi-codegen`, request validation with `kin-openapi` |
| Database | PostgreSQL 17, `pgx` driver, `goose` migrations |
| Security | TLS/mTLS, API keys, rate limiting with `golang.org/x/time/rate` |
| Observability | JSON logs with `log/slog`, Prometheus metrics |
| Deployment | Docker (distroless image), Docker Compose |
| Quality | `testify`, `-race`, fuzz tests, `golangci-lint`, `govulncheck`, Trivy, GitHub Actions |

## Quick start

Only Docker is required (Docker Desktop on Windows/macOS).

```bash
docker compose up --build -d --wait
```

Compose generates development certificates into `deploy/certs/`, starts
PostgreSQL with TLS, applies migrations and serves on `https://localhost:8443`.
All ports are published on localhost only, because the demo keys below are public.

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
environment variables or an `.env` file (see `.env.example`): `API_PORT` for the
API (default `8443`), `DB_PORT` for PostgreSQL (`5432`), `OPS_PORT` for the ops
endpoints (`8081`).

Stop with `docker compose down` (database data stays in the `pgdata` volume).
The database role of the service is created once, together with the volume, so
after upgrading from an older version recreate it with `docker compose down -v`.

## Build and run without Docker

Requires Go 1.27+ and PostgreSQL.

```bash
# Build (on Windows without make: go build -o bin/threat-exchange.exe ./cmd/threat-exchange)
make build

# Development certificates and an API key
bin/threat-exchange devcerts -dir deploy/certs
bin/threat-exchange keygen -id partner-a -role writer

# Configuration: use your database address and the Config entry line printed by keygen
export DB_URL="postgres://user:password@localhost:5432/threats?sslmode=disable"
export AUTH_API_KEYS="partner-a:writer:..."
export TLS_CERT_FILE=deploy/certs/server.crt TLS_KEY_FILE=deploy/certs/server.key

# Migrations and start
bin/threat-exchange migrate
bin/threat-exchange serve
```

To build only the Docker image: `docker build -t threat-exchange:local .`

## API

See [`api/openapi.yaml`](api/openapi.yaml) for the full contract (it opens in
[Swagger Editor](https://editor.swagger.io/)).

| Method | Path | Role | Responses |
|---|---|---|---|
| `GET`, `HEAD` | `/info/{md5}` | reader, writer | 200, 400, 401, 403, 404, 429, 500, 503 |
| `POST` | `/info` | writer | 201, 400, 401, 403, 409, 413, 415, 429, 500, 503 |
| `PUT` | `/info/{md5}` | writer | 200, 400, 401, 403, 404, 409, 412, 413, 415, 428, 429, 500, 503 |

- **Authentication:** `X-API-Key` header; missing or wrong key → `401`,
  insufficient role → `403`.
- **`PUT` is a full replacement:** optional fields omitted from the request are
  reset to defaults. The MD5 comes from the path and is rejected in the body.
- **Optimistic concurrency:** responses carry an `ETag` header with the
  record version number, e.g. `"2"`; with `If-Match`, a concurrent modification
  yields `412`.
- **Working on a shared record:** one MD5 has one record, and any `writer` may
  change it. An organization with data about a known MD5 gets `409` on `POST`,
  reads the record, merges the data and sends `PUT` with `If-Match`. A record
  last modified by another key cannot be replaced without a specific version in
  `If-Match`: the answer is `428`. All versions are kept in the `threat_history`
  table. See `docs/security.md` for the risks of this model.
- **Database outage:** `503` with `Retry-After`; the request can be retried.
- **Compatibility:** the fields of the original spec are unchanged, `md5` and
  `name` are enough to create and replace a record. New requirements: TLS, the
  `X-API-Key` header and no unknown fields in the request body.
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
| `sha1` / `sha256` | no | 40 / 64 hex characters, stored lower-case. One `sha256` cannot belong to two records (`409`) |
| `name` | on create and replace | 1–255 characters, no surrounding whitespace, control or invisible characters (e.g. `Trojan.Win32.Generic`) |
| `description` | no | 1–2000 characters, not whitespace-only, no characters that change the text direction |
| `types` | no | up to 12 unique values from the vocabulary, `[]` allowed: `virus, worm, trojan, backdoor, rootkit, exploit, ransomware, banker, downloader, dropper, spyware, stealer, miner, adware, riskware, hacktool, other` |
| `zone` | no | `red` (malicious), `orange` (suspicious), `yellow` (adware/PUA), `green` (clean), `grey` (no data, default) |
| `severity` | no | `unknown` (default), `low`, `medium`, `high`, `critical`; only `unknown` for `green`/`grey` |
| `file_size` | no | integer ≥ 0, bytes |
| `first_seen_at` / `last_seen_at` | no | RFC 3339 with time zone; not before 1970 and not in the future; `last ≥ first` |
| `tlp` | no | TLP 2.0 distribution label: `clear`, `green`, `amber` (default), `amber+strict`, `red`. The server stores it but does not restrict reads by it |
| `confidence` | no | author's confidence in the assessment, integer from 0 to 100 |
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
| `AUTH_BIND_CLIENT_CERT` | `false` | accept a key only with a client certificate whose Common Name equals the key `id` (needs `TLS_CLIENT_CA_FILE`) |
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
| `DB_CONNECT_TIMEOUT` | `2s` | timeout of one attempt to connect to the database |
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

When keys come from a file (`AUTH_API_KEYS_FILE`), `SIGHUP` rereads it without a
restart. To replace a key smoothly, add the new one with the same `id` and role,
wait for the client to switch and remove the old one: the audit trail stays intact.

## Development

Requires Go 1.27+ and Docker. Main targets (`make help` lists all):

```bash
make generate          # regenerate code from api/openapi.yaml
make test              # unit tests with -race
make db-up             # PostgreSQL on localhost:5432
make test-integration  # unit + integration tests
make fuzz              # fuzz tests of the parsers of untrusted input
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
deploy/postgres/               creation of the service's database role for compose
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
- The history of changes is available only in the database: the assignment has
  no endpoint for it.
- The `tlp` label reaches the readers, but the server does not restrict reads by
  it: that needs keys tied to organizations and access levels.
- One MD5 has one verdict. Separate reports per organization are described as
  the next step in `docs/decisions.md`.
