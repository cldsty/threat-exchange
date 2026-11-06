# Threat Exchange Service

Веб-сервис с REST API для обмена информацией об угрозах.
Реализован на Go по OpenAPI-спецификации.

## Что сделано

| Требование задания | Реализация |
|---|---| 
| REST-сервер по спецификации | [`api/openapi.yaml`](api/openapi.yaml) - единый источник правды. `GET /info/{md5}`, `POST /info`, `PUT /info/{md5}` |
| Дополнение полей и валидация | 16 новых полей ([модель](#модель-угрозы)), двухуровневая валидация: по спецификации (kin-openapi) и бизнес-правила в домене. Также ограничения в БД |
| Юнит и интеграционные тесты | Юнит-тесты всех слоёв, интеграционные - реальный PostgreSQL, TLS/mTLS, весь сервер целиком, `-race`, покрытие ~88% без сгенерированного кода, каждый ответ в HTTP-тестах проверяется по спецификации, fuzz-тесты парсеров |
| Docker | `Dockerfile`, `docker-compose.yml` (БД, миграции, сертификаты, сервис) |
| СУБД и кодогенерация по спеке | PostgreSQL + pgx, миграции goose, `oapi-codegen` генерирует модели, strict-сервер и встроенную спецификацию |
| Документация | Этот README, [`docs/`](docs/) (архитектура, безопасность, решения), godoc-комментарии |
| Дополнительная защита | TLS 1.2+/1.3, опционально mTLS с привязкой ключа к сертификату, ротация сертификата и ключей без перезапуска, API-ключи с ролями (хранятся только хеши), rate-limit по IP и по ключу, лимиты размера и таймауты, security-заголовки, отдельный служебный порт, сервис работает в БД под ролью без права менять схему |

## Технологический стек

| Назначение | Технологии |
|---|---|
| Язык и HTTP | Go 1.27, стандартный `net/http` |
| API и кодогенерация | OpenAPI 3.0, `oapi-codegen`, валидация запросов `kin-openapi` |
| База данных | PostgreSQL 17, драйвер `pgx`, миграции `goose` |
| Защита | TLS/mTLS, API-ключи, rate-limit на `golang.org/x/time/rate` |
| Наблюдаемость | Логи `log/slog` в JSON, метрики Prometheus |
| Развёртывание | Docker, Docker Compose |
| Качество | `testify`, `-race`, fuzz-тесты, `golangci-lint`, `govulncheck`, Trivy, GitHub Actions |

## Быстрый старт

Нужен Docker (Docker Desktop на Windows/macOS).

```bash
docker compose up --build -d --wait
```

Compose сгенерирует dev-сертификаты в `deploy/certs/`, поднимет PostgreSQL с
TLS, применит миграции и запустит сервис на `https://localhost:8443`, а документацию
API на `http://localhost:8090` (только чтение).

Демо-ключи для локального запуска:

| Ключ | Роль |
|---|---|
| `demo-writer-key-change-me` | `writer` - чтение и запись |
| `demo-partner-key-change-me` | `writer` - второй участник обмена |
| `demo-reader-key-change-me` | `reader` - только чтение |

Остановить всё (данные БД сохранятся в volume `pgdata`):

```bash
docker compose down
```

Отдельные запросы: [примеры](#примеры-запросов). Если не запускается: [возможные проблемы](#частые-проблемы).

## Сборка и запуск без Docker

Нужны Go 1.27+ и PostgreSQL.

```bash
# Сборка (на Windows без make: go build -o bin/threat-exchange.exe ./cmd/threat-exchange)
make build

# Сертификаты для разработки и API-ключ
bin/threat-exchange devcerts -dir deploy/certs
bin/threat-exchange keygen -id partner-a -role writer

# Настройка: подставьте адрес своей БД и строку Config entry из вывода keygen
export DB_URL="postgres://user:password@localhost:5432/threats?sslmode=disable"
export AUTH_API_KEYS="partner-a:writer:..."
export TLS_CERT_FILE=deploy/certs/server.crt TLS_KEY_FILE=deploy/certs/server.key

# Миграции и запуск
bin/threat-exchange migrate
bin/threat-exchange serve
```

Собрать только Docker-образ: `docker build -t threat-exchange:local .`

## API

Полное описание - в [`api/openapi.yaml`](api/openapi.yaml)

| Метод | Путь | Роль | Ответы |
|---|---|---|---|
| `GET`, `HEAD` | `/info/{md5}` | reader, writer | 200, 400, 401, 403, 404, 429, 500, 503 |
| `POST` | `/info` | writer | 201, 400, 401, 403, 409, 413, 415, 429, 500, 503 |
| `PUT` | `/info/{md5}` | writer | 200, 400, 401, 403, 404, 409, 412, 413, 415, 428, 429, 500, 503 |

- **Аутентификация:** заголовок `X-API-Key`, без ключа или с неверным - `401`,
  без прав - `403`.
- **`PUT` - полная замена:** необязательные поля, не переданные в запросе,
  сбрасываются к значениям по умолчанию. MD5 берётся из пути, в теле он запрещён.
- **Оптимистичная блокировка:** ответы содержат заголовок `ETag` с номером
  версии записи, например `"2"`. Если передать `If-Match`, а запись уже изменили, вернётся `412`.
- **Совместная работа над записью:** на один MD5 приходится одна запись, менять
  её может любой `writer`. Организация, у которой есть данные об известном MD5,
  получает `409` на `POST`, читает запись, объединяет данные и отправляет `PUT`
  с `If-Match`. Запись, которую последним менял другой ключ, нельзя заменить без
  конкретной версии в `If-Match`: вернётся `428`. Все версии сохраняются в
  таблице `threat_history`. Риски этой модели описаны в
  [`docs/security.md`](docs/security.md#достоверность-данных).
- **Недоступность БД:** `503` с `Retry-After`, запрос можно повторить.
- **Совместимость:** поля исходной спецификации не изменились, для создания и
  замены записи достаточно `md5` и `name`. Новые требования: TLS, заголовок
  `X-API-Key` и запрет лишних полей в теле запроса.
- **Ошибки** имеют единый формат, `request_id` совпадает с заголовком
  `X-Request-ID` и с записью в логе:

```json
{
  "code": "validation_failed",
  "message": "Request validation failed",
  "fields": [{ "field": "last_seen_at", "message": "must not be earlier than first_seen_at" }],
  "request_id": "0f8fad5b-d9cb-469f-a165-70867728950e"
}
```

### Примеры запросов

На Windows см. [возможные проблемы](#возможные-проблемы).

Создать запись:

```bash
curl --cacert deploy/certs/ca.crt https://localhost:8443/info \
  -H "X-API-Key: demo-writer-key-change-me" -H "Content-Type: application/json" \
  -d '{"md5":"44d88612fea8a8f36de82e1278abb02f","name":"EICAR-Test-File",
       "types":["other"],"zone":"red","severity":"low","tlp":"green","confidence":100}'
```

Прочитать запись (регистр MD5 не важен):

```bash
curl --cacert deploy/certs/ca.crt https://localhost:8443/info/44D88612FEA8A8F36DE82E1278ABB02F \
  -H "X-API-Key: demo-reader-key-change-me"
```

Полностью заменить запись с проверкой версии (`ETag` из предыдущего ответа):

```bash
curl --cacert deploy/certs/ca.crt -X PUT https://localhost:8443/info/44d88612fea8a8f36de82e1278abb02f \
  -H "X-API-Key: demo-writer-key-change-me" -H "Content-Type: application/json" \
  -H 'If-Match: "1"' -d '{"name":"EICAR-Test-File","zone":"red","severity":"low","revoked":true}'
```

Все сценарии можно проверить через Postman: импортируйте
[`postman/threat-exchange.postman_collection.json`](postman/threat-exchange.postman_collection.json),
укажите `deploy/certs/ca.crt` в Settings → Certificates → CA Certificates и запустите
коллекцию целиком.

### Служебные адреса

`http://127.0.0.1:8081/healthz`, `/readyz` и `/metrics` доступны только с localhost.

### Модель угрозы

| Поле | Обязательность | Правила |
|---|---|---|
| `md5` | при создании | 32 hex-символа, любой регистр, хранится в нижнем. В `PUT` - из пути |
| `sha1` / `sha256` | нет | 40 / 64 hex-символа, хранится в нижнем регистре. Один `sha256` не может принадлежать двум записям (`409`) |
| `name` | при создании и замене | 1–255 символов, без пробелов по краям, управляющих и невидимых символов (например, `Trojan.Win32.Generic`) |
| `description` | нет | 1–2000 символов, не из одних пробелов, без символов смены направления текста |
| `types` | нет | до 12 значений из словаря без повторов, `[]` допустим: `virus, worm, trojan, backdoor, rootkit, exploit, ransomware, banker, downloader, dropper, spyware, stealer, miner, adware, riskware, hacktool, other` |
| `zone` | нет | `red` (вредоносный), `orange` (подозрительный), `yellow` (рекламное/нежелательное ПО), `green` (угроз нет), `grey` (нет данных, по умолчанию) |
| `severity` | нет | `unknown` (по умолчанию), `low`, `medium`, `high`, `critical`, для `green`/`grey` - только `unknown` |
| `file_size` | нет | целое ≥ 0, байты |
| `first_seen_at` / `last_seen_at` | нет | RFC 3339 с часовым поясом, не раньше 1970 года и не в будущем, `last ≥ first` |
| `tlp` | нет | метка распространения TLP 2.0: `clear`, `green`, `amber` (по умолчанию), `amber+strict`, `red`. Сервер хранит её, но не ограничивает по ней чтение |
| `confidence` | нет | уверенность автора в оценке, целое от 0 до 100 |
| `revoked` | нет | признак отзыва (ложное срабатывание), по умолчанию `false` |
| `created_at` / `updated_at` | только в ответе | ставит сервер |
| `created_by` / `updated_by` | только в ответе | ID API-ключа (аудит) |

Почему поля именно такие - см. [`docs/decisions.md`](docs/decisions.md).

## Конфигурация

Все настройки - переменные окружения. 

| Переменная | По умолчанию | Описание |
|---|---|---|
| `DB_URL` / `DB_URL_FILE` | - (обязательна) | строка подключения PostgreSQL |
| `AUTH_API_KEYS` / `AUTH_API_KEYS_FILE` | - (обязательна) | `id:role:sha256hex` через запятую или перевод строки |
| `AUTH_BIND_CLIENT_CERT` | `false` | ключ принимается только с клиентским сертификатом, у которого Common Name равен `id` ключа (нужен `TLS_CLIENT_CA_FILE`) |
| `TLS_ENABLED` | `true` | `false` - только за TLS-терминирующим прокси |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | - | сертификат и ключ сервера (обязательны при TLS) |
| `TLS_CLIENT_CA_FILE` | - | включает mTLS: клиент обязан предъявить сертификат этого CA |
| `TLS_MIN_VERSION` | `1.2` | `1.2` или `1.3` |
| `HTTP_ADDR` / `OPS_ADDR` | `:8443` / `:8081` | адреса API и служебного сервера |
| `HTTP_MAX_BODY_BYTES` | `65536` | максимальный размер тела запроса |
| `HTTP_READ_HEADER_TIMEOUT`, `HTTP_READ_TIMEOUT`, `HTTP_WRITE_TIMEOUT`, `HTTP_IDLE_TIMEOUT` | `5s`, `10s`, `15s`, `60s` | таймауты сервера |
| `HTTP_HANDLER_TIMEOUT` | `10s` | лимит обработки запроса (распространяется на запросы к БД) |
| `HTTP_SHUTDOWN_TIMEOUT` | `15s` | время на завершение запросов при остановке |
| `HTTP_TRUSTED_PROXIES` | - | CIDR прокси, которым можно доверять `X-Forwarded-For` |
| `RATE_LIMIT_ENABLED` | `true` | включить ограничение частоты |
| `RATE_LIMIT_IP_RPS` / `RATE_LIMIT_IP_BURST` | `50` / `100` | лимит на IP (до аутентификации) |
| `RATE_LIMIT_KEY_RPS` / `RATE_LIMIT_KEY_BURST` | `20` / `40` | лимит на API-ключ |
| `DB_MAX_CONNS`, `DB_MIN_CONNS` | `10`, `1` | размер пула соединений |
| `DB_STATEMENT_TIMEOUT` | `5s` | серверный таймаут SQL-запроса |
| `DB_CONNECT_TIMEOUT` | `2s` | таймаут одной попытки подключения к БД |
| `MIGRATE_ON_START` | `false` | применять миграции при старте (по умолчанию - отдельной командой `migrate`) |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `json` | уровень и формат логов |

### Управление ключами

```bash
docker compose run --rm --no-deps threat-exchange keygen -id partner-a -role writer
# API key (give to the client, shown once): tx_...
# Config entry for AUTH_API_KEYS:        partner-a:writer:5e88...
```

Ключ передаётся клиенту по защищённому каналу, в конфиг попадает только строка с хешем.

Если ключи заданы файлом (`AUTH_API_KEYS_FILE`), сигнал `SIGHUP` перечитывает его
без перезапуска. Для плавной смены ключа добавьте новый с тем же `id` и ролью,
дождитесь перехода клиента и удалите старый: журнал аудита не прервётся.

## Разработка

Нужны Go 1.27+ и Docker. Основные команды (`make help` - полный список):

```bash
make generate          # перегенерировать код из api/openapi.yaml
make test              # юнит-тесты с -race
make db-up             # поднять PostgreSQL на localhost:5432
make test-integration  # юнит + интеграционные тесты
make cover             # отчёт о покрытии (coverage.html)
make fuzz              # fuzz-тесты парсеров недоверенных данных
make lint              # golangci-lint
make up / make down    # весь стек в Docker
```

### Структура проекта

```
api/openapi.yaml               спецификация (источник правды) + конфиг oapi-codegen
cmd/threat-exchange/           точка входа: serve, migrate, keygen, devcerts, healthcheck
internal/api/                  код, сгенерированный из спецификации (не редактируется)
internal/domain/threat/        сущность, перечисления, бизнес-валидация, ошибки
internal/service/              сценарии использования (Get/Create/Replace)
internal/storage/postgres/     репозиторий на pgx + встроенные миграции
internal/storage/memory/       in-memory репозиторий для юнит-тестов
internal/transport/httpapi/    обработчики, маппинг DTO, middleware
internal/auth/                 API-ключи, роли
internal/ratelimit/            token bucket на ключ/IP
internal/server/               сборка приложения, TLS, служебный сервер, graceful shutdown
internal/config/               конфигурация из окружения
internal/devcerts/             генерация dev-сертификатов (без openssl)
deploy/postgres/               создание роли сервиса в БД для compose
postman/                       коллекция Postman со сценариями API
docs/                          архитектура, безопасность, принятые решения
```

## Возможные проблемы

| Симптом | Решение |
|---|---|
| `ports are not available` | Порт занят. Скопируйте `.env.example` в `.env` и задайте другой: `API_PORT`, `DB_PORT`, `OPS_PORT`, `DOCS_PORT` |
| `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` в `curl` на Windows | Добавьте `--ssl-no-revoke`: dev-сертификат нельзя проверить на отзыв, доверие к `ca.crt` при этом проверяется |
| Примеры `curl` не работают в PowerShell | В PowerShell другие кавычки и переносы строк. Запускайте их в Git Bash или WSL |
| Сервис не подключается к БД после обновления со старой версии | Роль сервиса создаётся один раз, вместе с volume. Пересоздайте его: `docker compose down -v`. Данные БД будут удалены |

## Документация

- [Архитектура](docs/architecture.md) - слои, путь запроса, обработка ошибок.
- [Безопасность](docs/security.md) - модель угроз, принятые меры, рекомендации для продакшена.
- [Решения](docs/decisions.md) - почему выбраны именно эти поля, библиотеки и подходы.

## Ограничения и что можно развить

- Rate-limit хранится в памяти процесса: при нескольких репликах нужен общий
  стор (Redis) или лимит на уровне API-gateway.
- Ключи задаются конфигурацией, для большого числа партнёров - хранить в БД
  с API управления, либо перейти на OAuth 2.0 (интерфейс `auth.Authenticator`
  позволяет подключить JWT без изменения HTTP-слоя).
- Нет поиска по `sha1`/`sha256` и списков с пагинацией - в задании их нет,
  но схема БД это допускает.
- История изменений доступна только в БД: отдельного эндпоинта в задании нет.
- Метка `tlp` передаётся получателям, но сервер не ограничивает по ней чтение:
  для этого ключи нужно привязать к организациям и уровням доступа.
- На один MD5 приходится один вердикт. Отдельные отчёты от каждой организации
  описаны как следующий шаг в [`docs/decisions.md`](docs/decisions.md).
