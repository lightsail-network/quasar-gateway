# Quasar Gateway

A high-performance gateway service that provides API key validation and request proxying functionality.

## Quick Start

```bash
# Build
go build -o bin/gateway ./cmd

# Copy example config
cp config_example.toml config.toml

# Edit configuration
nano config.toml

# Run
./bin/gateway --config config.toml
```

The config is validated at startup: missing required values (e.g. `rpc.url`, `auth.service_url`) or unparseable `QUASAR_*` environment variables cause the gateway to exit with an error instead of failing on the first request.

### Environment Variables

| Variable                              | Description                              | Example                    |
| ------------------------------------- | ---------------------------------------- | -------------------------- |
| `QUASAR_CONFIG_PATH`                  | Path to config file                      | `/path/to/config.toml`     |
| `QUASAR_SERVER_HOST`                  | Server bind address                      | `0.0.0.0`                  |
| `QUASAR_SERVER_PORT`                  | Server port                              | `8080`                     |
| `QUASAR_SERVER_HEALTH_PORT`           | Health check server port                 | `8081`                     |
| `QUASAR_SERVER_GRACEFUL_SHUTDOWN_SEC` | Graceful shutdown wait time              | `30`                       |
| `QUASAR_SERVER_TYPE`                  | Gateway type                             | `rpc` or `s3`              |
| `QUASAR_RPC_URL`                      | Backend RPC URL                          | `http://localhost:8545`    |
| `QUASAR_S3_ENDPOINT`                  | S3 endpoint URL                          | `https://s3.amazonaws.com` |
| `QUASAR_S3_REGION`                    | S3 region                                | `us-east-1`                |
| `QUASAR_S3_BUCKET`                    | S3 bucket name                           | `my-bucket`                |
| `QUASAR_S3_ACCESS_KEY_ID`             | S3 access key ID                         | `AKIAIOSFODNN7EXAMPLE`     |
| `QUASAR_S3_SECRET_KEY`                | S3 secret access key                     | `wJalrXUtnFEMI/K7MDENG...` |
| `QUASAR_AUTH_SERVICE_URL`             | Auth service base URL                    | `http://localhost:9090`    |
| `QUASAR_AUTH_SERVICE_TOKEN`           | Auth service token                       | `secret-token`             |
| `QUASAR_AUTH_CACHE_EXPIRATION`        | Cache TTL (seconds)                      | `300`                      |
| `QUASAR_AUTH_HTTP_TIMEOUT`            | HTTP timeout (seconds)                   | `5`                        |
| `QUASAR_AUTH_CACHE_SIZE`              | Max cache entries                        | `10000`                    |
| `QUASAR_AUTH_FAIL_OPEN`               | Allow requests when auth service is down | `false` (default)          |

## API Endpoints

### RPC and S3 Proxy

- **URL**: `:8080/` (all paths)
- **Method**: `Any`
- **Authentication**: 
  - Header: `Authorization: Bearer <api-key>`
  - URL (RPC only): `/:8080/<api-key>` (token in path, path rewritten to root)
- **CORS**: handled by the gateway itself — `OPTIONS` preflight requests are answered with `204` and skip authentication; all responses carry `Access-Control-Allow-Origin: *`
- **S3 mode**: only `GET`/`HEAD` are allowed; `Range`, `If-None-Match`, and `If-Modified-Since` headers are passed through, so resumable downloads (206) and cache revalidation (304) work

### Health Check

- **URL**: `:8081/health` (separate port)
- **Method**: `GET`
- **Authentication**: None required

## Usage

```bash
# Health check (no auth required)
curl http://localhost:8081/health

# RPC request with header authentication
curl -H "Authorization: Bearer your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"someMethod"}' \
     http://localhost:8080/

# RPC request with URL authentication (token in path)
curl -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"someMethod"}' \
     http://localhost:8080/your-api-key

# S3 request (header authentication only)
curl -H "Authorization: Bearer your-api-key" \
     http://localhost:8080/path/to/file.txt
```

## Auth Service API

Your auth service must implement:

**POST** `/validate`

**Headers:**

```
Authorization: Bearer <service-token>
Content-Type: application/json
```

**Request:**

```json
{
  "key_secret": "user-api-key"
}
```

**Response:**

```json
{
  "valid": true
}
```

## Operational Notes

- `fail_open = true` only covers the auth service being **unreachable or broken** (network errors, 5xx). An explicit 4xx rejection from the auth service always results in 401, regardless of `fail_open`.
- Validation results are cached for `cache_expiration` seconds (default 300), so revoking an API key can take up to that long to take effect.
- With URL token authentication the API key appears in the request path — make sure access logs of any proxy in front (e.g. Caddy) are protected or masked accordingly.
