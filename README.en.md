# exkururuIPROS NGIPS

[Japanese README](README.md)
[4-stack demo note](README.4stack.md)

EXkururuIPROS is the public-distribution NGIPS/NDR component of the EXkururu stack.
The public repository keeps the parts that are valuable to show openly: product surface, dashboard, sensor
layout, ingest pipeline, and local startup flow.

This README is for public distribution. It does not include secrets or private operational know-how.

## Public scope

- Lightweight dashboard and API
- Rust sensor layout
- Event ingest and alert workflow
- Threat-intel integration surface
- Local development startup

Production tuning details, scoring logic, rollout rules, and environment-specific operational thresholds are
intentionally excluded from the public distribution.

## Not included in the public release

- Production shared keys, tokens, certificates, and target URLs
- Real corpus locations, detailed evaluation procedures, and customer data
- Internal thresholds, exclusion rules, tuning values, and rollout defaults
- Private runbooks and operational procedures from real projects
- Internal benchmark / quality gate logs and tuning notes

## Quick Start

```bash
cd /path/to/exkururuIPROS
python3 -m venv .venv
./.venv/bin/pip install -r requirements-dev.txt
cp .env.example .env
IPS_ADMIN_TOKEN=change-this-admin-token IPS_DB_PATH=./ips_open.db ./.venv/bin/uvicorn dashboard.app:app --host 127.0.0.1 --port 8787
```

Docker is the easiest way to run the public package.
`docker-compose.yml` is kept only for legacy compatibility; `docker-compose.yaml` is the recommended file.

```bash
cd /path/to/exkururuIPROS
cp .env.example .env
docker compose -f docker-compose.yaml up --build
```

Open `http://127.0.0.1:8787` after startup.

## Tests

```bash
cd /path/to/exkururuIPROS
./.venv/bin/pytest -q
```

## Public environment variables

- `IPS_DB_PATH`
- `IPS_ADMIN_TOKEN`
- `IPS_BIND_HOST`
- `IPS_BIND_PORT`
- `IPS_DEFAULT_WORKSPACE`
- `IPS_REQUIRE_NONCE` (default: `1`)
- `IPS_SIGNATURE_MAX_SKEW_SEC` (default: `300`)
- `IPS_REPLAY_TTL_SEC` (default: `310`)
- `IPS_REPLAY_BACKEND` (`auto` / `redis` / `memory`, default: `auto`)
- `IPS_REDIS_URL` (set this to enable the shared replay cache)
- `IPS_REPLAY_FALLBACK_TO_MEMORY` (default: `1`)
- `IPS_REPLAY_CACHE_MAX_ITEMS` (default: `200000`)

When `IPS_REPLAY_BACKEND=redis` and `IPS_REDIS_URL` are set, replay checks use Redis as a shared cache.
If Redis fails, the code falls back to in-memory replay tracking when `IPS_REPLAY_FALLBACK_TO_MEMORY=1`.

## Security

- Keep secrets and production endpoints out of the repository.
- Use the public examples for development only.
- Place shared deployments behind TLS termination and authenticated reverse proxies.

## License

This repository uses `Personal Developer License v1.0`.
See [LICENSE](LICENSE).
