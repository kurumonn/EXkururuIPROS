# exkururuIPROS NGIPS

[Japanese README](README.md)
[4-stack demo note](README.4stack.md)

EXkururuIPROS is the public-distribution NGIPS/NDR component of the EXkururu stack.
The public repository keeps the parts that are valuable to show openly: product surface, dashboard, sensor
layout, ingest pipeline, and local startup flow.

## Public scope

- Lightweight dashboard and API
- Rust sensor layout
- Event ingest and alert workflow
- Threat-intel integration surface
- Local development startup

Production tuning details, scoring logic, rollout rules, and environment-specific operational thresholds are
intentionally excluded from the public distribution.

## Quick Start

```bash
cd /path/to/exkururuIPROS
python3 -m venv .venv
./.venv/bin/pip install -r dashboard/requirements.txt
cp .env.example .env
IPS_ADMIN_TOKEN=change-this-admin-token IPS_DB_PATH=./ips_open.db ./.venv/bin/uvicorn dashboard.app:app --host 127.0.0.1 --port 8787
```

## Public environment variables

- `IPS_DB_PATH`
- `IPS_ADMIN_TOKEN`
- `IPS_BIND_HOST`
- `IPS_BIND_PORT`
- `IPS_DEFAULT_WORKSPACE`

## Security

- Keep secrets and production endpoints out of the repository.
- Use the public examples for development only.
- Place shared deployments behind TLS termination and authenticated reverse proxies.

## License

This repository uses `Personal Developer License v1.0`.
See [LICENSE](LICENSE).
