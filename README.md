# exkururuIPROS NGIPS

[English README](README.en.md)
[4-stack demo note](README.4stack.md)

EXkururuIPROS is a public-distribution-focused NGIPS/NDR component for low-resource environments.
This repository keeps the product surface that is useful to evaluate publicly: dashboard UI, sensor layout,
event ingest, alert workflow, and local development entry points.

## Public scope

- Lightweight dashboard and API
- Rust sensor layout for edge enforcement
- Event ingest and incident-oriented workflow
- Threat-intel integration surface
- Local development and demo startup

Implementation details that directly encode production tuning, scoring, rollout strategy, and operational
thresholds are intentionally excluded from the public distribution.

## Architecture

```text
Internet
   |
Edge Enforcement
   |
Rust Sensor
   |
Event Pipeline
   |
Incident Engine
   |
Dashboard
```

## Capabilities

- Multi-sensor operation
- Alert aggregation
- Threat-intel enrichment surface
- SOC/XDR/EDR integration panel
- Lightweight flow-oriented network detection

## Quick Start

```bash
cd /path/to/exkururuIPROS
python3 -m venv .venv
./.venv/bin/pip install -r dashboard/requirements.txt
cp .env.example .env
IPS_ADMIN_TOKEN=change-this-admin-token IPS_DB_PATH=./ips_open.db ./.venv/bin/uvicorn dashboard.app:app --host 127.0.0.1 --port 8787
```

## Environment

Public examples intentionally expose only minimum bootstrap variables.
Production thresholds, exclusion lists, rollout defaults, and environment-specific integration values should
be managed outside the public repository.

- `IPS_DB_PATH`
- `IPS_ADMIN_TOKEN`
- `IPS_BIND_HOST`
- `IPS_BIND_PORT`
- `IPS_DEFAULT_WORKSPACE`

## Integration

The dashboard can present a live integration panel for adjacent products such as XDR, SOC, and EDR.
Only the integration surface is documented in public; environment-specific endpoints and credentials should
be supplied privately.

## Security

- Keep secrets out of the repository.
- Bind local services to trusted interfaces only.
- Put the dashboard behind TLS termination and authenticated reverse proxying in shared environments.
- Treat public sample settings as development defaults only.

## License

This repository uses `Personal Developer License v1.0`.
See [LICENSE](LICENSE).
