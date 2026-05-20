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

## Covered Vulnerabilities & CVSS Information

Vulnerabilities for which this IPS currently holds detection signatures, scoring rules, or automated mitigation.

| ID | Name | CVSS v3.1 Score | Severity | Response |
|---|---|---|---|---|
| CVE-PENDING-PINTHEFT | PinTheft: Linux Kernel LPE via RDS zerocopy + io_uring | 7.8 | High | Detect + Sensor auto-remediation |
| CVE-2026-42945 | nginx Remote Code Execution | — | — | Detect + patch recommendation |

---

### CVE-PENDING-PINTHEFT — PinTheft Linux Kernel LPE

**Summary**  
A local privilege escalation (LPE) in the Linux kernel's RDS (Reliable Datagram Sockets) subsystem.  
A zerocopy refcount bug in `rds_message_zcopy_from_user()` is exploited via io_uring to drain page references, repurpose freed pages as SUID binary page cache, and obtain a root shell.

| Field | Value |
|---|---|
| **Disclosed** | 2026-05-20 |
| **CVE ID** | CVE-PENDING-PINTHEFT (assignment pending) |
| **CVSS v3.1 Score** | **7.8 (High)** |
| **CVSS Vector** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Impact** | Confidentiality, Integrity, Availability — all High |
| **Attack Vector** | Local (AV:L) |
| **Attack Complexity** | Low (AC:L) |
| **Privileges Required** | Low — reachable by a normal user (PR:L) |
| **User Interaction** | None (UI:N) |
| **Scope** | Unchanged (S:U) |
| **Affected configurations** | Linux kernels with `CONFIG_RDS`, `CONFIG_RDS_TCP`, and `CONFIG_IO_URING` enabled |
| **Mitigation** | Unload `rds_tcp` and `rds` modules + add `/etc/modprobe.d/` blacklist entries |

**CVSS vector breakdown**

```
CVSS:3.1/AV:L / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:H
         ^^^^   ^^^^   ^^^^   ^^^^   ^^^   ^^^   ^^^   ^^^
         Local  Low    Low    None   Unch  High  High  High
```

**How this IPS responds**

- *Detection*: The `kernel_lpe_pintheft` signature family assigns a CVSS-aligned high score.  
  Multi-stage matching covers payload hints including `pintheft`, `rds_zcopy`, `rds_message_zcopy_from_user`, and `iouring_lpe`.
- *Auto-remediation*: PinTheft events are detected at ingest time. The dashboard automatically queues a `kernel_module_blacklist` action targeting `rds_tcp,rds`.  
  When the sensor runs with `IPS_ALLOW_KERNEL_HARDENING=1` and `IPS_APPLY_MODE=nft`, it writes the modprobe blacklist and runs `rmmod` automatically.  
  The remediation action is delivered even when the WAF is disabled — it uses a dedicated path that bypasses the IP-block WAF gate.

---

### CVE-2026-42945 — nginx Remote Code Execution

| Field | Value |
|---|---|
| **Patched versions** | mainline 1.31.0+ / stable 1.30.1+ |
| **Response** | On probe detection, the IPS checks the server's nginx version and recommends block-source or urgent-patch accordingly |

---

## Security

- Keep secrets and production endpoints out of the repository.
- Use the public examples for development only.
- Place shared deployments behind TLS termination and authenticated reverse proxies.

## License

This repository uses `Personal Developer License v1.0`.
See [LICENSE](LICENSE).
