# Changelog

This public repository keeps only high-level release notes.
Operational rollout details, tuning values, and environment-specific hardening notes are maintained outside
the public distribution.

## 0.3.3 - 2026-06-06

- **Security**: Added WAF/IPS detection signatures for the HTTP/2 Bomb L7 DoS (CVE-2026-49975, disclosed 2026-06-03)
  - `storage.py`: `_apply_http2_bomb_detection()` classifies HTTP/2 HPACK compression-table amplification
    and Slowloris-style connection holding from sensor telemetry (header/HPACK-ref flood, oversized seeded
    header, dynamic-table size, decompression amplification, held memory, connection hold time)
  - Signatures: `HTTP2-BOMB-HPACK-001`, `HTTP2-BOMB-SLOWLORIS-001`, `HTTP2-BOMB-001`, `HTTP2-BOMB-SIGNAL-001`
    (profile `H2DP-001`); thresholds env-overridable via `IPS_H2_*`
  - `storage.py`: `_auto_enqueue_http2_bomb_mitigation()` queues per-source-IP block actions (WAF-gated, 24h dedup, audited)
  - `storage.py`: `_is_high_risk_signature()` flags `http2-bomb`/`hpack`/`bomb`; `mythos_defense_summary()` reports an `http2_bomb` rollup
  - `insert_security_events()` return payload now includes `http2_bomb_queued`

## 0.3.2 - 2026-05-20

- **Security**: Added detection signatures for PinTheft Linux Kernel LPE (2026-05-20)
  - `storage.py`: `_signature_family()` now routes `kernel_lpe`/`pintheft`/`lpe` signatures to the `kernel_lpe` family
  - `storage.py`: `_is_high_risk_signature()` flags `lpe`, `pintheft`, `privilege_escalation`, `kernel_exploit`, `iouring_abuse` as high-risk
  - `vuln.py`: Added `_LINUX_KERNEL_LPE_MITIGATED` registry for module-blacklist-based mitigations
  - `vuln.py`: `classify_cve_for_server()` now evaluates kernel LPE CVEs via `rds_module`/`rds_mitigation` component status

## 0.3.1 - 2026-03-10

- Public repository scope reviewed and reduced
- Bootstrap documentation simplified
- Sensitive operational notes removed from the public tree

## 0.3.0 - 2026-03-09

- Dashboard and sensor public distribution refreshed
- Public test data and sample threat-intel feed retained for evaluation

## 0.1.0 - 2026-03-08

- Initial public-distribution split from the larger internal stack
