# Changelog

This public repository keeps only high-level release notes.
Operational rollout details, tuning values, and environment-specific hardening notes are maintained outside
the public distribution.

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
