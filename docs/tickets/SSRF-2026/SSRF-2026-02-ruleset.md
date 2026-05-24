# SSRF-2026-02 — IPS ルールセット SSRF-001〜014 投入

- Status: TODO
- Priority: P1
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-99`

## 概要

詳細設計書 §3.11 の IPS ルール定義を EXkururuIPROS のルール体系に投入する。

## ルール (抜粋)

```json
{
  "rule_id": "SSRF-001",
  "title": "Dangerous URL scheme in request parameter",
  "severity": "high",
  "match": {
    "param_names": ["url","target","redirect","callback","webhook","endpoint"],
    "patterns": ["file:","gopher:","dict:","ldap:","smb:","data:","javascript:"]
  },
  "action": "block",
  "score": 100
}
```

```json
{
  "rule_id": "SSRF-006",
  "title": "DNS rebinding suspected",
  "severity": "critical",
  "signal": {"condition": "resolved_ip_changed_between_validation_and_fetch"},
  "action": "block",
  "score": 100
}
```

```json
{
  "rule_id": "SSRF-012",
  "title": "Application attempted egress to private address",
  "severity": "critical",
  "signal": {
    "source": "egress_firewall",
    "dst_ip_class": ["private","loopback","link_local","metadata"]
  },
  "action": "incident",
  "score": 100
}
```

## タスク細分化

- [ ] `dashboard/rules/ssrf.json` (or equivalent) にルール 14 件を投入
- [ ] ルールローダー (`dashboard/parser.py` 周り) で SSRF 系を識別
- [ ] 公開版では threshold だけ示し、本番チューニング値は載せない
- [ ] `tests/test_security_contract.py` 相当に SSRF ルールの契約テスト追加

## 注意

公開リポジトリのため、本番運用閾値・除外条件は含めない (SECURITY.md 準拠)。
