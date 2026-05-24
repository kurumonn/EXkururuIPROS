# SSRF-2026-07 — Incident engine への SSRF 対応

- Status: TODO
- Priority: P1
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-101`

## 概要

既存の Incident engine (README.md 「Incident Engine」) に SSRF カテゴリを追加。
スコア 90+ の DecisionLog または `SSRF-012` egress 検知をトリガーに Incident を起票する。

## Incident 雛形

```json
{
  "category": "ssrf",
  "rule_id": "SSRF-007",
  "severity": "high",
  "source_ip": "203.0.113.10",
  "target_host": "example.com",
  "first_seen": "...",
  "last_seen": "...",
  "event_count": 12,
  "grouping_key": "SSRF-007|203.0.113.10|example.com|/api/seo/fetch/|20260523_1545",
  "linked_request_ids": ["uuid1","uuid2"]
}
```

## タスク細分化

- [ ] Incident 生成器に SSRF ハンドラ追加
- [ ] 同 grouping_key の Incident は 15 分窓で重複させない
- [ ] Incident の `linked_request_ids` に DecisionLog の request_id を蓄積
- [ ] テスト: 重複圧縮 / 多元イベントから 1 Incident / window 切替で別 Incident
