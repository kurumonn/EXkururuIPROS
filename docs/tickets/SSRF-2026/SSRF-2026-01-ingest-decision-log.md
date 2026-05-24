# SSRF-2026-01 — kurutann SSRFDecisionLog 取り込み API

- Status: TODO
- Priority: P1
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-101`

## 概要

kurutann (Django SSRF Gateway) が SSRFDecisionLog を生成したタイミングで
EXkururuIPROS の取り込み API に JSON を POST する。本チケットは IPROS 側の
**受け口**を実装する。

## 入力スキーマ (基本設計書 §2.7 と同形)

```json
{
  "event_type": "ssrf_decision",
  "rule_id": "SSRF-007",
  "severity": "high",
  "action": "block",
  "source_ip": "203.0.113.10",
  "user_id": null,
  "path": "/api/seo/fetch/",
  "param": "url",
  "raw_url_hash": "sha256:...",
  "normalized_scheme": "https",
  "normalized_host": "example.com",
  "normalized_port": 443,
  "resolved_ips": ["203.0.113.10"],
  "blocked_reason": "redirect_to_private_or_disallowed_target",
  "policy_version": 3,
  "request_id": "uuid",
  "created_at": "2026-05-23T00:00:00Z"
}
```

## 実装方針

- FastAPI ルート `POST /api/v1/ssrf/decision` を追加
- `dashboard/app.py` 側の既存 ingest と同じ認証 (`IPS_ADMIN_TOKEN`) を利用
- raw_url は受け取らない (秘匿/XSS 防止)。受け取った場合は無視
- 受信後は `security_events` テーブルに `event_kind='ssrf_decision'` で保存

## タスク細分化

- [ ] スキーマモデル (pydantic) を `dashboard/ssrf_models.py` に定義
- [ ] エンドポイントを `dashboard/app.py` に追加
- [ ] `dashboard/storage.py` に SSRF 用 insert ヘルパを追加
- [ ] 単体テスト: 必須フィールド欠如・rule_id 不正・raw_url 入りを reject
- [ ] `README.en.md` の公開 API 一覧に追記 (本番閾値は載せない)
