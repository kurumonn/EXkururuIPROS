# SSRF-2026-03 — SSRF スコアリング & incident grouping

- Status: TODO
- Priority: P1
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-101`

## スコア閾値 (基本設計書 §2.5)

| score | action |
|-------|--------|
| 0–29  | allow |
| 30–59 | monitor |
| 60–89 | challenge |
| 90+   | block |

## 加点条件

| 条件 | 加点 |
|------|------|
| URL 系パラメータに内部 IP 表現 | +80 |
| メタデータ系宛先 | +100 |
| 危険スキーム | +100 |
| IPv4-mapped IPv6 | +70 |
| localhost 系表現 | +80 |
| 多重 URL エンコード | +40 |
| redirect 系パラメータ | +25 |
| TTL が極端に短い | +30 |
| リダイレクト後にホスト変更 | +50 |
| allowlist 外ドメイン | +60 |
| DNS 解決結果が変化 | +100 |

## Incident Grouping

`signature = rule_id + source_ip + normalized_host + path + 15min_window`

例:

```
SSRF-007|203.0.113.10|example.com|/api/seo/fetch/|20260523_1545
```

## タスク細分化

- [ ] `dashboard/parser.py` or 新規 `dashboard/ssrf_scoring.py` にスコア関数
- [ ] grouping key を生成するヘルパ
- [ ] 15 分窓のロールアップを `dashboard/storage.py` に追加
- [ ] 単体テスト: 各加点条件 / 合算 / 閾値判定
