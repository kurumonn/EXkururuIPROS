# SSRF-2026-04 — egress firewall ログ相関

- Status: TODO
- Priority: P1
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-103`

## 概要

kurutann のアプリサーバ egress firewall が落とした通信
(私有 IP / link-local / 169.254.169.254 への outbound) を取り込み、
同 request_id の SSRFDecisionLog と結合して `SSRF-012` インシデントを生成する。

## 入力例

```
ts=2026-05-23T00:00:00Z host=app01 src=10.0.1.5 dst=169.254.169.254 dport=80 verdict=deny
```

## 結合キー

- 一次: `request_id` (アプリ → egress sidecar で伝搬)
- 二次: `(src_app_host, dst_ip, ts ± 2s)`

## タスク細分化

- [ ] egress firewall ログの ingestion route 追加 (or 既存 sensor に組み込み)
- [ ] DecisionLog との結合関数 (`dashboard/ssrf_correlate.py`)
- [ ] 結合できない孤立ログも `SSRF-012` として別系統で incident 化
- [ ] テスト: 同 request_id でマッチ / 別 ts でマッチしない / 孤立ログ単体での incident 化
