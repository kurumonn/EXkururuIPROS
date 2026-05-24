# SSRF-2026-05 — DNS 再バインド検知センサー

- Status: TODO
- Priority: P2
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-92` / `DEV-104`

## 概要

`SSRF-006 dns_rebinding_suspected` の検知ロジックを IPROS 側でも独立して持つ。
アプリ側 Gateway が検査時/接続時の解決結果差分を見ているが、IPROS 側でも
DNS 応答を観測して短 TTL + 私有 IP 切り替えを検知する。

## 検知シグナル

- 同一ホストに対する直近 N 回の解決結果に private/public が混在
- TTL < 10 秒のホストに対する直近の解決
- 検査時 public IP → 接続時 private IP

## タスク細分化

- [ ] DNS 応答ログ取り込み (sensor or passive DNS)
- [ ] ホスト別の resolved_ips 履歴 (短 TTL 用に直近 5 分保持)
- [ ] `private/public 混在` 検知関数
- [ ] `SSRF-014 short_ttl_dns` のスコア加点
- [ ] テスト: 履歴差し替え / TTL 1 秒応答 / 連続 public→private 切替
