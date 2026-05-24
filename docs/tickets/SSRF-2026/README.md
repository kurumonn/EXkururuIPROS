# SSRF-2026 — IPS/WAF SSRF Defense Tickets

EXkururuIPROS 側のチケット運用 DB が無いため、`docs/tickets/SSRF-2026/` に
親 + 子チケットを Markdown で配置する。dev2 (kurutann.com) の DevQA
親チケット **DEV-88** と 1:1 で対応する。

## チケット一覧

| ID | Title | dev2 DevQA |
|----|-------|------------|
| [SSRF-2026-00](SSRF-2026-00-parent.md) | 親: SSRF/WAF/IPS 多層防御 (EXkururuIPROS 側) | DEV-88 |
| [SSRF-2026-01](SSRF-2026-01-ingest-decision-log.md) | kurutann SSRFDecisionLog 取り込み API | DEV-101 |
| [SSRF-2026-02](SSRF-2026-02-ruleset.md) | IPS ルールセット SSRF-001〜014 投入 | DEV-99 |
| [SSRF-2026-03](SSRF-2026-03-scoring.md) | SSRF スコアリング & incident grouping | DEV-101 |
| [SSRF-2026-04](SSRF-2026-04-egress-correlation.md) | egress firewall ログ相関 | DEV-103 |
| [SSRF-2026-05](SSRF-2026-05-dns-rebinding.md) | DNS 再バインド検知センサー | DEV-92 / DEV-104 |
| [SSRF-2026-06](SSRF-2026-06-dashboard-tab.md) | ダッシュボード SSRF タブ追加 | DEV-102 |
| [SSRF-2026-07](SSRF-2026-07-incident-engine.md) | Incident engine への SSRF 対応 | DEV-101 |
| [SSRF-2026-08](SSRF-2026-08-public-corpus.md) | 公開コーパス: SSRF 検証データ整備 | DEV-106〜108 |
| [SSRF-2026-09](SSRF-2026-09-acceptance.md) | 受け入れ基準消化 (IPROS 側) | DEV-109 |

## 設計準拠

- 要件定義書 §1
- 基本設計書 §2 (ルール ID 設計 §2.6 / ログ設計 §2.7)
- 詳細設計書 §3.11 (IPS ルール詳細)

## 注意

- 公開リポジトリのため、本番閾値・トークン・URL は含めない (SECURITY.md 準拠)
- スコア・チューニング値はあくまでサンプル
