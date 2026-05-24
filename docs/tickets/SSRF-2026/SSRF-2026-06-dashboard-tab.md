# SSRF-2026-06 — ダッシュボード SSRF タブ追加

- Status: TODO
- Priority: P1
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-102`

## 概要

`dashboard/templates/` 配下に SSRF 専用タブを追加する。
本番監視テンプレートと**別ページ**で作成する (CLAUDE.md SecOps Rules 準拠:
本番ダッシュボードにシミュレーション・演習コードを混ぜない原則と同じ)。

## 表示項目 (基本設計書 §3.13)

- SSRF 疑いイベント数 (全体 / 24h / 1h)
- block / monitor / challenge 件数
- 上位パラメータ名
- 上位送信元 IP
- 上位対象ホスト
- ルール別件数 (SSRF-001〜014)
- DNS 再バインド疑い
- リダイレクト拒否件数
- メタデータアクセス試行
- 外向き FW 拒否件数

## 実装方針

- ルート: `/dashboard/ssrf/`
- テンプレート: `dashboard/templates/ssrf_overview.html` (新規)
- 既存 `live_panel.py` の集計関数を流用してよいが、SSRF 系メトリクスは
  別関数に切り出して密結合を避ける
- `<script>` 文字列リテラルに `</script>` を絶対に書かない (分割エスケープ)

## タスク細分化

- [ ] ルート追加 (`dashboard/app.py`)
- [ ] テンプレート新規作成
- [ ] 集計関数 (`dashboard/ssrf_metrics.py`)
- [ ] 単体テスト + e2e smoke
