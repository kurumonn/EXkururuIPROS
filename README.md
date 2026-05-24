# exkururuIPROS NGIPS

[英語版 README](README.en.md)  
[4製品デモ概要](README.4stack.md)

EXkururuIPROS は、低リソース環境向けに設計した公開配布用の NGIPS/NDR コンポーネントです。  
この公開リポジトリでは、ダッシュボード UI、センサー構成、イベント投入、アラート運用、ローカル起動導線といった「評価しやすい面」を残しています。

この README は公開配布用の案内です。実運用の秘密情報や本番用ノウハウは含めません。

## 公開範囲

- 軽量ダッシュボードと API
- エッジ適用向け Rust センサー構成
- イベント投入とインシデント指向ワークフロー
- 脅威インテリジェンス連携の表面
- ローカル開発とデモ起動導線

本番の閾値、スコアリング、ロールアウト戦略、運用チューニング値のような核心部分は公開版から除外しています。

## 公開しないもの

- 本番の共有鍵、トークン、証明書、接続先 URL
- 実コーパスの保存場所、評価手順の詳細、顧客データ
- 内部閾値、除外条件、チューニング値、ロールアウトの既定値
- 実案件由来の運用導線や private runbook
- 内部検証向けの benchmark / quality gate の生ログや詳細メモ

## アーキテクチャ

```text
Internet
   |
Edge Enforcement
   |
Rust Sensor
   |
Event Pipeline
   |
Incident Engine
   |
Dashboard
```

## 主な機能

- マルチセンサー運用
- アラート集約
- 脅威インテリジェンス付与の受け口
- SOC / XDR / EDR の統合表示パネル
- 軽量なフロー指向ネットワーク検知

## クイックスタート

```bash
cd /path/to/exkururuIPROS
python3 -m venv .venv
./.venv/bin/pip install -r requirements-dev.txt
cp .env.example .env
IPS_ADMIN_TOKEN=change-this-admin-token IPS_DB_PATH=./ips_open.db ./.venv/bin/uvicorn dashboard.app:app --host 127.0.0.1 --port 8787
```

Docker で起動する場合は `docker-compose.yaml` を使うのが分かりやすいです。  
`docker-compose.yml` は互換用の旧ファイルとして残していますが、公開配布用の案内では `docker-compose.yaml` を推奨します。

```bash
cd /path/to/exkururuIPROS
cp .env.example .env
docker compose -f docker-compose.yaml up --build
```

起動後は `http://127.0.0.1:8787` を開きます。

## テスト

```bash
cd /path/to/exkururuIPROS
./.venv/bin/pytest -q
```

## 公開している環境変数

公開版では最小限の起動変数だけを例示しています。  
本番用の閾値、除外条件、ロールアウト既定値、環境固有の連携設定は公開リポジトリ外で管理する前提です。

- `IPS_DB_PATH`
- `IPS_ADMIN_TOKEN`
- `IPS_BIND_HOST`
- `IPS_BIND_PORT`
- `IPS_DEFAULT_WORKSPACE`
- `IPS_REQUIRE_NONCE` (既定: `1`)
- `IPS_SIGNATURE_MAX_SKEW_SEC` (既定: `300`)
- `IPS_REPLAY_TTL_SEC` (既定: `310`)
- `IPS_REPLAY_BACKEND` (`auto` / `redis` / `memory`, 既定: `auto`)
- `IPS_REDIS_URL` (`redis://...` を指定した場合に共有 replay cache を使用)
- `IPS_REPLAY_FALLBACK_TO_MEMORY` (既定: `1`)
- `IPS_REPLAY_CACHE_MAX_ITEMS` (既定: `200000`)

## 署名ヘッダー（v2）

- `X-IPS-Sensor-Id`
- `X-IPS-Timestamp`
- `X-IPS-Nonce` (既定で必須)
- `X-IPS-Signature`

署名文字列は `"{timestamp}.{nonce}.{raw_body}"` を利用します。  
`IPS_REQUIRE_NONCE=0` のときだけ、従来形式 `"{timestamp}.{raw_body}"` を後方互換として許可します。
`IPS_REPLAY_BACKEND=redis` と `IPS_REDIS_URL` を設定すると、replay 判定は Redis 共有キャッシュに切り替わります。
Redis 障害時は `IPS_REPLAY_FALLBACK_TO_MEMORY=1` の場合にメモリ退避します。

## 統合連携

ダッシュボードは XDR、SOC、EDR といった隣接プロダクトの統合パネルを表示できます。  
公開版では「連携面の存在」だけを示し、接続先や認証情報のような実運用設定は含めていません。

## 対応済み脆弱性・CVSS 情報

本 IPS が現在シグネチャを保有し、スコアリングまたは自動緩和を行っている脆弱性の一覧です。

| ID | 名称 | CVSS v3.1 スコア | 深刻度 | 対応方式 |
|---|---|---|---|---|
| IPROS-MDP | Mythos 型 AI-assisted exploit probe | — | High/Critical | 正規化 + 相関検知 + Canary + Evidence |
| CVE-PENDING-PINTHEFT | PinTheft: Linux Kernel LPE via RDS zerocopy + io_uring | 7.8 | High | 検出 + センサー自動緩和 |
| CVE-2026-42945 | nginx Remote Code Execution | — | — | 検出 + パッチ推奨 |

---

### IPROS-MDP — Mythos Defense Profile

Mythos は固定IoCではなく、AI支援で高速化する脆弱性探索・多段プローブのTTPとして扱う。

**本 IPS での対応**

- *正規化*: URL二重エンコード、パス表記ゆれ、クエリ/本文断片を正規化して `normalized_uri` と `request_categories` を付与。
- *検出*: `.env`, `.git`, `cgi-bin`, PHP RCE, traversal, SSRF, SQL/NoSQL injection, GraphQL introspection, request smuggling をカテゴリ化。
- *Canary*: `/.env`, `/.git/config`, `/api/internal/status`, `/debug/vars` などの honey URI を `canary_hit` として critical 扱い。
- *相関*: 同一送信元が短時間に複数カテゴリ・複数URI・4xx/5xx中心で探索した場合、`AI-RECON-CHAIN-001` として `AI_EXPLOIT_CHAIN` を付与。
- *API*: `GET /api/v1/workspaces/{workspace}/mythos-defense/summary/` で Mythos/PinTheft 防御サマリを返す。

---

### CVE-PENDING-PINTHEFT — PinTheft Linux Kernel LPE

**概要**  
Linux カーネルの RDS (Reliable Datagram Sockets) サブシステムにある `rds_message_zcopy_from_user()` の zerocopy 参照カウンタバグを、io_uring 経由で悪用するローカル権限昇格 (LPE)。  
解放済みページを再利用して SUID バイナリのページキャッシュを汚染し、root シェルを取得する。

| 項目 | 内容 |
|---|---|
| **公表日** | 2026-05-20 |
| **CVE ID** | CVE-PENDING-PINTHEFT (割当待ち) |
| **CVSS v3.1 スコア** | **7.8 (High)** |
| **CVSS ベクター** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **影響** | 機密性・完全性・可用性すべて High |
| **攻撃経路** | Local (AV:L) |
| **攻撃の複雑さ** | Low (AC:L) |
| **必要な権限** | Low — 一般ユーザー権限で到達可能 (PR:L) |
| **ユーザー操作** | 不要 (UI:N) |
| **影響範囲** | Unchanged (S:U) |
| **影響を受ける構成** | `CONFIG_RDS`, `CONFIG_RDS_TCP`, `CONFIG_IO_URING` が有効な Linux カーネル |
| **緩和策** | `rds_tcp`, `rds` モジュールのアンロード + `/etc/modprobe.d/` ブラックリスト |

**CVSS ベクター内訳**

```
CVSS:3.1/AV:L / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:H
         ^^^^   ^^^^   ^^^^   ^^^^   ^^^   ^^^   ^^^   ^^^
         Local  Low    Low    None   Unch  High  High  High
```

**本 IPS での対応**

- *検出*: シグネチャ `kernel_lpe_pintheft` ファミリーで CVSS スコアに対応した高スコアを付与。  
  ペイロード中の `pintheft`, `rds_zcopy`, `rds_message_zcopy_from_user`, `iouring_lpe` などのヒントに加え、EDRイベント `kernel_exposure_snapshot`, `module_load`, `io_uring_*` を照合する。
- *自動緩和*: PinTheft イベントをインジェスト時に自動検出し、ダッシュボードが `kernel_module_blacklist` アクション (`rds_tcp,rds`) をキューイング。  
  センサー側で `IPS_ALLOW_KERNEL_HARDENING=1` かつ `IPS_APPLY_MODE=nft` のとき、modprobe ブラックリスト書き込みと `rmmod` を自動実行する。  
  WAF 無効状態でも緩和アクションは配信される（IP ブロックの WAF ゲートを迂回する専用パス）。
- *監査*: 自動緩和キュー投入時に `policy_audit_logs` へ `kernel_hardening_queued` を記録する。

---

### CVE-2026-42945 — nginx Remote Code Execution

| 項目 | 内容 |
|---|---|
| **パッチ済みバージョン** | mainline 1.31.0 以降 / stable 1.30.1 以降 |
| **対応方式** | 本 IPS はプローブ検出時にサーバーのバージョンを照合し、脆弱/パッチ済みを判定してアクションを推奨 |

---

## セキュリティ方針

- 秘密情報はリポジトリに含めない
- ローカルサービスは信頼できるインターフェースへ bind する
- 共用環境では TLS 終端と認証付きリバースプロキシの背後で使う
- 公開サンプル設定は開発用既定値として扱う

## ライセンス

このリポジトリは `Personal Developer License v1.0` を採用しています。  
詳細は [LICENSE](LICENSE) を参照してください。
