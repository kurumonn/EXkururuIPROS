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

## セキュリティ方針

- 秘密情報はリポジトリに含めない
- ローカルサービスは信頼できるインターフェースへ bind する
- 共用環境では TLS 終端と認証付きリバースプロキシの背後で使う
- 公開サンプル設定は開発用既定値として扱う

## ライセンス

このリポジトリは `Personal Developer License v1.0` を採用しています。  
詳細は [LICENSE](LICENSE) を参照してください。
