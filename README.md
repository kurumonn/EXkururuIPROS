# exkururuIPROS NGIPS

[英語版 README](README.en.md)  
[4製品デモ概要](README.4stack.md)

EXkururuIPROS は、低リソース環境向けに設計した公開配布用の NGIPS/NDR コンポーネントです。  
この公開リポジトリでは、ダッシュボード UI、センサー構成、イベント投入、アラート運用、ローカル起動導線といった「評価しやすい面」を残しています。

## 公開範囲

- 軽量ダッシュボードと API
- エッジ適用向け Rust センサー構成
- イベント投入とインシデント指向ワークフロー
- 脅威インテリジェンス連携の表面
- ローカル開発とデモ起動導線

本番の閾値、スコアリング、ロールアウト戦略、運用チューニング値のような核心部分は公開版から除外しています。

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
./.venv/bin/pip install -r dashboard/requirements.txt
cp .env.example .env
IPS_ADMIN_TOKEN=change-this-admin-token IPS_DB_PATH=./ips_open.db ./.venv/bin/uvicorn dashboard.app:app --host 127.0.0.1 --port 8787
```

## 公開している環境変数

公開版では最小限の起動変数だけを例示しています。  
本番用の閾値、除外条件、ロールアウト既定値、環境固有の連携設定は公開リポジトリ外で管理する前提です。

- `IPS_DB_PATH`
- `IPS_ADMIN_TOKEN`
- `IPS_BIND_HOST`
- `IPS_BIND_PORT`
- `IPS_DEFAULT_WORKSPACE`

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
