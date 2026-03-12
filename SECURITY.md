# Security Policy

## Supported scope

このリポジトリは公開配布向けの最小構成です。  
以下は利用者側で必ず実施してください。

- `IPS_ADMIN_TOKEN` と `IPS_SHARED_SECRET` の再生成
- HTTPS 終端
- 管理 API の IP 制限または VPN 制限
- `dry-run` での十分な検証後にのみ `nft` を有効化
- `IPS_ADMIN_TOKEN` は20文字以上の乱数を使用
- 必要時は `IPS_ADMIN_EXTRA_HEADER_NAME` / `IPS_ADMIN_EXTRA_HEADER_VALUE` を有効化

## Reporting a vulnerability

脆弱性や危険なデフォルト設定を見つけた場合は、公開 Issue に機密情報を書かずに報告してください。  
再現ログを共有する場合は以下を必ずマスクしてください。

- 実IP
- 実ドメイン
- 実トークン
- 実シークレット
- 内部ネットワーク構成

## Out of scope

以下はこの配布物単体では保証しません。

- 受信ログの完全な真実性
- CDN / WAF / reverse proxy の設定不備
- nftables ルールの誤設定による通信断
- 利用者が追加した独自ルールの安全性
