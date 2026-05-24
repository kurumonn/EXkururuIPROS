# SSRF-2026-00 (parent) — SSRF/WAF/IPS 多層防御 (EXkururuIPROS 側)

- Status: TODO
- Priority: P0
- Linked: dev2 DevQA `DEV-88`
- Owner: TBD

## 目的

kurutann.com 側の Django SSRF Gateway が出す SSRFDecisionLog を
EXkururuIPROS で取り込み、ルール (SSRF-001〜014) ごとに集計・相関・
ダッシュボード化する。
WAF の URL 文字列検査だけでは防げない以下のバイパスを多層で潰す:

1. DNS 再バインド (検査時 public → 接続時 127.0.0.1)
2. IPv6 表現 (`[::]` / `[0:0:0:0:0:ffff:127.0.0.1]`)
3. Open Redirect chain (信頼ドメイン経由で内部宛に到達)

## 守るべき宛先 (要件定義書 §1.4)

- 127.0.0.0/8, 0.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16
- ::1, fc00::/7, fe80::/10, IPv4-mapped IPv6
- クラウドメタデータサービス (169.254.169.254)
- Redis / PostgreSQL / Docker API / Kubernetes API
- Nginx stub_status / Django admin / secops internal API

## アーキテクチャ (基本設計書 §2.1)

```
[User]
  ↓
Cloudflare WAF → Nginx → Django Middleware → SSRF Gateway
  ↓
Controlled HTTP Client → Egress Firewall → External Internet
  │
  └── SSRFDecisionLog / Egress FW Log
        ↓
      EXkururuIPROS  (← 本リポジトリの担当範囲)
        ↓
      XDR / SOC / Dashboard
```

## ルール ID (基本設計書 §2.6)

- SSRF-001 dangerous_scheme
- SSRF-002 private_ip_literal
- SSRF-003 localhost_alias
- SSRF-004 metadata_endpoint
- SSRF-005 ipv6_mapped_ipv4
- SSRF-006 dns_rebinding_suspected
- SSRF-007 redirect_to_disallowed_target
- SSRF-008 open_redirect_chain
- SSRF-009 suspicious_url_parameter
- SSRF-010 multi_encoded_url
- SSRF-011 allowlist_violation
- SSRF-012 egress_private_ip_attempt
- SSRF-013 raw_response_reflection
- SSRF-014 short_ttl_dns

## 受け入れ基準

- [ ] kurutann から SSRFDecisionLog を JSON で受信できる
- [ ] SSRF-001〜014 を IPS のルール ID 体系に投入済み
- [ ] スコア閾値 (0-29 allow / 30-59 monitor / 60-89 challenge / 90+ block) を実装
- [ ] Incident grouping (`rule_id + source_ip + normalized_host + path + 15min_window`) で重複圧縮
- [ ] egress firewall ログと SSRFDecisionLog を request_id で結合できる
- [ ] ダッシュボードに SSRF タブが出る
- [ ] 公開リポジトリに本番閾値・実コーパス・トークンが混入していない
