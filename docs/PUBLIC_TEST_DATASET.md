# Public Test Dataset

このデータセットは公開可能な合成データです。実ユーザー情報・実IP・実ログは含みません。

## データ安全性

- IP は RFC 5737 のテストレンジのみ使用
  - `192.0.2.0/24`
  - `198.51.100.0/24`
  - `203.0.113.0/24`
- User-Agent はダミー/一般公開識別子のみ
- payload は固定文字列（個人情報なし）

## シナリオ構成

- 攻撃系: `login_bruteforce`, `scraping`, `recon`, `credential_stuffing`, `api_abuse`
- 正常系: `normal_browse`, `crawler_search_bot`, `internal_noisy_traffic`, `mobile_network_fluctuation`

## 生成方法

```bash
cd /path/to/kururuIPROS
./scripts/public_e2e_demo.py
```

出力:

- `docs/public_demo_metrics.json`
