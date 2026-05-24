# SSRF-2026-09 — 受け入れ基準消化 (IPROS 側)

- Status: TODO
- Priority: P1
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-109`

## チェックリスト (IPROS 側)

- [ ] kurutann から SSRFDecisionLog を受信できる (SSRF-2026-01)
- [ ] SSRF-001〜014 のルールが投入されている (SSRF-2026-02)
- [ ] スコア閾値 (0-29 / 30-59 / 60-89 / 90+) が機能する (SSRF-2026-03)
- [ ] Incident grouping が 15 分窓で動く (SSRF-2026-03 / 07)
- [ ] egress firewall ログを request_id で結合できる (SSRF-2026-04)
- [ ] DNS 再バインド検知が動く (SSRF-2026-05)
- [ ] ダッシュボードに SSRF タブが出る (SSRF-2026-06)
- [ ] 本番ダッシュボードと SSRF タブが**別ページ**になっている (CLAUDE.md SecOps Rule)
- [ ] `<script>` 文字列リテラルに `</script>` 直書きが無い (XSS シナリオ流用時の事故防止)
- [ ] 公開リポジトリに本番閾値・トークン・実コーパスが含まれていない
- [ ] 公開版 README / PUBLIC_TEST_DATASET に SSRF 項目が追記されている
