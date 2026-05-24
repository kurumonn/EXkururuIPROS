# SSRF-2026-08 — 公開コーパス: SSRF 検証データ整備

- Status: TODO
- Priority: P2
- Parent: SSRF-2026-00
- Linked: dev2 DevQA `DEV-106` / `DEV-107` / `DEV-108`

## 概要

`docs/PUBLIC_TEST_DATASET.md` に SSRF 検証用の**安全な**サンプルを追加。
攻撃の生ペイロードや実コーパスは公開しない (SECURITY.md 準拠)。

## 含めるデータ

- IPv6/IPv4 特殊表現の正規化前 / 正規化後の **意図** (実値は伏字 OK)
- DNS 再バインド検証の論理シナリオ (具体的 IP / ドメインは公開しない)
- Open Redirect 連鎖の論理シナリオ
- 各シナリオで期待される rule_id / score / action

## タスク細分化

- [ ] `docs/PUBLIC_TEST_DATASET.md` に SSRF セクションを追加
- [ ] `tests/test_hard_negative_corpus.py` 相当に SSRF false-positive ケースを追加
- [ ] `tests/test_security_contract.py` に SSRF ルールの契約テスト追加
- [ ] 公開リポジトリに本番閾値が紛れていないかレビュー
