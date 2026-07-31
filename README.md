# qf-c4-gate-sandbox

Wegwerf-Sandbox für den Wirksamkeitsbeweis des C4 Merge-Receipt-Gates
(Finding A aus dem Audit von PR #705 im Produktrepo).

- `.github/workflows/audit_receipt_gate.yml` — byte-identische Kopie aus PR #705 @ 9537471f
- `scripts/verify_audit_receipt_gate.py` — byte-identische Kopie aus PR #705 @ 9537471f
- `.github/workflows/sandbox_post_bot_receipt.yml` — NUR Sandbox-Hilfsmittel, um ein
  Receipt als `github-actions[bot]` zu posten (Szenario 5). Nicht Teil des Gates.

Kein Produktivcode. Enthält keine Secrets.
