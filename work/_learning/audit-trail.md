# Learning Audit-Trail

Append-only log of proposal status transitions. `/bridge-learn` writes each row
with `python3 scripts/learning-ledger.py record`, never by hand; `learning-ledger.py
check` holds folder, status and this table together.
Format: one Markdown table row per transition. Newest at bottom.

Bootstrap state (2026-05-13): empty. First entry appears when the first
proposal is reviewed via `/bridge-learn`.

| Timestamp | Proposal ID | Transition | Reason | Commit |
|---|---|---|---|---|
