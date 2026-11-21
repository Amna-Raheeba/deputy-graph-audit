# Changelog

## 0.1.0 - 2026-11-21

- First release: provenance-graph auditor over a declared privilege lattice.
- Trust propagation with verification/approval sanitizers; an action is
  flagged when its required privilege exceeds its inherited trust.
- Minimal escalation path extraction (shortest unsanitized source-to-action
  chain) per violation.
- Seeded trace generator with 5 planted escalation patterns and 5 benign
  hard-negative patterns (290 traces); baselines: per-call permission
  check and keyword heuristic.
- Streamlit dashboard (3 tabs), CLI (demo / audit / evaluate), notebooks
  as runnable scripts, headline-drift guard in scripts/reproduce_results.py.
