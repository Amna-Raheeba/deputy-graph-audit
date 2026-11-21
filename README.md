# Deputy Graph Audit

**The agent had permission. The document that told it what to do did
not.** Per-call permission checks ask one question — *may this agent
call this tool?* — and the answer is almost always yes, because the
agent process itself is privileged. The confused-deputy failure is
different: a restricted action (send externally, delete records, make
a payment) gets *authorised by content nobody trusted* — a retrieved
document, a web page, a tool result — sometimes laundered through a
summariser or two so nothing in the final call looks suspicious. This
tool audits a recorded agent trace offline, rebuilds its provenance
graph over a declared privilege lattice, and flags exactly those
actions — with the minimal escalation path as the evidence.

It is a defensive auditor for your own agent traces. It runs no
attacks, calls no models, and needs no network: pure Python stdlib,
deterministic, seeded.

## 1. The idea in 30 seconds

1. Every tool declares a required privilege on a four-level lattice:
   0 untrusted, 1 low, 2 user, 3 approver. Sources declare trust on
   the same scale: retrieved documents and web pages are 0, tool
   output and memory are 1, a user instruction is 2, a human approver
   or system instruction is 3.
2. Replay the trace as a directed provenance graph. Every node
   inherits the **lowest trust of its causal ancestors** — a chain is
   as trustworthy as its weakest link.
3. Verification and approval nodes are **sanitizers**: content that
   passes through a human check inherits the checker's trust, not the
   document's. A verification that exists in the trace but is *not* a
   causal ancestor of the action sanitizes nothing.
4. An action is flagged when its required privilege exceeds its
   inherited trust. For each flag, the tool extracts the **minimal
   escalation path**: the shortest unsanitized chain from a too-weak
   source to the action.

## 2. Quick start

```bash
python -m deputy_graph_audit demo
python -m deputy_graph_audit audit data/hand_traces.json
python -m deputy_graph_audit evaluate --out results
streamlit run app.py
```

## 3. The demo

```
Trace demo-001 (pattern: two_hop_laundering)
VIOLATION act: requires 3 (approver), inherited 0 (untrusted)
  Minimal escalation path: doc -> sum -> act
  Authorising source: doc
```

A retrieved document (trust 0) is summarised, and the summary drives a
restricted external send (requires 3). A per-call check passes this
trace — the agent holds privilege 3 and the tool requires 3. The
escalation exists only in the provenance graph.

## 4. What is novel

- **Provenance-first, not permission-first.** The unit of analysis is
  the causal chain that authorised an action, not the call itself.
- **A declared privilege lattice with trust inheritance.** Sources,
  intermediate transforms, and actions all live on one ordered scale,
  and trust propagates by minimum over ancestors.
- **Sanitizer semantics.** Verification/approval edges restore trust —
  but only when they are actually in the action's causal ancestry,
  which is what makes the *verification-bypass* pattern (a check that
  happened somewhere else in the trace) detectable.
- **The minimal escalation path as output.** Not a score or a label:
  the shortest untrusted-to-privileged chain, a graph object a
  checklist cannot produce, ready to paste into an incident report.

## 5. Prior art and the differentiator

OWASP LLM06 (Excessive Agency), CWE-441 (confused deputy) write-ups,
and production-readiness audit-logging guidance all describe this
failure — as prose, checklists, and test advice. Visual Confused
Deputy (2026) is a *runtime* guardrail for GUI agents: it intervenes
live, on one agent type. No offline, deterministic trace auditor
computes escalation paths against a declared privilege lattice. This
tool works after the fact, on recorded traces from any agent, with no
model in the loop — so its verdicts are reproducible and auditable
themselves.

## 6. Measured results (seed 7, this repo)

Seeded generator: 290 traces — 170 planted violations across 5
patterns (direct injection 40, two-hop laundering 40, three-hop
laundering 30, tool-output escalation 30, verification bypass 30) and
120 benign hard negatives (user-authorised, human-verified, low-
privilege, keyword-laden user text, exact-trust tool chains).

| Method | Precision | Recall |
|---|---|---|
| Deputy Graph Audit | 1.0000 | 1.0000 |
| Per-call permission check | 1.0000 | 0.0000 |
| Keyword heuristic | 0.6667 | 0.2353 |

- Minimal escalation path exactness: **1.0000 (170/170)** — the
  extracted path equals the planted path for every detected violation.
- Per-pattern auditor recall is 1.0000 on all five violation patterns.
- The per-call baseline misses all 170 escalations: the agent's own
  privilege covers every call, which is the structural point.
- The keyword heuristic catches only the 40 direct injections (the
  laundered and tool-output patterns carry no alarm words) and fires
  on all 20 benign keyword-laden user instructions.

Reproduce with `python scripts/reproduce_results.py` — it recomputes
the evaluation and fails if any headline number drifts.

## 7. Honest limits

- **Synthetic traces, planted ground truth.** The auditor implements
  the rule that defines the labels, so a perfect score shows the
  implementation is correct and the baselines are structurally blind —
  not that the tool scores 1.0 on real production logs. Real traces
  have incomplete provenance, and missing edges read as "authorised
  by nothing" (trust 0), which is conservative but noisy.
- **The lattice is a total order.** Real trust is not: a document can
  be trusted for facts but not instructions. This model has one scale
  on purpose — it is the smallest model that exposes the failure.
- **Sanitizers are trusted absolutely.** A verification node lends its
  full trust downstream; a rubber-stamp human check is
  indistinguishable from a careful one in a recorded trace.
- **Causality is taken from the trace as recorded.** If the logging
  omits a parent edge, the audit inherits the omission.

## 8. Repository layout

1. `deputy_graph_audit/` — models, graph (trust propagation), audit
   (flags + minimal paths), baselines, generate, evaluate, report, cli.
2. `data/` — `policy.json`, `traces.json` (290 seeded traces),
   `hand_traces.json` (4 hand-written).
3. `tests/` — 70 tests. `notebooks/` — demo and evaluation as runnable
   scripts. `examples/` — hand traces with a sample report.
4. `scripts/` — `build_cases.py` regenerates the data;
   `reproduce_results.py` guards the headline numbers.
5. `results/` — evaluation JSON/CSV, summary, and headline file.
6. `app.py` — Streamlit dashboard: audit a trace, inspect the lattice,
   read the evaluation.

## 9. Author and licence

By Amna Raheeba. MIT licence (see `LICENSE`).
