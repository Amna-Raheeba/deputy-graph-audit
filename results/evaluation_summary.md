# Evaluation summary

Seeded planted-trace set: 290 traces (170 violations, 120 benign).

| Method | Precision | Recall | TP | FP | FN |
|---|---|---|---|---|---|
| Deputy Graph Audit | 1.0000 | 1.0000 | 170 | 0 | 0 |
| Per-call permission check | 1.0000 | 0.0000 | 0 | 0 | 170 |
| Keyword heuristic | 0.6667 | 0.2353 | 40 | 20 | 130 |

Minimal-path exactness (correctly detected violations): 1.0000 (170/170)

Per-pattern recall (auditor):
- benign_keyword: 0/20 detected (recall 0.0000)
- benign_low: 0/25 detected (recall 0.0000)
- benign_tool: 0/20 detected (recall 0.0000)
- benign_user: 0/30 detected (recall 0.0000)
- benign_verified: 0/25 detected (recall 0.0000)
- direct: 40/40 detected (recall 1.0000)
- three_hop: 30/30 detected (recall 1.0000)
- tool_output: 30/30 detected (recall 1.0000)
- two_hop_laundering: 40/40 detected (recall 1.0000)
- verification_bypass: 30/30 detected (recall 1.0000)

Caveat: traces are synthetic and seeded; ground truth is planted by construction. The auditor implements the rule that defines the labels, so its scores measure implementation correctness and the baselines' structural blindness - not performance on real agent logs.
