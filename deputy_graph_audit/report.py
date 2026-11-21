"""Human-readable reports for one trace audit and for the evaluation."""
from deputy_graph_audit.graph import level_label


def trace_report(trace, violations):
    lines = []
    lines.append("Trace %s (pattern: %s)" % (trace.trace_id, trace.pattern))
    if not violations:
        lines.append("No violations: every action is authorised by its causal ancestors.")
        return "\n".join(lines)
    for violation in violations:
        lines.append(
            "VIOLATION %s: requires %s, inherited %s" % (
                violation.action_id, level_label(violation.required),
                level_label(violation.inherited_trust)))
        lines.append("  Minimal escalation path: %s" % " -> ".join(violation.path))
        lines.append("  Authorising source: %s" % violation.source_id)
    return "\n".join(lines)


def evaluation_summary(results):
    lines = []
    lines.append("# Evaluation summary")
    lines.append("")
    lines.append("Seeded planted-trace set: %d traces (%d violations, %d benign)." % (
        results["n_traces"], results["n_violations"], results["n_benign"]))
    lines.append("")
    lines.append("| Method | Precision | Recall | TP | FP | FN |")
    lines.append("|---|---|---|---|---|---|")
    for key, name in (("auditor", "Deputy Graph Audit"),
                      ("per_call_baseline", "Per-call permission check"),
                      ("keyword_baseline", "Keyword heuristic")):
        row = results[key]
        lines.append("| %s | %.4f | %.4f | %d | %d | %d |" % (
            name, row["precision"], row["recall"], row["tp"], row["fp"], row["fn"]))
    lines.append("")
    lines.append("Minimal-path exactness (correctly detected violations): %.4f (%d/%d)" % (
        results["path_exactness"], results["paths_exact"], results["paths_scored"]))
    lines.append("")
    lines.append("Per-pattern recall (auditor):")
    for pattern in sorted(results["per_pattern"]):
        bucket = results["per_pattern"][pattern]
        lines.append("- %s: %d/%d detected (recall %.4f)" % (
            pattern, bucket["detected"], bucket["n"], bucket["recall"]))
    lines.append("")
    lines.append("Caveat: traces are synthetic and seeded; ground truth is planted by "
                 "construction. The auditor implements the rule that defines the "
                 "labels, so its scores measure implementation correctness and the "
                 "baselines' structural blindness - not performance on real agent logs.")
    return "\n".join(lines) + "\n"
