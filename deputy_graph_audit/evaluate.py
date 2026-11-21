"""Evaluation: auditor vs baselines on the seeded planted-trace set.

Action-level scoring. A predicted flag is a true positive when it names
the planted violating action of a violation trace; any flag in a benign
trace, or on the wrong action, is a false positive. Minimal-path
exactness is scored over correctly detected violations only.
"""
from deputy_graph_audit.audit import audit_trace
from deputy_graph_audit.baselines import keyword_heuristic, per_call_check


def _score(flagged_by_trace, traces):
    tp = fp = fn = 0
    for trace in traces:
        flagged = set(flagged_by_trace.get(trace.trace_id, []))
        if trace.label_violation:
            if trace.violating_action in flagged:
                tp += 1
                fp += len(flagged) - 1
            else:
                fn += 1
                fp += len(flagged)
        else:
            fp += len(flagged)
    precision = tp / float(tp + fp) if (tp + fp) else 1.0
    recall = tp / float(tp + fn) if (tp + fn) else 1.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4)}


def evaluate(traces, policy=None):
    auditor_flags = {}
    paths_exact = 0
    paths_scored = 0
    per_pattern = {}
    for trace in traces:
        violations = audit_trace(trace, policy)
        auditor_flags[trace.trace_id] = [v.action_id for v in violations]
        bucket = per_pattern.setdefault(trace.pattern, {"n": 0, "detected": 0})
        bucket["n"] += 1
        if trace.label_violation:
            hit = [v for v in violations if v.action_id == trace.violating_action]
            if hit:
                bucket["detected"] += 1
                paths_scored += 1
                if hit[0].path == trace.planted_path:
                    paths_exact += 1
    for bucket in per_pattern.values():
        viol = bucket["detected"]
        bucket["recall"] = round(viol / float(bucket["n"]), 4) if bucket["n"] else 0.0

    per_call = dict((t.trace_id, per_call_check(t, policy)) for t in traces)
    keyword = dict((t.trace_id, keyword_heuristic(t, policy)) for t in traces)

    n_viol = sum(1 for t in traces if t.label_violation)
    return {
        "n_traces": len(traces),
        "n_violations": n_viol,
        "n_benign": len(traces) - n_viol,
        "auditor": _score(auditor_flags, traces),
        "per_call_baseline": _score(per_call, traces),
        "keyword_baseline": _score(keyword, traces),
        "path_exactness": round(paths_exact / float(paths_scored), 4) if paths_scored else 0.0,
        "paths_scored": paths_scored,
        "paths_exact": paths_exact,
        "per_pattern": per_pattern,
    }
