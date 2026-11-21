"""Streamlit dashboard for Deputy Graph Audit (3 tabs)."""
import json
import os

import streamlit as st

from deputy_graph_audit.audit import audit_trace
from deputy_graph_audit.baselines import keyword_heuristic, per_call_check
from deputy_graph_audit.graph import effective_trust
from deputy_graph_audit.models import Policy, load_traces
from deputy_graph_audit.policy import lattice_table
from deputy_graph_audit.report import trace_report

ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_results():
    path = os.path.join(ROOT, "results", "evaluation.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return None


def main():
    st.set_page_config(page_title="Deputy Graph Audit", layout="wide")
    st.title("Deputy Graph Audit")
    st.write("Offline provenance-graph auditing of agent tool-call traces: "
             "find the actions that untrusted content, not the user, authorised.")
    policy = Policy.default()
    tab_audit, tab_lattice, tab_eval = st.tabs(
        ["Audit a trace", "Privilege lattice", "Evaluation"])

    with tab_audit:
        traces = load_traces(os.path.join(ROOT, "data", "hand_traces.json"))
        labels = [t.trace_id + " (" + t.pattern + ")" for t in traces]
        choice = st.selectbox("Hand-written trace", labels)
        trace = traces[labels.index(choice)]
        trust = effective_trust(trace, policy)
        rows = []
        for node_id in sorted(trace.nodes):
            node = trace.nodes[node_id]
            rows.append({
                "node": node_id, "kind": node.kind, "tool": node.tool or "-",
                "required": node.required_privilege,
                "inherited_trust": trust[node_id],
                "parents": ", ".join(node.parents) or "-",
            })
        st.table(rows)
        violations = audit_trace(trace, policy)
        st.code(trace_report(trace, violations))
        st.write("Per-call baseline flags: %s" % per_call_check(trace, policy))
        st.write("Keyword baseline flags: %s" % keyword_heuristic(trace, policy))

    with tab_lattice:
        rows = []
        for level, name, tools in lattice_table(policy):
            rows.append({"level": level, "name": name, "tools": ", ".join(tools)})
        st.table(rows)
        st.write("Trust flows downhill: an action inherits the lowest trust of "
                 "its causal ancestors. Verification and approval nodes are "
                 "sanitizers - content they check inherits their trust instead.")

    with tab_eval:
        results = _load_results()
        if results is None:
            st.write("No results yet - run: python -m deputy_graph_audit evaluate")
        else:
            st.write("Seeded set: %d traces, %d planted violations, %d benign." % (
                results["n_traces"], results["n_violations"], results["n_benign"]))
            rows = []
            for key, name in (("auditor", "Deputy Graph Audit"),
                              ("per_call_baseline", "Per-call check"),
                              ("keyword_baseline", "Keyword heuristic")):
                row = results[key]
                rows.append({"method": name, "precision": row["precision"],
                             "recall": row["recall"]})
            st.table(rows)
            st.write("Minimal-path exactness: %.4f (%d/%d)" % (
                results["path_exactness"], results["paths_exact"],
                results["paths_scored"]))
            try:
                import matplotlib
                matplotlib.use("Agg")
                import matplotlib.pyplot as plt
                patterns = sorted(results["per_pattern"])
                recalls = [results["per_pattern"][p]["recall"] for p in patterns]
                fig, ax = plt.subplots(figsize=(8, 3))
                ax.barh(patterns, recalls)
                ax.set_xlim(0, 1.05)
                ax.set_xlabel("auditor recall")
                st.pyplot(fig)
            except Exception:
                st.write("Per-pattern recall: %s" % results["per_pattern"])


if __name__ == "__main__":
    main()
