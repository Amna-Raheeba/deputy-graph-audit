"""Notebook 01 (as a runnable script): audit the demo trace by hand."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from deputy_graph_audit.audit import audit_trace
from deputy_graph_audit.baselines import per_call_check
from deputy_graph_audit.cli import DEMO_TRACE
from deputy_graph_audit.graph import effective_trust
from deputy_graph_audit.models import Policy, Trace
from deputy_graph_audit.report import trace_report


def main():
    trace = Trace.from_dict(DEMO_TRACE)
    policy = Policy.default()
    print("Effective trust per node:")
    trust = effective_trust(trace, policy)
    for node_id in sorted(trust):
        print("  %s: %d" % (node_id, trust[node_id]))
    violations = audit_trace(trace, policy)
    print("")
    print(trace_report(trace, violations))
    print("")
    print("Per-call baseline flags: %s (the escalation is invisible to it)" % (
        per_call_check(trace, policy)))


if __name__ == "__main__":
    main()
