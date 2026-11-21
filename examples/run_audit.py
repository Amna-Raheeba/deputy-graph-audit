"""Run the auditor over the hand-written example traces."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from deputy_graph_audit.audit import audit_trace
from deputy_graph_audit.models import Policy, Trace
from deputy_graph_audit.report import trace_report


def main():
    path = os.path.join(os.path.dirname(__file__), "demo_trace.json")
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    policy = Policy.default()
    for item in raw:
        trace = Trace.from_dict(item)
        print(trace_report(trace, audit_trace(trace, policy)))
        print("")


if __name__ == "__main__":
    main()
