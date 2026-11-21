"""Notebook 02 (as a runnable script): the full seeded evaluation."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from deputy_graph_audit.evaluate import evaluate
from deputy_graph_audit.generate import generate_traces, pattern_counts
from deputy_graph_audit.models import Policy
from deputy_graph_audit.report import evaluation_summary


def main():
    traces = generate_traces()
    print("Pattern counts: %s" % pattern_counts(traces))
    results = evaluate(traces, Policy.default())
    print("")
    print(evaluation_summary(results))


if __name__ == "__main__":
    main()
