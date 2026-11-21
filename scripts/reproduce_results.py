"""Recompute the evaluation and fail if the headline numbers drift."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from deputy_graph_audit.evaluate import evaluate
from deputy_graph_audit.generate import generate_traces
from deputy_graph_audit.models import Policy


def main():
    root = os.path.join(os.path.dirname(__file__), "..")
    stored_path = os.path.join(root, "results", "evaluation.json")
    with open(stored_path, "r", encoding="utf-8") as handle:
        stored = json.load(handle)
    fresh = evaluate(generate_traces(), Policy.default())
    keys = ("n_traces", "n_violations", "path_exactness")
    drift = []
    for key in keys:
        if stored[key] != fresh[key]:
            drift.append("%s: stored %s != fresh %s" % (key, stored[key], fresh[key]))
    for key in ("auditor", "per_call_baseline", "keyword_baseline"):
        for metric in ("precision", "recall", "tp", "fp", "fn"):
            if stored[key][metric] != fresh[key][metric]:
                drift.append("%s.%s: stored %s != fresh %s" % (
                    key, metric, stored[key][metric], fresh[key][metric]))
    if drift:
        print("HEADLINE DRIFT DETECTED:")
        for line in drift:
            print(" - " + line)
        return 1
    print("OK: headline numbers reproduce exactly.")
    print("auditor precision %.4f recall %.4f; path exactness %.4f" % (
        fresh["auditor"]["precision"], fresh["auditor"]["recall"],
        fresh["path_exactness"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
