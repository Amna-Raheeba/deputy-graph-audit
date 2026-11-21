from deputy_graph_audit.evaluate import evaluate
from deputy_graph_audit.generate import generate_traces
from deputy_graph_audit.models import Policy

RESULTS = evaluate(generate_traces(), Policy.default())


def test_auditor_perfect_on_planted_set():
    assert RESULTS["auditor"]["precision"] == 1.0
    assert RESULTS["auditor"]["recall"] == 1.0
    assert RESULTS["auditor"]["tp"] == 170
    assert RESULTS["auditor"]["fp"] == 0
    assert RESULTS["auditor"]["fn"] == 0


def test_per_call_baseline_blind():
    assert RESULTS["per_call_baseline"]["recall"] == 0.0
    assert RESULTS["per_call_baseline"]["fn"] == 170


def test_keyword_baseline_partial():
    row = RESULTS["keyword_baseline"]
    assert 0.0 < row["recall"] < 1.0
    assert row["fp"] == 20


def test_path_exactness():
    assert RESULTS["path_exactness"] == 1.0
    assert RESULTS["paths_scored"] == 170


def test_counts():
    assert RESULTS["n_traces"] == 290
    assert RESULTS["n_violations"] == 170
    assert RESULTS["n_benign"] == 120


def test_per_pattern_violation_recall():
    for pattern in ("direct", "two_hop_laundering", "three_hop",
                    "tool_output", "verification_bypass"):
        assert RESULTS["per_pattern"][pattern]["recall"] == 1.0
