import json
import os

from deputy_graph_audit.cli import main


def test_demo_runs(capsys):
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "VIOLATION act" in out
    assert "doc -> sum -> act" in out


def test_default_command_is_demo(capsys):
    assert main([]) == 0
    assert "Demo" in capsys.readouterr().out


def test_audit_hand_traces(capsys):
    root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(root, "data", "hand_traces.json")
    assert main(["audit", path]) == 0
    out = capsys.readouterr().out
    assert "2 violation(s) across 4 trace(s)" in out


def test_evaluate_writes_outputs(tmp_path):
    out_dir = str(tmp_path / "results")
    assert main(["evaluate", "--out", out_dir]) == 0
    for name in ("evaluation.json", "evaluation.csv",
                 "evaluation_summary.md", "HEADLINE.md"):
        assert os.path.exists(os.path.join(out_dir, name))
    with open(os.path.join(out_dir, "evaluation.json")) as handle:
        results = json.load(handle)
    assert results["auditor"]["recall"] == 1.0
