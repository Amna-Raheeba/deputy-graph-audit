from deputy_graph_audit.audit import audit_trace
from deputy_graph_audit.evaluate import evaluate
from deputy_graph_audit.generate import generate_traces
from deputy_graph_audit.models import Node, Policy, Trace
from deputy_graph_audit.report import evaluation_summary, trace_report


def test_trace_report_violation():
    t = Trace("t", [
        Node("doc", "source", source_type="web_page"),
        Node("act", "action", tool="send_external", required_privilege=3, parents=["doc"]),
    ])
    text = trace_report(t, audit_trace(t, Policy.default()))
    assert "VIOLATION act" in text
    assert "doc -> act" in text


def test_trace_report_clean():
    t = Trace("t", [
        Node("user", "source", source_type="user_instruction"),
        Node("act", "action", tool="write_workspace", required_privilege=2, parents=["user"]),
    ])
    text = trace_report(t, audit_trace(t, Policy.default()))
    assert "No violations" in text


def test_evaluation_summary_contents():
    results = evaluate(generate_traces(), Policy.default())
    text = evaluation_summary(results)
    assert "Deputy Graph Audit" in text
    assert "Per-call permission check" in text
    assert "Caveat" in text
