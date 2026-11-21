from deputy_graph_audit.audit import audit_trace, audit_traces, minimal_escalation_path
from deputy_graph_audit.graph import effective_trust
from deputy_graph_audit.models import Node, Policy, Trace

POLICY = Policy.default()


def trace(nodes, **kw):
    return Trace(kw.pop("trace_id", "t"), nodes, **kw)


def test_direct_escalation_flagged():
    t = trace([
        Node("doc", "source", source_type="retrieved_document"),
        Node("act", "action", tool="delete_records", required_privilege=3, parents=["doc"]),
    ])
    violations = audit_trace(t, POLICY)
    assert len(violations) == 1
    assert violations[0].required == 3
    assert violations[0].inherited_trust == 0


def test_user_authorised_passes():
    t = trace([
        Node("user", "source", source_type="user_instruction"),
        Node("act", "action", tool="write_workspace", required_privilege=2, parents=["user"]),
    ])
    assert audit_trace(t, POLICY) == []


def test_verified_untrusted_passes():
    t = trace([
        Node("doc", "source", source_type="web_page"),
        Node("check", "approval", trust=3, parents=["doc"]),
        Node("act", "action", tool="make_payment", required_privilege=3, parents=["check"]),
    ])
    assert audit_trace(t, POLICY) == []


def test_low_privilege_on_untrusted_passes():
    t = trace([
        Node("doc", "source", source_type="web_page"),
        Node("act", "action", tool="read_public_data", required_privilege=0, parents=["doc"]),
    ])
    assert audit_trace(t, POLICY) == []


def test_tool_output_to_restricted_flagged():
    t = trace([
        Node("out", "source", source_type="tool_output"),
        Node("act", "action", tool="send_external", required_privilege=3, parents=["out"]),
    ])
    violations = audit_trace(t, POLICY)
    assert len(violations) == 1
    assert violations[0].inherited_trust == 1


def test_equal_trust_and_requirement_passes():
    t = trace([
        Node("out", "source", source_type="tool_output"),
        Node("act", "action", tool="search_internal", required_privilege=1, parents=["out"]),
    ])
    assert audit_trace(t, POLICY) == []


def test_requirement_from_policy_when_undeclared():
    t = trace([
        Node("doc", "source", source_type="web_page"),
        Node("act", "action", tool="send_external", parents=["doc"]),
    ])
    assert len(audit_trace(t, POLICY)) == 1


def test_bypass_verification_still_flagged():
    t = trace([
        Node("doc", "source", source_type="web_page"),
        Node("other", "source", source_type="web_page"),
        Node("check", "verification", trust=3, parents=["other"]),
        Node("act", "action", tool="send_external", required_privilege=3, parents=["doc"]),
    ])
    violations = audit_trace(t, POLICY)
    assert len(violations) == 1
    assert "check" not in violations[0].path


def test_multiple_actions_scored_independently():
    t = trace([
        Node("user", "source", source_type="user_instruction"),
        Node("doc", "source", source_type="web_page"),
        Node("ok", "action", tool="write_workspace", required_privilege=2, parents=["user"]),
        Node("bad", "action", tool="send_external", required_privilege=3, parents=["doc"]),
    ])
    violations = audit_trace(t, POLICY)
    assert [v.action_id for v in violations] == ["bad"]


def test_audit_traces_maps_ids():
    t = trace([Node("doc", "source", source_type="web_page"),
               Node("act", "action", tool="send_external", parents=["doc"])])
    found = audit_traces([t], POLICY)
    assert list(found) == ["t"]
    assert len(found["t"]) == 1


def test_minimal_path_two_hop():
    t = trace([
        Node("doc", "source", source_type="web_page"),
        Node("sum", "action", tool="summarise", parents=["doc"]),
        Node("act", "action", tool="send_external", parents=["sum"]),
    ])
    path, source = minimal_escalation_path(t, "act", effective_trust(t, POLICY))
    assert path == ["doc", "sum", "act"]
    assert source == "doc"


def test_minimal_path_three_hop():
    t = trace([
        Node("doc", "source", source_type="web_page"),
        Node("a", "action", tool="summarise", parents=["doc"]),
        Node("b", "action", tool="summarise", parents=["a"]),
        Node("act", "action", tool="send_external", parents=["b"]),
    ])
    path, _source = minimal_escalation_path(t, "act", effective_trust(t, POLICY))
    assert path == ["doc", "a", "b", "act"]


def test_minimal_path_prefers_shortest_source():
    t = trace([
        Node("far", "source", source_type="web_page"),
        Node("mid", "action", tool="summarise", parents=["far"]),
        Node("near", "source", source_type="web_page"),
        Node("act", "action", tool="send_external", parents=["mid", "near"]),
    ])
    path, source = minimal_escalation_path(t, "act", effective_trust(t, POLICY))
    assert path == ["near", "act"]
    assert source == "near"


def test_minimal_path_never_crosses_sanitizer():
    t = trace([
        Node("doc", "source", source_type="web_page"),
        Node("check", "verification", trust=3, parents=["doc"]),
        Node("act", "action", tool="send_external", parents=["check", "doc"]),
    ])
    path, _source = minimal_escalation_path(t, "act", effective_trust(t, POLICY))
    assert path == ["doc", "act"]
