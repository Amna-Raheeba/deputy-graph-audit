import pytest

from deputy_graph_audit.graph import ancestors, children_map, effective_trust, topo_order
from deputy_graph_audit.models import Node, Policy, Trace


def make(nodes):
    return Trace("t", nodes)


def test_topo_parents_before_children():
    trace = make([
        Node("act", "action", tool="send_external", parents=["sum"]),
        Node("sum", "action", tool="summarise", parents=["doc"]),
        Node("doc", "source", source_type="web_page"),
    ])
    order = topo_order(trace)
    assert order.index("doc") < order.index("sum") < order.index("act")


def test_cycle_rejected():
    trace = Trace.__new__(Trace)
    trace.trace_id = "t"
    trace.nodes = {
        "a": Node("a", "action", parents=["b"]),
        "b": Node("b", "action", parents=["a"]),
    }
    with pytest.raises(ValueError):
        topo_order(trace)


def test_trust_direct_source():
    trace = make([
        Node("doc", "source", source_type="retrieved_document"),
        Node("act", "action", tool="send_external", parents=["doc"]),
    ])
    assert effective_trust(trace)["act"] == 0


def test_trust_min_of_parents():
    trace = make([
        Node("user", "source", source_type="user_instruction"),
        Node("doc", "source", source_type="web_page"),
        Node("act", "action", tool="send_external", parents=["user", "doc"]),
    ])
    assert effective_trust(trace)["act"] == 0


def test_sanitizer_raises_trust():
    trace = make([
        Node("doc", "source", source_type="web_page"),
        Node("check", "verification", trust=3, parents=["doc"]),
        Node("act", "action", tool="send_external", parents=["check"]),
    ])
    trust = effective_trust(trace)
    assert trust["check"] == 3
    assert trust["act"] == 3


def test_orphan_action_is_untrusted():
    trace = make([Node("act", "action", tool="send_external")])
    assert effective_trust(trace)["act"] == 0


def test_user_trust_flows():
    trace = make([
        Node("user", "source", source_type="user_instruction"),
        Node("act", "action", tool="write_workspace", parents=["user"]),
    ])
    assert effective_trust(trace)["act"] == 2


def test_children_map_and_ancestors():
    trace = make([
        Node("doc", "source", source_type="web_page"),
        Node("sum", "action", tool="summarise", parents=["doc"]),
        Node("act", "action", tool="send_external", parents=["sum"]),
    ])
    assert children_map(trace)["doc"] == ["sum"]
    assert ancestors(trace, "act") == {"doc", "sum"}
    assert ancestors(trace, "doc") == set()


def test_policy_argument_accepted():
    trace = make([Node("doc", "source", source_type="tool_output")])
    assert effective_trust(trace, Policy.default())["doc"] == 1
