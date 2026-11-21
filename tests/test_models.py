import pytest

from deputy_graph_audit.models import Node, Policy, Trace


def test_node_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Node("x", "widget")


def test_source_trust_defaults_by_type():
    assert Node("a", "source", source_type="retrieved_document").base_trust() == 0
    assert Node("b", "source", source_type="tool_output").base_trust() == 1
    assert Node("c", "source", source_type="user_instruction").base_trust() == 2
    assert Node("d", "source", source_type="system_instruction").base_trust() == 3


def test_source_without_known_type_has_no_trust():
    with pytest.raises(ValueError):
        Node("a", "source", source_type="carrier_pigeon").base_trust()


def test_explicit_trust_overrides_default():
    node = Node("a", "source", source_type="tool_output", trust=0)
    assert node.base_trust() == 0


def test_sanitizer_needs_explicit_trust():
    with pytest.raises(ValueError):
        Node("v", "verification").base_trust()


def test_sanitizer_flag():
    assert Node("v", "approval", trust=3).is_sanitizer()
    assert not Node("a", "action").is_sanitizer()


def test_trace_rejects_duplicate_ids():
    nodes = [Node("a", "source", source_type="tool_output"),
             Node("a", "source", source_type="tool_output")]
    with pytest.raises(ValueError):
        Trace("t", nodes)


def test_trace_rejects_unknown_parent():
    nodes = [Node("a", "action", tool="summarise", parents=["ghost"])]
    with pytest.raises(ValueError):
        Trace("t", nodes)


def test_trace_roundtrip():
    trace = Trace("t1", [
        Node("doc", "source", source_type="web_page", text="hi"),
        Node("act", "action", tool="send_external", required_privilege=3, parents=["doc"]),
    ], pattern="direct", label_violation=True, violating_action="act",
        planted_path=["doc", "act"])
    clone = Trace.from_dict(trace.to_dict())
    assert clone.trace_id == "t1"
    assert clone.planted_path == ["doc", "act"]
    assert clone.nodes["act"].parents == ["doc"]
    assert clone.label_violation is True


def test_actions_filter():
    trace = Trace("t", [
        Node("doc", "source", source_type="web_page"),
        Node("act", "action", tool="summarise"),
    ])
    assert [a.node_id for a in trace.actions()] == ["act"]


def test_policy_default_levels():
    policy = Policy.default()
    assert policy.required("read_public_data") == 0
    assert policy.required("send_external") == 3
    assert policy.level_name(0) == "untrusted"


def test_policy_unknown_tool():
    with pytest.raises(ValueError):
        Policy.default().required("launch_missiles")


def test_policy_rejects_unknown_level():
    with pytest.raises(ValueError):
        Policy(tools={"x": 9})


def test_policy_roundtrip():
    policy = Policy.default()
    clone = Policy.from_dict(policy.to_dict())
    assert clone.tools == policy.tools
    assert clone.levels == policy.levels
