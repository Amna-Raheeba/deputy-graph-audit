from deputy_graph_audit.models import Policy
from deputy_graph_audit.policy import lattice_table, validate_policy


def test_default_policy_is_valid():
    assert validate_policy(Policy.default()) == []


def test_empty_policy_flagged():
    problems = validate_policy(Policy(tools={}, levels={0: "untrusted"}))
    assert any("no tools" in p for p in problems)


def test_noncontiguous_levels_flagged():
    policy = Policy(tools={"a": 0}, levels={0: "x", 2: "z"})
    assert any("contiguous" in p for p in validate_policy(policy))


def test_lattice_table_rows():
    rows = lattice_table(Policy.default())
    assert [r[0] for r in rows] == [0, 1, 2, 3]
    assert "send_external" in rows[3][2]
    assert "summarise" in rows[0][2]
