from deputy_graph_audit.generate import generate_traces, pattern_counts

EXPECTED = {
    "direct": 40, "two_hop_laundering": 40, "three_hop": 30,
    "tool_output": 30, "verification_bypass": 30, "benign_user": 30,
    "benign_verified": 25, "benign_low": 25, "benign_keyword": 20,
    "benign_tool": 20,
}


def test_total_count():
    assert len(generate_traces()) == 290


def test_pattern_counts():
    assert pattern_counts(generate_traces()) == EXPECTED


def test_violation_split():
    traces = generate_traces()
    assert sum(1 for t in traces if t.label_violation) == 170
    assert sum(1 for t in traces if not t.label_violation) == 120


def test_determinism():
    first = [t.to_dict() for t in generate_traces(seed=7)]
    second = [t.to_dict() for t in generate_traces(seed=7)]
    assert first == second


def test_planted_paths_are_real_paths():
    for trace in generate_traces():
        if not trace.label_violation:
            assert trace.planted_path == []
            continue
        assert trace.planted_path[-1] == trace.violating_action
        for parent, child in zip(trace.planted_path, trace.planted_path[1:]):
            assert parent in trace.nodes[child].parents


def test_unique_trace_ids():
    ids = [t.trace_id for t in generate_traces()]
    assert len(set(ids)) == len(ids)
