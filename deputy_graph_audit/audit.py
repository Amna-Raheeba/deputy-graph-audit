"""The auditor: flag under-authorised actions, extract minimal paths."""
from collections import deque

from deputy_graph_audit.graph import effective_trust, required_privilege
from deputy_graph_audit.models import Violation


def minimal_escalation_path(trace, action_id, trust):
    """Shortest unsanitized path from a too-weak source to the action.

    Breadth-first search over the reversed provenance graph, starting at
    the flagged action and walking to parents. Sanitizer nodes are never
    crossed: a path through a verification or approval is authorised by
    that sanitizer, so it cannot be the escalation path. Among shortest
    paths the lexicographically smallest node sequence wins, so the
    result is deterministic.
    """
    # BFS from sources forward is easier to keep exact: search backward
    # from the action collecting candidate paths level by level.
    best = None
    queue = deque()
    queue.append((action_id, [action_id]))
    seen_depth = {action_id: 0}
    while queue:
        node_id, path = queue.popleft()
        node = trace.nodes[node_id]
        if node.kind == "source":
            if best is None or len(path) < len(best):
                best = list(reversed(path))
            continue
        if best is not None and len(path) + 1 > len(best):
            continue
        for parent in sorted(node.parents):
            parent_node = trace.nodes[parent]
            if parent_node.is_sanitizer():
                continue
            depth = len(path) + 1
            if parent in seen_depth and seen_depth[parent] < depth:
                continue
            seen_depth[parent] = depth
            queue.append((parent, path + [parent]))
    if best is None:
        return [action_id], action_id
    return best, best[0]


def audit_trace(trace, policy=None):
    """Return the list of violations in one trace (possibly empty)."""
    trust = effective_trust(trace, policy)
    violations = []
    for action in sorted(trace.actions(), key=lambda n: n.node_id):
        required = required_privilege(action, policy)
        inherited = trust[action.node_id]
        if required > inherited:
            path, source_id = minimal_escalation_path(trace, action.node_id, trust)
            violations.append(Violation(
                trace_id=trace.trace_id, action_id=action.node_id,
                required=required, inherited_trust=inherited,
                path=path, source_id=source_id))
    return violations


def audit_traces(traces, policy=None):
    found = {}
    for trace in traces:
        found[trace.trace_id] = audit_trace(trace, policy)
    return found
