"""Trust propagation over the provenance graph.

Rules (the whole mechanism, deliberately small):

1. A source node contributes its declared trust.
2. A verification / approval node is a *sanitizer*: content that passes
   through it inherits the sanitizer's own trust, not the (lower) trust
   of what it checked. A human who read and approved a document lends
   the document their trust downstream.
3. Any other node inherits the *minimum* trust of its parents - trust
   only ever flows downhill through a causal chain, and a chain is as
   trustworthy as its weakest causal ancestor.
4. A node with no parents and no base trust inherits 0 (untrusted):
   an action that appears from nowhere is authorised by nothing.
"""
from deputy_graph_audit.models import LEVELS


def topo_order(trace):
    """Deterministic topological order (parents before children)."""
    order = []
    seen = set()
    visiting = set()

    def visit(node_id):
        if node_id in seen:
            return
        if node_id in visiting:
            raise ValueError("cycle in trace %s at %s" % (trace.trace_id, node_id))
        visiting.add(node_id)
        for parent in sorted(trace.nodes[node_id].parents):
            visit(parent)
        visiting.discard(node_id)
        seen.add(node_id)
        order.append(node_id)

    for node_id in sorted(trace.nodes):
        visit(node_id)
    return order


def effective_trust(trace, policy=None):
    """Map node id -> inherited trust, for every node in the trace."""
    trust = {}
    for node_id in topo_order(trace):
        node = trace.nodes[node_id]
        base = node.base_trust(policy)
        if node.is_sanitizer():
            trust[node_id] = int(base)
        elif node.kind == "source":
            trust[node_id] = int(base)
        elif not node.parents:
            trust[node_id] = int(base) if base is not None else 0
        else:
            inherited = min(trust[parent] for parent in node.parents)
            if base is not None:
                inherited = min(inherited, int(base))
            trust[node_id] = inherited
    return trust


def required_privilege(node, policy):
    """Privilege an action needs: its declared value, else the policy's."""
    if node.required_privilege is not None:
        return int(node.required_privilege)
    if node.tool is not None and policy is not None:
        return policy.required(node.tool)
    raise ValueError("action %s has no required privilege" % node.node_id)


def children_map(trace):
    children = dict((node_id, []) for node_id in trace.nodes)
    for node in trace.nodes.values():
        for parent in node.parents:
            children[parent].append(node.node_id)
    for node_id in children:
        children[node_id].sort()
    return children


def ancestors(trace, node_id):
    """All causal ancestors of a node (excluding the node itself)."""
    found = set()
    stack = list(trace.nodes[node_id].parents)
    while stack:
        current = stack.pop()
        if current in found:
            continue
        found.add(current)
        stack.extend(trace.nodes[current].parents)
    return found


def level_label(level):
    return "%d (%s)" % (int(level), LEVELS[int(level)])
