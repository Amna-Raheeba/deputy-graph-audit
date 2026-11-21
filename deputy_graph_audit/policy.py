"""Policy helpers: lattice sanity checks over a declared policy."""
from deputy_graph_audit.models import Policy


def validate_policy(policy):
    """Return a list of problems with the policy (empty means valid)."""
    problems = []
    if not policy.tools:
        problems.append("policy declares no tools")
    levels = sorted(policy.levels)
    if levels != list(range(len(levels))):
        problems.append("lattice levels must be contiguous from 0, got %s" % levels)
    for name, level in sorted(policy.tools.items()):
        if int(level) < 0:
            problems.append("tool %s has negative level %s" % (name, level))
    return problems


def lattice_table(policy):
    """Rows of (level, name, tools at that level) for display."""
    rows = []
    for level in sorted(policy.levels):
        tools = sorted(n for n, req in policy.tools.items() if int(req) == level)
        rows.append((level, policy.levels[level], tools))
    return rows


def default_policy():
    return Policy.default()
