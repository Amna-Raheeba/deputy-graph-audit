"""Core data model: nodes, traces, policies, violations.

Trust and privilege share one ordered lattice (a total order of levels):

    0  untrusted   - external / retrieved content nobody vouched for
    1  low         - ordinary tool output, internal memory
    2  user        - a direct instruction from the user
    3  approver    - a human approver or the system policy itself

An action is authorised only if the trust it inherits from its causal
ancestors is at least the privilege the action requires.
"""
import json

LEVELS = {0: "untrusted", 1: "low", 2: "user", 3: "approver"}
SOURCE_TRUST = {
    "external_document": 0,
    "retrieved_document": 0,
    "web_page": 0,
    "tool_output": 1,
    "memory": 1,
    "user_instruction": 2,
    "system_instruction": 3,
}
SANITIZER_KINDS = ("verification", "approval")
NODE_KINDS = ("source", "action", "verification", "approval")


class Node(object):
    """One node in a trace provenance graph."""

    def __init__(self, node_id, kind, label="", tool=None, source_type=None,
                 required_privilege=None, trust=None, parents=None, text=""):
        if kind not in NODE_KINDS:
            raise ValueError("unknown node kind: %s" % kind)
        self.node_id = node_id
        self.kind = kind
        self.label = label or node_id
        self.tool = tool
        self.source_type = source_type
        self.required_privilege = required_privilege
        self.trust = trust
        self.parents = list(parents or [])
        self.text = text or ""

    def base_trust(self, policy=None):
        """Trust this node contributes on its own, before inheritance."""
        if self.trust is not None:
            return int(self.trust)
        if self.kind == "source":
            if self.source_type in SOURCE_TRUST:
                return SOURCE_TRUST[self.source_type]
            raise ValueError("source node %s has no trust" % self.node_id)
        if self.kind in SANITIZER_KINDS:
            raise ValueError("sanitizer node %s needs an explicit trust" % self.node_id)
        return None

    def is_sanitizer(self):
        return self.kind in SANITIZER_KINDS

    def to_dict(self):
        return {
            "id": self.node_id, "kind": self.kind, "label": self.label,
            "tool": self.tool, "source_type": self.source_type,
            "required_privilege": self.required_privilege,
            "trust": self.trust, "parents": list(self.parents),
            "text": self.text,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            node_id=data["id"], kind=data["kind"],
            label=data.get("label", ""), tool=data.get("tool"),
            source_type=data.get("source_type"),
            required_privilege=data.get("required_privilege"),
            trust=data.get("trust"), parents=data.get("parents", []),
            text=data.get("text", ""),
        )


class Trace(object):
    """A recorded agent trace: nodes plus ground-truth labels (optional)."""

    def __init__(self, trace_id, nodes, pattern="unknown", label_violation=False,
                 violating_action=None, planted_path=None, actor_privilege=3):
        self.trace_id = trace_id
        self.nodes = {}
        for node in nodes:
            if node.node_id in self.nodes:
                raise ValueError("duplicate node id %s in trace %s" % (node.node_id, trace_id))
            self.nodes[node.node_id] = node
        for node in nodes:
            for parent in node.parents:
                if parent not in self.nodes:
                    raise ValueError("node %s has unknown parent %s" % (node.node_id, parent))
        self.pattern = pattern
        self.label_violation = bool(label_violation)
        self.violating_action = violating_action
        self.planted_path = list(planted_path or [])
        # The agent process itself holds this much privilege; per-call
        # permission checks compare a tool's requirement against it.
        self.actor_privilege = int(actor_privilege)

    def actions(self):
        return [n for n in self.nodes.values() if n.kind == "action"]

    def to_dict(self):
        return {
            "trace_id": self.trace_id, "pattern": self.pattern,
            "label_violation": self.label_violation,
            "violating_action": self.violating_action,
            "planted_path": list(self.planted_path),
            "actor_privilege": self.actor_privilege,
            "nodes": [n.to_dict() for n in self.nodes.values()],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            trace_id=data["trace_id"],
            nodes=[Node.from_dict(n) for n in data["nodes"]],
            pattern=data.get("pattern", "unknown"),
            label_violation=data.get("label_violation", False),
            violating_action=data.get("violating_action"),
            planted_path=data.get("planted_path", []),
            actor_privilege=data.get("actor_privilege", 3),
        )


class Policy(object):
    """A declared privilege lattice: tool requirements and level names."""

    def __init__(self, tools, levels=None):
        self.tools = dict(tools)
        self.levels = dict(levels or LEVELS)
        for name, level in self.tools.items():
            if int(level) not in self.levels:
                raise ValueError("tool %s requires unknown level %s" % (name, level))

    def required(self, tool):
        if tool not in self.tools:
            raise ValueError("tool not in policy: %s" % tool)
        return int(self.tools[tool])

    def level_name(self, level):
        return self.levels[int(level)]

    def to_dict(self):
        return {"tools": dict(self.tools),
                "levels": dict((str(k), v) for k, v in self.levels.items())}

    @classmethod
    def from_dict(cls, data):
        levels = dict((int(k), v) for k, v in data.get("levels", {}).items())
        return cls(tools=data["tools"], levels=levels or None)

    @classmethod
    def default(cls):
        return cls(tools={
            "read_public_data": 0,
            "summarise": 0,
            "search_internal": 1,
            "draft_message": 1,
            "write_workspace": 2,
            "send_external": 3,
            "delete_records": 3,
            "make_payment": 3,
        })


class Violation(object):
    """One flagged action with its minimal escalation path."""

    def __init__(self, trace_id, action_id, required, inherited_trust, path, source_id):
        self.trace_id = trace_id
        self.action_id = action_id
        self.required = int(required)
        self.inherited_trust = int(inherited_trust)
        self.path = list(path)
        self.source_id = source_id

    def to_dict(self):
        return {
            "trace_id": self.trace_id, "action_id": self.action_id,
            "required": self.required, "inherited_trust": self.inherited_trust,
            "path": list(self.path), "source_id": self.source_id,
        }

    def __repr__(self):
        return "Violation(%s: %s requires %d, inherited %d, path %s)" % (
            self.trace_id, self.action_id, self.required,
            self.inherited_trust, "->".join(self.path))


def load_traces(path):
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if isinstance(raw, dict):
        raw = raw["traces"]
    return [Trace.from_dict(item) for item in raw]


def load_policy(path):
    with open(path, "r", encoding="utf-8") as handle:
        return Policy.from_dict(json.load(handle))
