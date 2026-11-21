"""Deputy Graph Audit: offline provenance-graph auditing of agent traces.

Finds confused-deputy privilege escalations: actions whose required
privilege exceeds the trust of their authorising causal ancestors.
"""
from deputy_graph_audit.models import Node, Trace, Policy, Violation
from deputy_graph_audit.audit import audit_trace

__version__ = "0.1.0"
__author__ = "Amna Raheeba"
__all__ = ["Node", "Trace", "Policy", "Violation", "audit_trace", "__version__"]
