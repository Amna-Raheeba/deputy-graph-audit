# Sample audit report

Trace hand-01 (pattern: direct)
VIOLATION act: requires 3 (approver), inherited 0 (untrusted)
  Minimal escalation path: doc -> act
  Authorising source: doc

Trace hand-02 (pattern: benign_user)
No violations: every action is authorised by its causal ancestors.

Trace hand-03 (pattern: benign_verified)
No violations: every action is authorised by its causal ancestors.

Trace hand-04 (pattern: two_hop_laundering)
VIOLATION act: requires 3 (approver), inherited 0 (untrusted)
  Minimal escalation path: doc -> sum -> act
  Authorising source: doc
