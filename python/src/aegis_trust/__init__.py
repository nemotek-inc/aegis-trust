# aegis-trust: AI agent data access control.
#
# The public quickstart surface is intentionally a single decorator. Everything
# else (testing helpers, configuration loaders, advanced types, the optional
# enterprise backend client) lives on submodule paths and stays out of the
# top-level autocomplete to keep the agent-facing surface small and clear:
#
#     from aegis_trust import shield
#     from aegis_trust.pytest_plugin import shield_history, assert_shield_blocked
#     from aegis_trust.config import load_config
#     from aegis_trust.types import Mode  # only if you want to type-annotate the parameter
#
# v0.9.0-rc1 additions:
#     from aegis_trust.errors import AegisError, AegisValidationError, AegisConfigError, ...
#     from aegis_trust.trace import trace_context, new_trace_id, get_trace_context
#     from aegis_trust.history import HistoryStore  # .record_idempotent(key=..., ...)
#
from aegis_trust.shield import ShieldResult, shield, wrap
from aegis_trust.ai_native import (
    StreamSession,
    current_capability,
    delegate,
    guard_tool,
    stream_session,
)
from aegis_trust.errors import (
    AegisError,
    AegisValidationError,
    AegisConfigError,
    AegisIngestError,
    AegisAuditError,
    AegisHttpError,
    AegisStreamDenied,
    AegisStreamRevoked,
    aegis_docs_url,
)
from aegis_trust.attest_verify import (
    AttestCheck,
    AttestExpectation,
    AttestState,
    AttestVerdict,
    advance_state,
    load_state,
    report_arrived_check,
    save_state,
    verify_attestation,
)
from aegis_trust.receipt_verify import (
    compute_lineage_root,
    dangling_prior_receipt_refs,
    session_dag_root,
    verify_lineage_root,
    verify_session_receipt_structure,
)
from aegis_trust.trace import (
    TraceContext,
    trace_context,
    with_trace_context,
    get_trace_context,
    new_trace_id,
)

__all__ = [
    "shield",
    "wrap",
    "ShieldResult",
    "guard_tool",
    "delegate",
    "stream_session",
    "StreamSession",
    "current_capability",
    "AegisStreamDenied",
    "AegisStreamRevoked",
    "AegisError",
    "AegisValidationError",
    "AegisConfigError",
    "AegisIngestError",
    "AegisAuditError",
    "AegisHttpError",
    "aegis_docs_url",
    "TraceContext",
    "trace_context",
    "with_trace_context",
    "get_trace_context",
    "new_trace_id",
    "session_dag_root",
    "verify_session_receipt_structure",
    "dangling_prior_receipt_refs",
    "compute_lineage_root",
    "verify_lineage_root",
    # Core attestation verification (S051 (3)). The SDK verifies Core's
    # statement about a disk; it never re-derives one of its own.
    "verify_attestation",
    "report_arrived_check",
    "advance_state",
    "load_state",
    "save_state",
    "AttestExpectation",
    "AttestState",
    "AttestVerdict",
    "AttestCheck",
    "AEGIS_API_VERSION",
    "AEGIS_API_VERSION_HEADER",
    "AUDIT_SCHEMA_VERSION",
    "STABILITY_LEVEL",
]
__version__ = "0.11.0"

# Schema version for the audit-event shape — single source in `_constants`
# (S017 T4 / D-A). Re-exported here for the public API surface (parity with
# npm aegis-trust AUDIT_SCHEMA_VERSION). Bumped when audit record shape changes.
from aegis_trust._constants import AUDIT_SCHEMA_VERSION

# Stability level — see docs/VERSIONING.md (mirrors npm SDK).
#   "preview"    → v0.x.y-rc* : public API may change between rc tags.
#   "stable"     → v1+        : SemVer breaking change rules apply.
#   "deprecated" → marked for removal in next major.
STABILITY_LEVEL = "preview"

# Aegis-Api-Version dated header (Stripe-model dated API versioning).
# Date-based public contract version. Clients send `Aegis-Api-Version: <YYYY-MM-DD>`;
# unset → SDK uses this default.
# Sunset policy: 18-month notice + 6-month deprecation warning.
AEGIS_API_VERSION = "2026-05-18"
AEGIS_API_VERSION_HEADER = "Aegis-Api-Version"
