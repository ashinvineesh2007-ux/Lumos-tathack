"""
app/security.py — Deterministic Server-Side Authorization Gateway

Enforces fail-closed, document-level Access Control Lists (ACLs) and clearance tiers
before retrieved candidates can reach the LLM context window.

Key Principles:
1. Trusted Identity Resolution: Never trust client-supplied roles. Roles and clearance
   levels are looked up exclusively from the trusted server-side directory.
2. Fail-Closed Security: Unknown users, missing clearances, or policy errors default
   strictly to DENY.
3. Deterministic Policy: Clearance alone does NOT override restrictive document-level ACLs.
4. Content Redaction: Denied documents strictly have content_snippet=None and are excluded
   from the protected context.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from threading import Lock
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from pydantic import BaseModel, Field

from app.data_store import SearchResult, KnowledgeDocument
from app.schemas import (
    AccessLevel,
    AuthDecision,
    AuditEvent,
    DocumentAuthMeta,
    SystemMode,
    UserRole,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class UserContext(BaseModel):
    """Server-resolved user identity context."""
    user_id: str = Field(..., max_length=64, description="Unique user identifier (normalized lowercase)")
    name: str = Field(..., description="Full employee name")
    role: UserRole = Field(..., description="Assigned role from trusted registry")
    clearance: int = Field(..., description="Clearance level: 1 (Public), 2 (Internal), 3 (Confidential)")
    department: str = Field(..., description="Department or business unit")
    is_active: bool = Field(default=True, description="Account active status")


class DocumentACL(BaseModel):
    """Document-specific access control list."""
    doc_id: str
    allowed_roles: Optional[Set[UserRole]] = None
    allowed_users: Optional[Set[str]] = None
    min_clearance: Optional[int] = None
    require_department_match: Optional[str] = None


# ---------------------------------------------------------------------------
# Canonical Clearance Hierarchy & Server-Side Directory
# ---------------------------------------------------------------------------

ROLE_CLEARANCE: Dict[UserRole, int] = {
    UserRole.GUEST: 1,
    UserRole.EMPLOYEE: 2,
    UserRole.MANAGER: 2,
    UserRole.ADMIN: 3,
}

ACCESS_LEVEL_MIN_CLEARANCE: Dict[AccessLevel, int] = {
    AccessLevel.PUBLIC: 1,
    AccessLevel.INTERNAL: 2,
    AccessLevel.CONFIDENTIAL: 3,
}

# Fixed server-side identity directory (simulated enterprise IAM)
USER_DIRECTORY: Dict[str, UserContext] = {
    "ext_guest": UserContext(
        user_id="ext_guest",
        name="External Guest Visitor",
        role=UserRole.GUEST,
        clearance=1,
        department="External",
    ),
    "guest_anon": UserContext(
        user_id="guest_anon",
        name="Anonymous External Guest",
        role=UserRole.GUEST,
        clearance=1,
        department="External",
    ),
    "guest": UserContext(
        user_id="guest",
        name="Guest Visitor",
        role=UserRole.GUEST,
        clearance=1,
        department="External",
    ),
    "emp_alice": UserContext(
        user_id="emp_alice",
        name="Alice Smith",
        role=UserRole.EMPLOYEE,
        clearance=2,
        department="Engineering",
    ),
    "emp_bob": UserContext(
        user_id="emp_bob",
        name="Bob Jones",
        role=UserRole.EMPLOYEE,
        clearance=2,
        department="Procurement",
    ),
    "mgr_bob": UserContext(
        user_id="mgr_bob",
        name="Bob Martinez",
        role=UserRole.MANAGER,
        clearance=2,
        department="Operations",
    ),
    "mgr_carol": UserContext(
        user_id="mgr_carol",
        name="Carol Danvers",
        role=UserRole.MANAGER,
        clearance=2,
        department="Human Resources",
    ),
    "adm_charlie": UserContext(
        user_id="adm_charlie",
        name="Charlie Vance",
        role=UserRole.ADMIN,
        clearance=3,
        department="IT Security",
    ),
    "admin_dave": UserContext(
        user_id="admin_dave",
        name="Dave Bowman",
        role=UserRole.ADMIN,
        clearance=3,
        department="Security",
    ),
}

# Document-specific ACL rules
# Notice: Restrictive ACLs override blanket clearance!
DOCUMENT_ACLS: Dict[str, DocumentACL] = {
    "DOC-010": DocumentACL(
        doc_id="DOC-010",
        min_clearance=3,
        allowed_roles={UserRole.ADMIN},
    ),
    "DOC-011": DocumentACL(
        doc_id="DOC-011",
        min_clearance=3,
        allowed_roles={UserRole.ADMIN},
    ),
    "DOC-012": DocumentACL(
        doc_id="DOC-012",
        min_clearance=2,
        # Restrictive user ACL: only designated administrators and Carol (HR manager) are permitted.
        allowed_users={"admin_dave", "adm_charlie", "mgr_carol"},
    ),
    "DOC-013": DocumentACL(
        doc_id="DOC-013",
        min_clearance=3,
        allowed_roles={UserRole.ADMIN},
    ),
    "INJ-001": DocumentACL(
        doc_id="INJ-001",
        min_clearance=2,
        allowed_roles={UserRole.EMPLOYEE, UserRole.MANAGER, UserRole.ADMIN},
    ),
    "INJ-002": DocumentACL(
        doc_id="INJ-002",
        min_clearance=2,
        allowed_roles={UserRole.MANAGER, UserRole.ADMIN},
    ),
}


# ---------------------------------------------------------------------------
# Identity Resolution
# ---------------------------------------------------------------------------

def resolve_user_context(user_id: Optional[str]) -> Optional[UserContext]:
    """
    Resolve trusted user context from the server-side directory.

    Security guarantees:
    - Normalizes user_id (strip, lowercase).
    - Unknown, inactive, or malformed user IDs return None (fail-closed).
    - Never trusts client-supplied roles.
    """
    if not user_id or not isinstance(user_id, str):
        return None

    normalized_id = user_id.strip().lower()
    user = USER_DIRECTORY.get(normalized_id)
    if user is None or not user.is_active:
        return None

    return user


# ---------------------------------------------------------------------------
# Authorization Decision Engine
# ---------------------------------------------------------------------------

def evaluate_document_access(
    user: Optional[UserContext],
    doc: Any = None,
    access_level: Optional[AccessLevel] = None,
    doc_id: Optional[str] = None,
) -> Tuple[AuthDecision, str]:
    """
    Evaluate if a user is authorized to access a given document.

    Supports multiple call styles:
    - evaluate_document_access(user, doc): doc can be KnowledgeDocument or SearchResult.
    - evaluate_document_access(user, doc_id, access_level): positional arguments.
    - evaluate_document_access(user=user, doc_id="DOC-001", access_level=AccessLevel.PUBLIC): keyword arguments.

    Evaluates:
    1. Identity validity (fail-closed: unauthenticated / missing user -> DENY).
    2. Baseline clearance tier vs. document requirement.
    3. Document-specific ACLs (explicit user/role sets take precedence).

    Returns:
        (AuthDecision.ALLOW | AuthDecision.DENY, policy_reason)
    """
    if user is None:
        return (
            AuthDecision.DENY,
            "Deny: Unauthenticated or unknown identity (fail-closed default).",
        )

    # Resolve target document identifier and clearance level polymorphically
    target = doc if doc is not None else doc_id
    if target is None:
        return (
            AuthDecision.DENY,
            "Deny: Missing document reference (fail-closed default).",
        )

    if isinstance(target, str):
        target_id = target
        lvl = access_level if access_level is not None else AccessLevel.CONFIDENTIAL
    else:
        target_id = getattr(target, "doc_id", str(target))
        lvl = (
            access_level
            if access_level is not None
            else getattr(target, "clearance", getattr(target, "access_level", AccessLevel.CONFIDENTIAL))
        )

    acl = DOCUMENT_ACLS.get(target_id)
    # ACL min_clearance if explicitly set, else base tier clearance
    required_clearance = (
        acl.min_clearance
        if (acl and acl.min_clearance is not None)
        else ACCESS_LEVEL_MIN_CLEARANCE.get(lvl, 3)
    )

    if user.clearance < required_clearance:
        return (
            AuthDecision.DENY,
            f"Deny: Insufficient clearance. Document requires {lvl.value} "
            f"(clearance {required_clearance}), but user '{user.user_id}' has clearance {user.clearance}.",
        )

    if acl:
        # Restrictive user ACL: if specified, user MUST be in the allowed set
        if acl.allowed_users is not None and user.user_id not in acl.allowed_users:
            return (
                AuthDecision.DENY,
                f"Deny: Restrictive ACL requires user membership in {sorted(acl.allowed_users)}; "
                f"user '{user.user_id}' is not in allowed list.",
            )

        # Restrictive role ACL: if specified, user MUST hold one of the allowed roles
        if acl.allowed_roles is not None and user.role not in acl.allowed_roles:
            role_names = [r.value for r in acl.allowed_roles]
            return (
                AuthDecision.DENY,
                f"Deny: Restrictive ACL requires role in {role_names}; "
                f"user role is {user.role.value}.",
            )

        # Restrictive department ACL: if specified, user department MUST match
        if acl.require_department_match is not None:
            if not user.department or user.department.strip().lower() != acl.require_department_match.strip().lower():
                return (
                    AuthDecision.DENY,
                    f"Deny: Restrictive ACL requires department '{acl.require_department_match}'; "
                    f"user '{user.user_id}' department is '{user.department}'.",
                )

    return (
        AuthDecision.ALLOW,
        f"Allow: User '{user.user_id}' meets {lvl.value} clearance requirement and ACL checks.",
    )


def filter_candidates(
    user: Optional[UserContext],
    candidates: List[SearchResult],
    snippet_max_chars: int = 300,
) -> Tuple[List[DocumentAuthMeta], List[str]]:
    """
    Filter retrieved candidate documents using the server-side authorization gateway.

    Parameters:
    -----------
    user: Resolved user context, or None.
    candidates: Raw retrieval results from InMemoryIndex.search().
    snippet_max_chars: Maximum character length for allowed content snippets.

    Returns:
    --------
    Tuple of:
    1. auth_decisions: List of DocumentAuthMeta records for each candidate.
       Crucially: content_snippet is None whenever decision == DENY.
    2. authorized_context: List of content texts for allowed documents ONLY.
    """
    auth_decisions: List[DocumentAuthMeta] = []
    authorized_context: List[str] = []

    for cand in candidates:
        decision, reason = evaluate_document_access(
            user=user,
            doc_id=cand.doc_id,
            access_level=cand.clearance,
        )

        snippet: Optional[str] = None
        if decision == AuthDecision.ALLOW:
            snippet = cand.content[:snippet_max_chars]
            authorized_context.append(cand.content)

        meta = DocumentAuthMeta(
            doc_id=cand.doc_id,
            title=cand.title,
            access_level=cand.clearance,
            similarity_score=round(cand.score, 4),
            decision=decision,
            policy_reason=reason,
            content_snippet=snippet,
        )
        auth_decisions.append(meta)

    return auth_decisions, authorized_context


# ---------------------------------------------------------------------------
# In-Memory Thread-Safe Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Thread-safe in-memory store for immutable AuditEvent records."""

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []
        self._purge_history: List[Dict[str, Any]] = []
        self._lock = Lock()

    def record_event(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def record_events(self, events: List[AuditEvent]) -> None:
        with self._lock:
            self._events.extend(events)

    def get_events(
        self,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        decision: Optional[AuthDecision] = None,
        doc_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        with self._lock:
            filtered = list(self._events)

        if user_id:
            uid_norm = user_id.strip().lower()
            filtered = [e for e in filtered if e.user_id.lower() == uid_norm]
        if request_id:
            filtered = [e for e in filtered if e.request_id == request_id]
        if decision:
            filtered = [e for e in filtered if e.decision == decision]
        if doc_id:
            filtered = [e for e in filtered if e.doc_id == doc_id]

        return filtered[-limit:]

    def clear(self, purged_by: Optional[str] = None) -> int:
        """
        Clear in-memory query audit events while appending an entry to purge history.
        Returns the number of purged events.
        """
        with self._lock:
            count = len(self._events)
            self._events.clear()
            self._purge_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "purged_by": purged_by or "system",
                "events_purged": count,
            })
            return count

    def get_purge_history(self) -> List[Dict[str, Any]]:
        """Retrieve recorded log purge history."""
        with self._lock:
            return list(self._purge_history)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


# Global singleton audit logger
_AUDIT_LOGGER = AuditLogger()

def get_audit_logger() -> AuditLogger:
    return _AUDIT_LOGGER
