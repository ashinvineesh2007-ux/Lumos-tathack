"""
app/schemas.py — RAGLeak Data Contracts & Pydantic Models

All inter-module data flows are typed here. Nothing outside this file
should define its own ad-hoc dicts for RAG/audit payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SystemMode(str, Enum):
    """
    Controls whether the RAG pipeline enforces authorization.

    - BASELINE : Intentionally unprotected. ALL retrieved chunks reach the LLM
                 regardless of the requester's clearance. Used to *demonstrate*
                 the leakage vulnerability in audit comparisons.
    - PROTECTED: Server-side RBAC filter runs BEFORE context construction.
                 Only chunks the user is cleared for are passed to the LLM.
    """
    BASELINE  = "baseline"
    PROTECTED = "protected"


class AccessLevel(str, Enum):
    """Document sensitivity tiers, ordered by clearance requirement."""
    PUBLIC       = "PUBLIC"        # Clearance 1+
    INTERNAL     = "INTERNAL"      # Clearance 2+
    CONFIDENTIAL = "CONFIDENTIAL"  # Clearance 3+


class UserRole(str, Enum):
    """Canonical user roles in the clearance matrix."""
    GUEST    = "GUEST"
    EMPLOYEE = "EMPLOYEE"
    MANAGER  = "MANAGER"
    ADMIN    = "ADMIN"


class AuthDecision(str, Enum):
    """Outcome of a single document-level access evaluation."""
    ALLOW = "ALLOW"
    DENY  = "DENY"


# ---------------------------------------------------------------------------
# Per-Document Authorization Metadata
# ---------------------------------------------------------------------------

class DocumentAuthMeta(BaseModel):
    """
    Describes a single document chunk and the authorization decision
    made for it during a retrieval event.

    This is the core audit unit — one record per (query, document) pair.
    """
    doc_id          : str         = Field(...,  description="Unique document identifier")
    title           : str         = Field(...,  description="Human-readable document title")
    access_level    : AccessLevel = Field(...,  description="Document's required clearance tier")
    similarity_score: float       = Field(...,  description="Cosine similarity to the query vector", ge=0.0, le=1.0)
    decision        : AuthDecision= Field(...,  description="ALLOW or DENY for this retrieval event")
    policy_reason   : str         = Field(...,  description="Plain-English explanation of the decision")

    # Populated only when decision == ALLOW (snippet passed to LLM context)
    content_snippet : Optional[str] = Field(
        default=None,
        description="The text chunk included in LLM context (None when DENY)"
    )


# ---------------------------------------------------------------------------
# API Request / Response Contracts
# ---------------------------------------------------------------------------

class QueryRequest(BaseModel):
    """
    Incoming query from the frontend or test client.

    The `user_id` maps to the static clearance matrix defined in security.py.
    The `mode` selects baseline (leaky demo) vs protected (secure) execution.
    """
    user_id  : str        = Field(...,  description="User identifier (e.g. 'emp_alice')", min_length=1, max_length=64)
    query    : str        = Field(...,  description="Natural-language question to the RAG assistant", min_length=3, max_length=4096)
    mode     : SystemMode = Field(
        default=SystemMode.PROTECTED,
        description="'baseline' leaks all chunks; 'protected' enforces RBAC"
    )
    top_k    : int        = Field(
        default=5,
        description="Max number of candidate documents to retrieve before filtering",
        ge=1,
        le=20
    )

    @field_validator("user_id")
    @classmethod
    def user_id_lowercase(cls, v: str) -> str:
        return v.strip().lower()


class QueryResponse(BaseModel):
    """
    Full response envelope returned by POST /query.

    Includes the LLM (or fallback) answer, every authorization decision made
    during retrieval, and a summary of the leakage surface.
    """
    request_id      : str                    = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique ID for this request/response pair"
    )
    user_id         : str                    = Field(..., description="Resolved user identity")
    user_role       : UserRole               = Field(..., description="Role resolved from clearance matrix")
    user_clearance  : int                    = Field(..., description="Numeric clearance level (1–3)")
    mode            : SystemMode             = Field(..., description="Execution mode used")
    query           : str                    = Field(..., description="Original query text")

    # Authorization decisions for every candidate document
    auth_decisions  : List[DocumentAuthMeta] = Field(
        default_factory=list,
        description="One entry per retrieved candidate document"
    )

    # Context actually sent to the LLM (empty list in full-deny scenarios)
    context_sent    : List[str]              = Field(
        default_factory=list,
        description="Ordered list of text chunks passed to the LLM/fallback"
    )

    # Final answer from LLM or deterministic offline fallback
    answer          : str                    = Field(..., description="Generated answer")

    # Leakage surface summary (useful for dashboard)
    docs_retrieved  : int = Field(..., description="Total candidate documents before filtering")
    docs_allowed    : int = Field(..., description="Docs that passed the authorization filter")
    docs_denied     : int = Field(..., description="Docs blocked by server-side policy")

    timestamp       : datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of response generation"
    )


# ---------------------------------------------------------------------------
# Audit Event — Immutable Record for the Audit Log
# ---------------------------------------------------------------------------

class AuditEvent(BaseModel):
    """
    Immutable audit record appended to the in-memory audit log after
    every query, regardless of mode. Consumed by GET /audit/logs.

    Design note: this is a *flat* record (not nested) so it can be serialised
    directly to JSONL or a DataFrame for the Auditor dashboard.
    """
    event_id        : str        = Field(default_factory=lambda: str(uuid4()))
    timestamp       : datetime   = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Identity
    user_id         : str        = Field(...)
    user_role       : UserRole   = Field(...)
    user_clearance  : int        = Field(...)

    # Query context
    request_id      : str        = Field(...)
    query_text      : str        = Field(...)
    mode            : SystemMode = Field(...)

    # Per-document decision (flat for easy tabular export)
    doc_id          : str        = Field(...)
    doc_title       : str        = Field(...)
    doc_access_level: AccessLevel= Field(...)
    similarity_score: float      = Field(...)
    decision        : AuthDecision= Field(...)
    policy_reason   : str        = Field(...)

    # Was this chunk's content exposed to the LLM?
    content_exposed : bool       = Field(
        ...,
        description="True when the chunk text reached the LLM context window"
    )
