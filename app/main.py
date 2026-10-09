"""
app/main.py — FastAPI Application & Teammate Integration API

Provides endpoints for:
- Person 1 (Frontend & Dashboard): /health, /config, /config/documents, /query, /api/identities
- Person 3 (AI Security Auditor): /query (baseline vs protected), /audit/logs, /audit/logs/clear
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.data_store import KNOWLEDGE_BASE, get_default_index
from app.rag_engine import execute_rag_pipeline
from app.schemas import (
    AccessLevel,
    AuthDecision,
    AuditEvent,
    QueryRequest,
    QueryResponse,
    SystemMode,
    UserRole,
)
from app.security import USER_DIRECTORY, UserContext, get_audit_logger, resolve_user_context

logger = logging.getLogger(__name__)

# Initialize FastAPI application
app = FastAPI(
    title="RAGLeak Gateway & Security Auditing API",
    description=(
        "A lightweight, zero-latency security testing and enforcement engine "
        "designed to audit and eliminate authorization bypasses in RAG-based AI assistants."
    ),
    version="1.0.0",
)

# Cross-Origin Resource Sharing (CORS) for Person 1 Frontend (Vite / React / Next.js)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Teammate Helper Models
# ---------------------------------------------------------------------------

class UserIdentitySummary(BaseModel):
    user_id: str
    name: str
    role: UserRole
    clearance: int
    department: str


class DocumentSummary(BaseModel):
    doc_id: str
    title: str
    access_level: AccessLevel = Field(..., description="Clearance tier required")
    department: str
    is_injection_test: bool


class SystemConfigResponse(BaseModel):
    service: str
    track: str
    supported_modes: List[str]
    default_mode: str
    mode_descriptions: Dict[str, str]
    clearance_tiers: List[str]
    user_roles: List[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["Root"])
def root_info() -> Dict[str, Any]:
    """Root info returning system name and active track."""
    return {
        "service": "RAGLeak Gateway",
        "track": "Track 2: Safe & Trustworthy AI",
        "description": "Zero-latency security gateway auditing & eliminating RAG authorization bypasses.",
        "docs_url": "/docs",
        "health_url": "/health",
        "config_url": "/config",
    }


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """
    Health check reporting operational status without exposing filesystem or credentials.
    """
    index = get_default_index()
    audit_logger = get_audit_logger()
    return {
        "status": "healthy",
        "backend": index.active_backend,
        "indexed_documents": index.document_count,
        "total_audit_events": len(audit_logger),
    }


@app.get("/config", response_model=SystemConfigResponse, tags=["System"])
def get_system_config() -> SystemConfigResponse:
    """
    Return safe configuration metadata, supported execution modes, and descriptions.
    Never exposes internal filesystem paths or system credentials.
    """
    return SystemConfigResponse(
        service="RAGLeak Gateway",
        track="Track 2: Safe & Trustworthy AI",
        supported_modes=[SystemMode.BASELINE.value, SystemMode.PROTECTED.value],
        default_mode=SystemMode.PROTECTED.value,
        mode_descriptions={
            SystemMode.BASELINE.value: (
                "Intentionally vulnerable demonstration mode that retrieves candidate chunks "
                "by topical relevance and passes all chunks to context without clearance filtering."
            ),
            SystemMode.PROTECTED.value: (
                "Deterministic server-side authorization enforcement gateway filtering candidate "
                "documents by user clearance and document ACLs before context construction."
            ),
        },
        clearance_tiers=[lvl.value for lvl in AccessLevel],
        user_roles=[r.value for r in UserRole],
    )


@app.get("/config/documents", response_model=List[DocumentSummary], tags=["Metadata"])
@app.get("/api/documents", response_model=List[DocumentSummary], tags=["Metadata"])
def list_documents() -> List[DocumentSummary]:
    """
    List corpus documents with clearance tiers and departments.
    Safe metadata only: full document contents and snippets are strictly omitted.
    """
    return [
        DocumentSummary(
            doc_id=doc.doc_id,
            title=doc.title,
            access_level=doc.clearance,
            department=doc.metadata.department,
            is_injection_test=doc.metadata.is_injection_test,
        )
        for doc in KNOWLEDGE_BASE
    ]


@app.post("/query", response_model=QueryResponse, tags=["RAG"])
def query_rag(request: QueryRequest) -> QueryResponse:
    """
    Execute a RAG query in either BASELINE (vulnerable) or PROTECTED (secure) mode.

    - **baseline**: Retrieves by relevance only and forwards all chunks to context (demonstrates leak).
    - **protected**: Enforces server-side clearance and ACL filter before context construction.
    """
    try:
        response = execute_rag_pipeline(request)
        return response
    except Exception as exc:
        logger.error(f"Error processing RAG query: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error evaluating RAG query. Please inspect server logs.",
        )


@app.get("/audit/logs", response_model=List[AuditEvent], tags=["Audit"])
def get_audit_logs(
    caller_id: Optional[str] = Query(None, description="Simulated user ID requesting audit log access"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id", description="User ID in HTTP header"),
    user_id: Optional[str] = Query(None, description="Filter audit events by target user ID"),
    request_id: Optional[str] = Query(None, description="Filter by request ID"),
    decision: Optional[AuthDecision] = Query(None, description="Filter by ALLOW or DENY"),
    doc_id: Optional[str] = Query(None, description="Filter by document ID"),
    limit: int = Query(100, ge=1, le=1000, description="Max records to return"),
) -> List[AuditEvent]:
    """
    Retrieve structured audit event logs for security analysis and dashboards.

    Access Control:
    Restricted to Administrator identities (ADMIN clearance 3) resolved on the server
    via caller_id or X-User-Id header.
    """
    effective_caller = caller_id or x_user_id
    caller = resolve_user_context(effective_caller)

    if caller is None or caller.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Audit logs are restricted to Administrator identities (ADMIN clearance 3).",
        )

    audit_logger = get_audit_logger()
    return audit_logger.get_events(
        user_id=user_id,
        request_id=request_id,
        decision=decision,
        doc_id=doc_id,
        limit=limit,
    )


@app.delete("/audit/logs", tags=["Audit"])
def clear_audit_logs(
    caller_id: Optional[str] = Query(None, description="Simulated user ID requesting audit log reset"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id", description="User ID in HTTP header"),
) -> Dict[str, str]:
    """
    Clear in-memory audit logs (restricted to Administrator callers).
    """
    effective_caller = caller_id or x_user_id
    caller = resolve_user_context(effective_caller)

    if caller is None or caller.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Audit log management is restricted to Administrator identities (ADMIN clearance 3).",
        )

    audit_logger = get_audit_logger()
    audit_logger.clear()
    return {"status": "success", "message": "Audit logs cleared."}


@app.get("/api/identities", response_model=List[UserIdentitySummary], tags=["Metadata"])
def list_identities() -> List[UserIdentitySummary]:
    """
    List simulated user identities for frontend role selectors and auditor harnesses.
    """
    return [
        UserIdentitySummary(
            user_id=u.user_id,
            name=u.name,
            role=u.role,
            clearance=u.clearance,
            department=u.department,
        )
        for u in USER_DIRECTORY.values()
    ]
