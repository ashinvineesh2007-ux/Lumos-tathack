"""
backend_client.py — RAGLeak Backend API Client

Resilient HTTP client for connecting the Streamlit dashboard to the
FastAPI RAGLeak security testing & evaluation backend (commit 3c7dd33).

Key Design Principles:
1. Strict schema compliance: request & response formats match inspected backend models.
2. Graceful offline fallback: connection failures, timeouts, and HTTP errors return
   structured ApiResponse objects indicating unavailable state (success=False),
   never silently converting failures into fake empty findings.
3. Fail-safe isolation: audit logs require explicit admin authorization and are
   never cleared automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger(__name__)

# Default backend URL configurable via environment variable
DEFAULT_BACKEND_URL: str = os.environ.get(
    "RAGLEAK_BACKEND_URL",
    os.environ.get("BACKEND_URL", "http://localhost:8000"),
).rstrip("/")


@dataclass
class ApiResponse:
    """
    Standardized result wrapper for all backend interactions.

    Attributes:
        success: True if the API call returned an HTTP 2xx response with valid data.
        data: Parsed JSON payload returned by the backend (None on failure).
        error: Human-readable error message explaining why the call failed.
        status_code: HTTP response status code (None on network/timeout errors).
    """

    success: bool
    data: Any = None
    error: Optional[str] = None
    status_code: Optional[int] = None

    @property
    def is_available(self) -> bool:
        """Alias indicating whether backend data was successfully retrieved."""
        return self.success


class RAGLeakClient:
    """
    HTTP client for the RAGLeak evaluation and security gateway.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        default_timeout: float = 3.0,
    ) -> None:
        self.base_url: str = (base_url or DEFAULT_BACKEND_URL).rstrip("/")
        self.default_timeout: float = default_timeout

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> ApiResponse:
        """
        Execute an HTTP request with comprehensive error handling.
        """
        url = f"{self.base_url}{endpoint}"
        effective_timeout = timeout if timeout is not None else self.default_timeout
        request_headers = {"Accept": "application/json"}
        if headers:
            request_headers.update(headers)

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=request_headers,
                timeout=effective_timeout,
            )

            # Handle non-2xx status codes
            if not response.ok:
                error_detail = ""
                try:
                    err_json = response.json()
                    error_detail = err_json.get("detail", str(err_json))
                except Exception:
                    error_detail = response.text.strip() or f"HTTP {response.status_code}"

                logger.warning(
                    f"RAGLeak API error [{response.status_code}] on {method} {endpoint}: {error_detail}"
                )
                return ApiResponse(
                    success=False,
                    data=None,
                    error=f"HTTP {response.status_code}: {error_detail}",
                    status_code=response.status_code,
                )

            # Parse successful 2xx response
            try:
                data = response.json()
                return ApiResponse(
                    success=True,
                    data=data,
                    error=None,
                    status_code=response.status_code,
                )
            except Exception as json_err:
                logger.error(f"Failed to decode JSON from {method} {endpoint}: {json_err}")
                return ApiResponse(
                    success=False,
                    data=None,
                    error=f"Invalid JSON response from backend: {json_err}",
                    status_code=response.status_code,
                )

        except requests.exceptions.Timeout:
            err_msg = f"Request to {endpoint} timed out after {effective_timeout:.1f}s."
            logger.debug(err_msg)
            return ApiResponse(success=False, data=None, error=err_msg, status_code=None)

        except requests.exceptions.ConnectionError:
            err_msg = f"Backend connection failed at {self.base_url}. Service appears offline."
            logger.debug(err_msg)
            return ApiResponse(success=False, data=None, error=err_msg, status_code=None)

        except requests.exceptions.RequestException as req_err:
            err_msg = f"Network request error: {req_err}"
            logger.warning(err_msg)
            return ApiResponse(success=False, data=None, error=err_msg, status_code=None)

    # -----------------------------------------------------------------------
    # System & Metadata Endpoints
    # -----------------------------------------------------------------------

    def get_health(self, timeout: float = 2.0) -> ApiResponse:
        """
        Check backend operational status and retrieval engine.
        GET /health -> {"status": "healthy", "backend": "...", "indexed_documents": 15, ...}
        """
        return self._request("GET", "/health", timeout=timeout)

    def get_config(self, timeout: float = 3.0) -> ApiResponse:
        """
        Retrieve backend configuration metadata, clearance tiers, and supported modes.
        GET /config -> {"service": "...", "supported_modes": ["baseline", "protected"], ...}
        """
        return self._request("GET", "/config", timeout=timeout)

    def get_documents(self, timeout: float = 3.0) -> ApiResponse:
        """
        Retrieve list of synthetic corpus documents and metadata (without raw bodies).
        GET /config/documents -> List of {"doc_id": "...", "title": "...", "access_level": "...", ...}
        """
        return self._request("GET", "/config/documents", timeout=timeout)

    def get_identities(self, timeout: float = 3.0) -> ApiResponse:
        """
        Retrieve list of simulated directory identities and user roles.
        GET /api/identities -> List of {"user_id": "...", "name": "...", "role": "...", "clearance": ...}
        """
        return self._request("GET", "/api/identities", timeout=timeout)

    # -----------------------------------------------------------------------
    # RAG Query Execution Endpoint
    # -----------------------------------------------------------------------

    def execute_query(
        self,
        user_id: str,
        query: str,
        mode: str = "protected",
        top_k: int = 5,
        timeout: float = 10.0,
    ) -> ApiResponse:
        """
        Execute an adversarial or legitimate query through the RAG pipeline.

        Args:
            user_id: User identifier resolved in server directory (e.g. 'emp_alice').
            query: Question text to evaluate (3–4096 characters).
            mode: 'baseline' (intentionally leaks chunks) or 'protected' (enforces RBAC).
            top_k: Number of candidate chunks to retrieve (1–20).
            timeout: Maximum wait time in seconds (default 10.0s for embedding computation).
        """
        normalized_mode = mode.lower().strip()
        if normalized_mode not in ("baseline", "protected"):
            raise ValueError(f"Invalid mode '{mode}'. Must be 'baseline' or 'protected'.")

        if not (1 <= top_k <= 20):
            raise ValueError(f"top_k must be between 1 and 20, got {top_k}.")

        payload = {
            "user_id": user_id.strip().lower(),
            "query": query.strip(),
            "mode": normalized_mode,
            "top_k": top_k,
        }
        return self._request("POST", "/query", json_data=payload, timeout=timeout)

    # -----------------------------------------------------------------------
    # Audit Log Endpoints (Admin Clearance Required)
    # -----------------------------------------------------------------------

    def get_audit_logs(
        self,
        admin_id: str = "adm_charlie",
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        decision: Optional[str] = None,
        doc_id: Optional[str] = None,
        limit: int = 100,
        timeout: float = 5.0,
    ) -> ApiResponse:
        """
        Fetch structured audit event logs.
        Requires Administrator identity (Clearance 3) via X-User-Id header.

        Args:
            admin_id: Administrator caller identity (e.g. 'adm_charlie' or 'admin_dave').
            user_id: Optional filter by queried user.
            request_id: Optional filter by request UUID.
            decision: Optional filter ('ALLOW' or 'DENY').
            doc_id: Optional filter by document ID.
            limit: Maximum records to return (1–1000).
            timeout: Request timeout.
        """
        params: Dict[str, Any] = {
            "caller_id": admin_id,
            "limit": max(1, min(limit, 1000)),
        }
        if user_id:
            params["user_id"] = user_id
        if request_id:
            params["request_id"] = request_id
        if decision:
            params["decision"] = decision.upper()
        if doc_id:
            params["doc_id"] = doc_id

        headers = {"X-User-Id": admin_id}
        return self._request("GET", "/audit/logs", params=params, headers=headers, timeout=timeout)

    def clear_audit_logs(
        self,
        admin_id: str = "adm_charlie",
        timeout: float = 5.0,
    ) -> ApiResponse:
        """
        Explicitly clear in-memory audit logs.
        NOTE: Must only be invoked via user confirmation, NEVER automatically.
        Requires Administrator identity (Clearance 3) via X-User-Id header.
        """
        params = {"caller_id": admin_id}
        headers = {"X-User-Id": admin_id}
        return self._request("DELETE", "/audit/logs", params=params, headers=headers, timeout=timeout)


# ---------------------------------------------------------------------------
# Default Global Client Instance & Convenience Functions
# ---------------------------------------------------------------------------

_default_client = RAGLeakClient()


def get_health(timeout: float = 2.0) -> ApiResponse:
    return _default_client.get_health(timeout=timeout)


def get_config(timeout: float = 3.0) -> ApiResponse:
    return _default_client.get_config(timeout=timeout)


def get_documents(timeout: float = 3.0) -> ApiResponse:
    return _default_client.get_documents(timeout=timeout)


def get_identities(timeout: float = 3.0) -> ApiResponse:
    return _default_client.get_identities(timeout=timeout)


def execute_query(
    user_id: str,
    query: str,
    mode: str = "protected",
    top_k: int = 5,
    timeout: float = 10.0,
) -> ApiResponse:
    return _default_client.execute_query(
        user_id=user_id,
        query=query,
        mode=mode,
        top_k=top_k,
        timeout=timeout,
    )


def get_audit_logs(
    admin_id: str = "adm_charlie",
    user_id: Optional[str] = None,
    request_id: Optional[str] = None,
    decision: Optional[str] = None,
    doc_id: Optional[str] = None,
    limit: int = 100,
    timeout: float = 5.0,
) -> ApiResponse:
    return _default_client.get_audit_logs(
        admin_id=admin_id,
        user_id=user_id,
        request_id=request_id,
        decision=decision,
        doc_id=doc_id,
        limit=limit,
        timeout=timeout,
    )


def clear_audit_logs(
    admin_id: str = "adm_charlie",
    timeout: float = 5.0,
) -> ApiResponse:
    return _default_client.clear_audit_logs(admin_id=admin_id, timeout=timeout)
