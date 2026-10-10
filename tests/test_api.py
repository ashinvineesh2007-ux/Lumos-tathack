"""
tests/test_api.py — Comprehensive Test Suite for Step 5 FastAPI Endpoints & Integration
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security import get_audit_logger


@pytest.fixture
def client():
    get_audit_logger().clear()
    return TestClient(app, raise_server_exceptions=False)


class TestSystemEndpoints:
    """Test health, config, and document metadata endpoints."""

    # 1. Health endpoint works
    def test_health_endpoint_reports_status_and_backend(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["backend"] in ["sentence-transformers", "tfidf"]
        assert data["indexed_documents"] == 15
        assert "password" not in str(data)
        assert "path" not in str(data)

    # 2. Configuration endpoint returns valid modes
    def test_config_endpoint_returns_valid_modes_and_descriptions(self, client):
        response = client.get("/config")
        assert response.status_code == 200
        data = response.json()
        assert "baseline" in data["supported_modes"]
        assert "protected" in data["supported_modes"]
        assert data["default_mode"] == "protected"
        assert "baseline" in data["mode_descriptions"]
        assert "protected" in data["mode_descriptions"]
        assert "PUBLIC" in data["clearance_tiers"]
        assert "ADMIN" in data["user_roles"]
        # Ensure no internal server paths or secrets are returned
        assert "C:\\" not in str(data)
        assert "secret" not in str(data).lower()

    # 3. Document metadata does not expose document bodies
    def test_document_metadata_does_not_expose_document_bodies(self, client):
        response = client.get("/config/documents")
        assert response.status_code == 200
        docs = response.json()
        assert len(docs) == 15

        for doc in docs:
            assert "doc_id" in doc
            assert "title" in doc
            assert "access_level" in doc
            assert "department" in doc
            assert "is_injection_test" in doc
            # CRITICAL SECURITY CHECK: Document content or snippets must NEVER be present
            assert "content" not in doc
            assert "content_snippet" not in doc
            assert "body" not in doc


class TestQueryEndpoint:
    """Test POST /query behavior, modes, input validation, and fail-closed security."""

    # 4. Query endpoint works in protected mode
    def test_query_endpoint_works_in_protected_mode(self, client):
        payload = {
            "user_id": "emp_alice",
            "query": "What are the engineering department salary bands and payroll compensation?",
            "mode": "protected",
            "top_k": 5,
        }
        response = client.post("/query", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["mode"] == "protected"
        assert data["user_id"] == "emp_alice"
        assert data["request_id"] is not None
        assert "docs_retrieved" in data
        assert "docs_allowed" in data
        assert "docs_denied" in data

    # 5. Query endpoint works in baseline mode
    def test_query_endpoint_works_in_baseline_mode(self, client):
        payload = {
            "user_id": "emp_alice",
            "query": "What are the engineering department salary bands and payroll compensation?",
            "mode": "baseline",
            "top_k": 5,
        }
        response = client.post("/query", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["mode"] == "baseline"
        # Baseline demonstrates vulnerability by leaking confidential figures
        assert "180,000" in data["answer"] or "72,000" in data["answer"]
        assert len(data["context_sent"]) > 0

    # 6. Invalid mode and malformed requests are handled safely (422)
    def test_invalid_mode_and_malformed_requests_handled_safely(self, client):
        # Invalid mode
        bad_mode_res = client.post(
            "/query",
            json={"user_id": "emp_alice", "query": "hello world", "mode": "invalid_mode_xyz"},
        )
        assert bad_mode_res.status_code == 422

        # Too short query (min_length=3)
        short_query_res = client.post(
            "/query",
            json={"user_id": "emp_alice", "query": "hi", "mode": "protected"},
        )
        assert short_query_res.status_code == 422

        # Empty user_id (min_length=1)
        empty_user_res = client.post(
            "/query",
            json={"user_id": "", "query": "hello world", "mode": "protected"},
        )
        assert empty_user_res.status_code == 422

    # 7. Unknown identities fail closed in protected mode
    def test_unknown_identities_fail_closed_in_protected_mode(self, client):
        payload = {
            "user_id": "attacker_mallory",
            "query": "What is the production Kubernetes architecture?",
            "mode": "protected",
        }
        response = client.post("/query", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["docs_allowed"] == 0
        assert len(data["context_sent"]) == 0
        assert "Access Denied" in data["answer"]

    # 8. Confidential data is not returned to unauthorized users
    def test_confidential_data_not_returned_to_unauthorized_users(self, client):
        payload = {
            "user_id": "emp_alice",
            "query": "What are the engineering department salary bands?",
            "mode": "protected",
        }
        response = client.post("/query", json=payload)
        assert response.status_code == 200
        data = response.json()
        # Alice is EMPLOYEE (Clearance 2); DOC-010 requires CONFIDENTIAL (Clearance 3)
        assert "180,000" not in data["answer"]
        for meta in data["auth_decisions"]:
            if meta["doc_id"] == "DOC-010":
                assert meta["decision"] == "DENY"
                assert meta["content_snippet"] is None

    # 9. Request IDs are preserved or generated consistently
    def test_request_ids_are_generated_uniquely_and_consistently(self, client):
        res1 = client.post("/query", json={"user_id": "emp_alice", "query": "incident response"})
        res2 = client.post("/query", json={"user_id": "emp_alice", "query": "incident response"})

        id1 = res1.json()["request_id"]
        id2 = res2.json()["request_id"]
        assert id1 is not None and len(id1) >= 16
        assert id2 is not None and len(id2) >= 16
        assert id1 != id2


class TestAuditLogAccessControl:
    """Test server-side access control, filtering, and authorization on /audit/logs."""

    # 10. Unauthorized callers cannot read restricted audit logs (403 Forbidden)
    def test_unauthorized_callers_cannot_read_audit_logs(self, client):
        # 1. Anonymous caller (no caller_id or header)
        anon_res = client.get("/audit/logs")
        assert anon_res.status_code == 403
        assert "Forbidden" in anon_res.json()["detail"]

        # 2. Employee caller (emp_alice is EMPLOYEE, not ADMIN)
        emp_res = client.get("/audit/logs?caller_id=emp_alice")
        assert emp_res.status_code == 403
        assert "Forbidden" in emp_res.json()["detail"]

        # 3. Header-based non-admin caller
        hdr_res = client.get("/audit/logs", headers={"X-User-Id": "ext_guest"})
        assert hdr_res.status_code == 403

    # 11. Authorized admin callers can read audit logs and filter them
    def test_authorized_admin_callers_can_read_and_filter_audit_logs(self, client):
        # Run a query first to generate audit logs
        client.post(
            "/query",
            json={"user_id": "emp_alice", "query": "engineering salary bands", "mode": "protected"},
        )

        # Admin via query param
        admin_res = client.get("/audit/logs?caller_id=adm_charlie")
        assert admin_res.status_code == 200
        logs = admin_res.json()
        assert len(logs) > 0

        # Admin via X-User-Id header
        hdr_admin_res = client.get("/audit/logs", headers={"X-User-Id": "admin_dave"})
        assert hdr_admin_res.status_code == 200
        assert len(hdr_admin_res.json()) > 0

        # Filter by decision
        filter_res = client.get("/audit/logs?caller_id=adm_charlie&decision=DENY")
        assert filter_res.status_code == 200
        for entry in filter_res.json():
            assert entry["decision"] == "DENY"
            assert entry["content_exposed"] is False

    # 12. Error responses do not reveal stack traces or internal paths
    def test_error_responses_do_not_reveal_stack_traces(self, client):
        res = client.post("/query", json={"user_id": "emp_alice", "query": "x" * 10, "top_k": 999})
        # 999 exceeds ge=1, le=20
        assert res.status_code == 422
        body = res.text
        assert "Traceback" not in body
        assert "C:\\" not in body
        assert "/app/" not in body

    # 13. Oversized query and identity strings rejected with 422 (DoS Prevention)
    def test_oversized_query_and_user_id_rejected_with_422(self, client):
        # Oversized query (> 4096 chars)
        res_query = client.post(
            "/query",
            json={"user_id": "emp_alice", "query": "a" * 4097, "mode": "protected"},
        )
        assert res_query.status_code == 422

        # Oversized user_id (> 64 chars)
        res_user = client.post(
            "/query",
            json={"user_id": "u" * 65, "query": "valid query text", "mode": "protected"},
        )
        assert res_user.status_code == 422

    # 14. DELETE /audit/logs access control enforced (403 Forbidden for non-admins)
    def test_delete_audit_logs_unauthorized_returns_403(self, client):
        # Anonymous caller
        anon_res = client.delete("/audit/logs")
        assert anon_res.status_code == 403

        # Non-admin employee
        emp_res = client.delete("/audit/logs?caller_id=emp_alice")
        assert emp_res.status_code == 403

        # Non-admin via header
        hdr_res = client.delete("/audit/logs", headers={"X-User-Id": "ext_guest"})
        assert hdr_res.status_code == 403

    # 15. DELETE /audit/logs authorized admin succeeds and records purge event
    def test_delete_audit_logs_authorized_admin_succeeds(self, client):
        # Generate an audit event first
        client.post(
            "/query",
            json={"user_id": "emp_alice", "query": "company overview", "mode": "protected"},
        )

        # Admin purges audit logs
        del_res = client.delete("/audit/logs?caller_id=adm_charlie")
        assert del_res.status_code == 200
        del_data = del_res.json()
        assert del_data["status"] == "success"
        assert "Audit logs cleared." in del_data["message"]
        assert del_data["purged_by"] == "adm_charlie"

        # Subsequent query returns zero logs
        logs_res = client.get("/audit/logs?caller_id=adm_charlie")
        assert logs_res.status_code == 200
        assert len(logs_res.json()) == 0

    # 16. End-to-end document ACL denial and protected context isolation
    def test_end_to_end_document_acl_denial_and_context_isolation(self, client):
        # Alice is EMPLOYEE (clearance 2). DOC-012 restricts access to admin_dave, adm_charlie, mgr_carol
        res = client.post(
            "/query",
            json={
                "user_id": "emp_alice",
                "query": "HR confidential employee disciplinary cases summary",
                "mode": "protected",
                "top_k": 5,
            },
        )
        assert res.status_code == 200
        data = res.json()

        # Find DOC-012 in auth decisions
        doc12 = [d for d in data["auth_decisions"] if d["doc_id"] == "DOC-012"]
        if doc12:
            assert doc12[0]["decision"] == "DENY"
            assert doc12[0]["content_snippet"] is None
            assert "Restrictive ACL requires user membership" in doc12[0]["policy_reason"]

        # Ensure no disciplinary case content entered context_sent or answer
        for chunk in data["context_sent"]:
            assert "HR-2025" not in chunk
            assert "DOC-012" not in chunk
        assert "HR-2025" not in data["answer"]

    # 17. Simulated identity resolution boundary: known vs unknown admin
    def test_simulated_identity_boundary_known_vs_unknown_admin(self, client):
        # Known simulated admin
        known_res = client.get("/audit/logs?caller_id=admin_dave")
        assert known_res.status_code == 200

        # Non-existent forged admin identity fails closed
        forged_res = client.get("/audit/logs?caller_id=forged_superadmin")
        assert forged_res.status_code == 403
