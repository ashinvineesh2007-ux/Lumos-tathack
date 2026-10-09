"""
tests/test_api.py — Test Suite for Step 5 FastAPI Endpoints & Integration
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security import get_audit_logger


@pytest.fixture
def client():
    get_audit_logger().clear()
    return TestClient(app)


class TestSystemEndpoints:
    """Test health, root, and metadata endpoints."""

    def test_root_endpoint_returns_ok(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "RAGLeak Gateway" in data["service"]
        assert "Track 2" in data["track"]

    def test_health_endpoint_reports_status_and_backend(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["backend"] in ["sentence-transformers", "tfidf"]
        assert data["indexed_documents"] == 15

    def test_api_identities_returns_simulated_users(self, client):
        response = client.get("/api/identities")
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 5
        user_ids = [u["user_id"] for u in data]
        assert "emp_alice" in user_ids
        assert "admin_dave" in user_ids
        assert "guest_anon" in user_ids

    def test_api_documents_returns_safe_metadata(self, client):
        response = client.get("/api/documents")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 15
        # Ensure full content is not in summary model
        for doc in data:
            assert "doc_id" in doc
            assert "title" in doc
            assert "clearance" in doc
            assert "content" not in doc


class TestQueryEndpoint:
    """Test POST /query endpoint behavior and security enforcement."""

    def test_query_baseline_mode_demonstrates_leakage(self, client):
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
        assert data["user_id"] == "emp_alice"
        assert "180,000" in data["answer"] or "72,000" in data["answer"]
        assert len(data["context_sent"]) > 0

    def test_query_protected_mode_prevents_leakage(self, client):
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
        assert "180,000" not in data["answer"]
        assert "Access Denied" in data["answer"] or "not possess" in data["answer"]
        assert data["docs_denied"] >= 1

    def test_query_validation_error_on_short_query(self, client):
        payload = {
            "user_id": "emp_alice",
            "query": "hi",  # min_length is 3
            "mode": "protected",
        }
        response = client.post("/query", json=payload)
        assert response.status_code == 422


class TestAuditLogEndpoints:
    """Test GET /audit/logs and DELETE /audit/logs endpoints."""

    def test_audit_logs_record_and_filter(self, client):
        # Run a query to populate logs
        client.post(
            "/query",
            json={
                "user_id": "emp_alice",
                "query": "engineering salary bands",
                "mode": "protected",
                "top_k": 3,
            },
        )

        response = client.get("/audit/logs")
        assert response.status_code == 200
        logs = response.json()
        assert len(logs) > 0

        # Filter by user_id
        res_filter = client.get("/audit/logs?user_id=emp_alice")
        assert res_filter.status_code == 200
        for entry in res_filter.json():
            assert entry["user_id"] == "emp_alice"

    def test_clear_audit_logs(self, client):
        client.post(
            "/query",
            json={"user_id": "emp_alice", "query": "incident response", "mode": "protected"},
        )
        assert len(client.get("/audit/logs").json()) > 0

        delete_res = client.delete("/audit/logs")
        assert delete_res.status_code == 200
        assert len(client.get("/audit/logs").json()) == 0
