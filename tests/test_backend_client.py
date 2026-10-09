"""
tests/test_backend_client.py — Unit Tests for RAGLeak API Client

Comprehensive mocked tests covering:
1. Endpoint invocation and URL construction
2. Header injection (X-User-Id for admin audit calls)
3. Timeout, ConnectionError, and HTTP error handling
4. Strict separation between unavailable backend states and genuine empty responses
"""

import unittest
from unittest.mock import MagicMock, patch
import requests

from backend_client import (
    ApiResponse,
    RAGLeakClient,
    get_health,
    get_config,
    get_documents,
    get_identities,
    execute_query,
    get_audit_logs,
    clear_audit_logs,
)


class TestRAGLeakClient(unittest.TestCase):
    def setUp(self):
        self.client = RAGLeakClient(base_url="http://127.0.0.1:8000", default_timeout=2.0)

    @patch("backend_client.requests.request")
    def test_get_health_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "healthy",
            "backend": "sentence-transformers",
            "indexed_documents": 15,
            "total_audit_events": 0,
        }
        mock_request.return_value = mock_resp

        result = self.client.get_health()

        self.assertTrue(result.success)
        self.assertTrue(result.is_available)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data["status"], "healthy")
        self.assertEqual(result.data["indexed_documents"], 15)
        mock_request.assert_called_once_with(
            method="GET",
            url="http://127.0.0.1:8000/health",
            params=None,
            json=None,
            headers={"Accept": "application/json"},
            timeout=2.0,
        )

    @patch("backend_client.requests.request")
    def test_get_health_connection_error(self, mock_request):
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection refused")

        result = self.client.get_health()

        self.assertFalse(result.success)
        self.assertFalse(result.is_available)
        self.assertIsNone(result.data)
        self.assertIsNone(result.status_code)
        self.assertIn("offline", result.error.lower())

    @patch("backend_client.requests.request")
    def test_get_health_timeout(self, mock_request):
        mock_request.side_effect = requests.exceptions.Timeout("Read timed out")

        result = self.client.get_health(timeout=1.5)

        self.assertFalse(result.success)
        self.assertFalse(result.is_available)
        self.assertIsNone(result.data)
        self.assertIn("timed out", result.error.lower())

    @patch("backend_client.requests.request")
    def test_get_config_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "service": "RAGLeak Gateway",
            "supported_modes": ["baseline", "protected"],
            "default_mode": "protected",
        }
        mock_request.return_value = mock_resp

        result = self.client.get_config()

        self.assertTrue(result.success)
        self.assertEqual(result.data["default_mode"], "protected")
        self.assertIn("baseline", result.data["supported_modes"])

    @patch("backend_client.requests.request")
    def test_get_documents_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"doc_id": "DOC-001", "title": "Overview", "access_level": "PUBLIC"},
            {"doc_id": "DOC-010", "title": "Payroll", "access_level": "CONFIDENTIAL"},
        ]
        mock_request.return_value = mock_resp

        result = self.client.get_documents()

        self.assertTrue(result.success)
        self.assertEqual(len(result.data), 2)
        self.assertEqual(result.data[1]["access_level"], "CONFIDENTIAL")

    @patch("backend_client.requests.request")
    def test_get_identities_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"user_id": "emp_alice", "role": "EMPLOYEE", "clearance": 2},
            {"user_id": "adm_charlie", "role": "ADMIN", "clearance": 3},
        ]
        mock_request.return_value = mock_resp

        result = self.client.get_identities()

        self.assertTrue(result.success)
        self.assertEqual(len(result.data), 2)
        self.assertEqual(result.data[0]["user_id"], "emp_alice")

    @patch("backend_client.requests.request")
    def test_execute_query_protected(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "request_id": "req-123",
            "user_id": "emp_alice",
            "user_role": "EMPLOYEE",
            "mode": "protected",
            "answer": "Access Denied",
            "docs_retrieved": 5,
            "docs_allowed": 2,
            "docs_denied": 3,
            "auth_decisions": [],
        }
        mock_request.return_value = mock_resp

        result = self.client.execute_query(
            user_id="emp_alice",
            query="What is the executive salary?",
            mode="protected",
            top_k=5,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.data["answer"], "Access Denied")
        self.assertEqual(result.data["docs_denied"], 3)
        mock_request.assert_called_once_with(
            method="POST",
            url="http://127.0.0.1:8000/query",
            params=None,
            json={
                "user_id": "emp_alice",
                "query": "What is the executive salary?",
                "mode": "protected",
                "top_k": 5,
            },
            headers={"Accept": "application/json"},
            timeout=10.0,
        )

    def test_execute_query_validation(self):
        # Invalid mode
        with self.assertRaises(ValueError):
            self.client.execute_query("emp_alice", "Query", mode="invalid_mode")

        # Invalid top_k
        with self.assertRaises(ValueError):
            self.client.execute_query("emp_alice", "Query", top_k=0)
        with self.assertRaises(ValueError):
            self.client.execute_query("emp_alice", "Query", top_k=25)

    @patch("backend_client.requests.request")
    def test_get_audit_logs_authorized(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "event_id": "ev-01",
                "user_id": "emp_alice",
                "decision": "DENY",
                "content_exposed": False,
            }
        ]
        mock_request.return_value = mock_resp

        result = self.client.get_audit_logs(admin_id="adm_charlie", limit=50)

        self.assertTrue(result.success)
        self.assertEqual(len(result.data), 1)
        mock_request.assert_called_once_with(
            method="GET",
            url="http://127.0.0.1:8000/audit/logs",
            params={"caller_id": "adm_charlie", "limit": 50},
            json=None,
            headers={"Accept": "application/json", "X-User-Id": "adm_charlie"},
            timeout=5.0,
        )

    @patch("backend_client.requests.request")
    def test_get_audit_logs_forbidden_403(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 403
        mock_resp.json.return_value = {
            "detail": "Forbidden: Audit logs are restricted to Administrator identities (ADMIN clearance 3)."
        }
        mock_request.return_value = mock_resp

        result = self.client.get_audit_logs(admin_id="emp_alice")

        self.assertFalse(result.success)
        self.assertEqual(result.status_code, 403)
        self.assertIn("Forbidden", result.error)
        self.assertIsNone(result.data)

    @patch("backend_client.requests.request")
    def test_get_audit_logs_genuine_empty_vs_unavailable(self, mock_request):
        # 1. Genuine empty response from live backend (e.g. fresh start)
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_request.return_value = mock_resp

        result_empty = self.client.get_audit_logs(admin_id="adm_charlie")
        self.assertTrue(result_empty.success)
        self.assertEqual(result_empty.data, [])
        self.assertIsNone(result_empty.error)

        # 2. Unavailable backend (connection error)
        mock_request.side_effect = requests.exceptions.ConnectionError("Refused")
        result_offline = self.client.get_audit_logs(admin_id="adm_charlie")
        self.assertFalse(result_offline.success)
        self.assertIsNone(result_offline.data)
        self.assertIsNotNone(result_offline.error)

    @patch("backend_client.requests.request")
    def test_clear_audit_logs(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "message": "Audit logs cleared.",
            "events_purged": 5,
            "purged_by": "adm_charlie",
        }
        mock_request.return_value = mock_resp

        result = self.client.clear_audit_logs(admin_id="adm_charlie")

        self.assertTrue(result.success)
        self.assertEqual(result.data["events_purged"], 5)
        mock_request.assert_called_once_with(
            method="DELETE",
            url="http://127.0.0.1:8000/audit/logs",
            params={"caller_id": "adm_charlie"},
            json=None,
            headers={"Accept": "application/json", "X-User-Id": "adm_charlie"},
            timeout=5.0,
        )

    @patch("backend_client.requests.request")
    def test_invalid_json_handling(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Malformed JSON")
        mock_request.return_value = mock_resp

        result = self.client.get_health()

        self.assertFalse(result.success)
        self.assertIn("Invalid JSON", result.error)


if __name__ == "__main__":
    unittest.main()
