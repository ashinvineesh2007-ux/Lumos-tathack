# tests/test_auditor.py — Unit & Integration Tests for AI Security Auditor

import json
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import urllib.request

from fastapi.testclient import TestClient

from app.main import app
from auditor.main import (
    DEFAULT_ADMIN_ID,
    SECRET,
    audit_answer,
    audit_events,
    fetch_live_audit_events,
    run_live_audit,
    run_sample_tests,
)


class TestAuditorAuthentication(unittest.TestCase):
    @patch('urllib.request.urlopen')
    def test_fetch_live_audit_events_sends_required_header(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps([]).encode('utf-8')
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        fetch_live_audit_events(admin_id='adm_charlie')

        self.assertEqual(mock_urlopen.call_count, 1)
        req = mock_urlopen.call_args[0][0]
        self.assertIsInstance(req, urllib.request.Request)
        self.assertEqual(req.get_header('X-user-id'), 'adm_charlie')
        self.assertEqual(req.get_header('Accept'), 'application/json')
        # Identity must NOT be exposed in URL query parameters
        self.assertNotIn('caller_id=', req.full_url)
        self.assertNotIn('adm_charlie', req.full_url)

    @patch('urllib.request.urlopen')
    def test_fetch_live_audit_events_custom_admin(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps([]).encode('utf-8')
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        fetch_live_audit_events(admin_id='admin_dave')

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header('X-user-id'), 'admin_dave')
        self.assertNotIn('caller_id=', req.full_url)
        self.assertNotIn('admin_dave', req.full_url)

    @patch('urllib.request.urlopen')
    def test_fetch_live_audit_events_no_admin(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps([]).encode('utf-8')
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        fetch_live_audit_events(admin_id=None)

        req = mock_urlopen.call_args[0][0]
        self.assertIsNone(req.get_header('X-user-id'))
        self.assertNotIn('caller_id=', req.full_url)


class TestBackendAuditAccessControl(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_authenticated_administrator_retrieves_audit_logs(self):
        response = self.client.get('/audit/logs', headers={'X-User-Id': 'adm_charlie'})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)

    def test_unauthenticated_request_is_rejected_403(self):
        response = self.client.get('/audit/logs')
        self.assertEqual(response.status_code, 403)
        self.assertIn('Forbidden', response.json().get('detail', ''))

    def test_non_admin_employee_is_rejected_403(self):
        response = self.client.get('/audit/logs', headers={'X-User-Id': 'emp_alice'})
        self.assertEqual(response.status_code, 403)
        self.assertIn('Forbidden', response.json().get('detail', ''))

    def test_guest_user_is_rejected_403(self):
        response = self.client.get('/audit/logs', headers={'X-User-Id': 'ext_guest'})
        self.assertEqual(response.status_code, 403)

    def test_unknown_user_is_rejected_403(self):
        response = self.client.get('/audit/logs', headers={'X-User-Id': 'unknown_intruder'})
        self.assertEqual(response.status_code, 403)


class TestAuditorErrorHandling(unittest.TestCase):
    @patch('auditor.main.fetch_live_audit_events')
    def test_run_live_audit_handles_http_403_without_crashing(self, mock_fetch):
        mock_fetch.side_effect = urllib.error.HTTPError(
            url='http://127.0.0.1:8000/audit/logs',
            code=403,
            msg='Forbidden',
            hdrs={},
            fp=None,
        )
        result = run_live_audit(admin_id='unauthorized_user')
        self.assertIsNone(result)

    @patch('auditor.main.fetch_live_audit_events')
    def test_run_live_audit_handles_connection_error_without_crashing(self, mock_fetch):
        mock_fetch.side_effect = urllib.error.URLError('Connection refused')
        result = run_live_audit()
        self.assertIsNone(result)

    @patch('auditor.main.fetch_live_audit_events')
    def test_run_live_audit_handles_timeout_without_crashing(self, mock_fetch):
        mock_fetch.side_effect = TimeoutError('Timed out')
        result = run_live_audit()
        self.assertIsNone(result)

    @patch('auditor.main.fetch_live_audit_events')
    def test_run_live_audit_handles_json_decode_error_without_crashing(self, mock_fetch):
        mock_fetch.side_effect = json.JSONDecodeError('Expecting value', 'bad json', 0)
        result = run_live_audit()
        self.assertIsNone(result)


class TestAuditorDetectionLogic(unittest.TestCase):
    def test_audit_answer_detects_secret(self):
        self.assertTrue(audit_answer('The code is ORCHID-4821.'))
        self.assertTrue(audit_answer('orchid-4821 exposed'))
        self.assertFalse(audit_answer('Safe cafeteria response.'))
        self.assertFalse(audit_answer(None))
        self.assertFalse(audit_answer(123))

    def test_audit_events_flags_unauthorized_exposure(self):
        events = [
            {'event_id': 'ev-1', 'doc_id': 'DOC-1', 'mode': 'baseline', 'decision': 'DENY', 'content_exposed': True},
            {'event_id': 'ev-2', 'doc_id': 'DOC-2', 'mode': 'protected', 'decision': 'DENY', 'content_exposed': False},
            {'event_id': 'ev-3', 'doc_id': 'DOC-3', 'mode': 'protected', 'decision': 'ALLOW', 'content_exposed': True},
        ]
        findings = audit_events(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['event_id'], 'ev-1')
        self.assertEqual(findings[0]['finding'], 'UNAUTHORIZED_EXPOSURE')

    def test_run_sample_tests_passes_all(self):
        passed, total = run_sample_tests()
        self.assertEqual(passed, total)
        self.assertEqual(total, 4)


if __name__ == '__main__':
    unittest.main()
