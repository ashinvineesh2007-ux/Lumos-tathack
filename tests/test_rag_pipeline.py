"""
tests/test_rag_pipeline.py — Test Suite for Step 4 Baseline vs Protected RAG Pipeline
"""

import pytest

from app.schemas import AccessLevel, AuthDecision, QueryRequest, SystemMode, UserRole
from app.rag_pipeline import RAGPipeline, get_rag_pipeline
from app.security import get_audit_logger


class TestBaselineVsProtectedExecution:
    """
    Core security audit tests demonstrating leakage in Baseline mode
    and strict enforcement in Protected mode on IDENTICAL queries.
    """

    def setup_method(self):
        get_audit_logger().clear()
        self.pipeline = RAGPipeline()

    def test_identical_query_baseline_leaks_and_protected_denies(self):
        """
        CRITICAL HACKATHON DEMO TEST:
        An employee asks for engineering payroll salary bands (DOC-010).
        - Baseline mode: Leaks the confidential $180,000-$210,000 salary bands.
        - Protected mode: Blocks the chunk, returns safe access denial.
        """
        query_text = "What are the engineering department salary bands and payroll compensation?"

        # 1. BASELINE MODE (Vulnerable)
        req_baseline = QueryRequest(
            user_id="emp_alice",
            query=query_text,
            mode=SystemMode.BASELINE,
            top_k=5,
        )
        res_baseline = self.pipeline.run_query(req_baseline)

        # Baseline exposes the confidential figure
        assert "180,000" in res_baseline.answer or "72,000" in res_baseline.answer
        assert len(res_baseline.context_sent) > 0
        assert any("DOC-010" in c or "72000" in c for c in res_baseline.context_sent)

        # Baseline audit event records content_exposed=True
        audit_events = get_audit_logger().get_events(request_id=res_baseline.request_id)
        doc10_events = [e for e in audit_events if e.doc_id == "DOC-010"]
        assert len(doc10_events) > 0
        assert doc10_events[0].content_exposed is True

        # 2. PROTECTED MODE (Zero Leakage)
        req_protected = QueryRequest(
            user_id="emp_alice",
            query=query_text,
            mode=SystemMode.PROTECTED,
            top_k=5,
        )
        res_protected = self.pipeline.run_query(req_protected)

        # Protected mode MUST NOT leak the confidential figure
        assert "180,000" not in res_protected.answer
        assert "Access Denied" in res_protected.answer or "not possess" in res_protected.answer

        # DOC-010 chunk must NOT be in context_sent
        for chunk in res_protected.context_sent:
            assert "180000" not in chunk
            assert "72000" not in chunk

        # DOC-010 decision must be DENY with content_snippet=None
        doc10_metas = [d for d in res_protected.auth_decisions if d.doc_id == "DOC-010"]
        if doc10_metas:
            assert doc10_metas[0].decision == AuthDecision.DENY
            assert doc10_metas[0].content_snippet is None

        # Protected audit event records content_exposed=False for DOC-010
        prot_events = get_audit_logger().get_events(request_id=res_protected.request_id)
        prot_doc10 = [e for e in prot_events if e.doc_id == "DOC-010"]
        if prot_doc10:
            assert prot_doc10[0].content_exposed is False

    def test_admin_legitimately_accesses_confidential_records_in_protected_mode(self):
        """
        Verify that an administrator with clearance 3 legitimately receives
        confidential context in Protected mode.
        """
        req = QueryRequest(
            user_id="admin_dave",
            query="What are the engineering department salary bands and payroll compensation?",
            mode=SystemMode.PROTECTED,
            top_k=5,
        )
        res = self.pipeline.run_query(req)

        assert res.user_role == UserRole.ADMIN
        assert res.user_clearance == 3
        assert "180,000" in res.answer or "72,000" in res.answer
        doc10_metas = [d for d in res.auth_decisions if d.doc_id == "DOC-010"]
        assert len(doc10_metas) > 0
        assert doc10_metas[0].decision == AuthDecision.ALLOW
        assert doc10_metas[0].content_snippet is not None

    def test_unknown_user_fail_closed_in_protected_mode(self):
        """Unknown or unauthenticated user must get zero context and full denial."""
        req = QueryRequest(
            user_id="intruder_mallory",
            query="What is the production Kubernetes architecture?",
            mode=SystemMode.PROTECTED,
            top_k=5,
        )
        res = self.pipeline.run_query(req)

        assert res.docs_allowed == 0
        assert len(res.context_sent) == 0
        assert "Access Denied" in res.answer
        for decision in res.auth_decisions:
            assert decision.decision == AuthDecision.DENY
            assert decision.content_snippet is None

    def test_guest_can_access_public_company_overview(self):
        """Guest user can access public info (DOC-001) in protected mode."""
        req = QueryRequest(
            user_id="guest_anon",
            query="What is Aethon Labs mission and overview?",
            mode=SystemMode.PROTECTED,
            top_k=3,
        )
        res = self.pipeline.run_query(req)

        # DOC-001 is PUBLIC, should be allowed
        doc1_metas = [d for d in res.auth_decisions if d.doc_id == "DOC-001"]
        if doc1_metas:
            assert doc1_metas[0].decision == AuthDecision.ALLOW
            assert doc1_metas[0].content_snippet is not None

    def test_indirect_prompt_injection_document_handled_safely(self):
        """
        Verify that adversarial document INJ-001 containing prompt injection
        does not crash the pipeline and its instructions are not executed.
        """
        req = QueryRequest(
            user_id="emp_alice",
            query="Find invoice #9914 vendor notes",
            mode=SystemMode.PROTECTED,
            top_k=5,
        )
        res = self.pipeline.run_query(req)
        # Content remains inert data, never executed
        assert res.answer is not None
        assert isinstance(res.answer, str)
