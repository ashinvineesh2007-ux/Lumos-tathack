"""
tests/test_security.py — Test Suite for Step 3 Security & Authorization Gateway
"""

import pytest

from app.data_store import SearchResult
from app.schemas import AccessLevel, AuthDecision, AuditEvent, SystemMode, UserRole
from app.security import (
    DOCUMENT_ACLS,
    DocumentACL,
    UserContext,
    evaluate_document_access,
    filter_candidates,
    get_audit_logger,
    resolve_user_context,
)


class TestIdentityResolution:
    """Tests for trusted server-side identity resolution."""

    def test_known_employee_resolves_correctly(self):
        user = resolve_user_context("emp_alice")
        assert user is not None
        assert user.user_id == "emp_alice"
        assert user.role == UserRole.EMPLOYEE
        assert user.clearance == 2
        assert user.department == "Engineering"

    def test_known_admin_resolves_correctly(self):
        user = resolve_user_context("admin_dave")
        assert user is not None
        assert user.user_id == "admin_dave"
        assert user.role == UserRole.ADMIN
        assert user.clearance == 3

    def test_known_guest_resolves_correctly(self):
        user = resolve_user_context("guest_anon")
        assert user is not None
        assert user.user_id == "guest_anon"
        assert user.role == UserRole.GUEST
        assert user.clearance == 1

    def test_case_insensitive_and_whitespace_tolerant(self):
        user = resolve_user_context("  EMP_ALICE  ")
        assert user is not None
        assert user.user_id == "emp_alice"

    def test_unknown_user_returns_none(self):
        assert resolve_user_context("attacker_mallory") is None
        assert resolve_user_context("root") is None

    def test_empty_or_none_user_returns_none(self):
        assert resolve_user_context("") is None
        assert resolve_user_context("   ") is None
        assert resolve_user_context(None) is None


class TestAuthorizationEvaluation:
    """Tests for clearance tiers and ACL enforcement."""

    def test_guest_can_access_public_document(self):
        user = resolve_user_context("guest_anon")
        decision, reason = evaluate_document_access(user, "DOC-001", AccessLevel.PUBLIC)
        assert decision == AuthDecision.ALLOW
        assert "Allow" in reason

    def test_guest_cannot_access_internal_document(self):
        user = resolve_user_context("guest_anon")
        decision, reason = evaluate_document_access(user, "DOC-005", AccessLevel.INTERNAL)
        assert decision == AuthDecision.DENY
        assert "Insufficient clearance" in reason

    def test_guest_cannot_access_confidential_document(self):
        user = resolve_user_context("guest_anon")
        decision, reason = evaluate_document_access(user, "DOC-011", AccessLevel.CONFIDENTIAL)
        assert decision == AuthDecision.DENY
        assert "Insufficient clearance" in reason

    def test_employee_can_access_internal_document(self):
        user = resolve_user_context("emp_alice")
        decision, reason = evaluate_document_access(user, "DOC-005", AccessLevel.INTERNAL)
        assert decision == AuthDecision.ALLOW

    def test_employee_cannot_access_confidential_document(self):
        user = resolve_user_context("emp_alice")
        decision, reason = evaluate_document_access(user, "DOC-011", AccessLevel.CONFIDENTIAL)
        assert decision == AuthDecision.DENY
        assert "Insufficient clearance" in reason

    def test_admin_can_access_confidential_document(self):
        user = resolve_user_context("admin_dave")
        decision, reason = evaluate_document_access(user, "DOC-011", AccessLevel.CONFIDENTIAL)
        assert decision == AuthDecision.ALLOW

    def test_specific_user_acl_grants_access_to_non_admin_carol(self):
        # DOC-012 allows admin_dave and mgr_carol explicitly
        carol = resolve_user_context("mgr_carol")
        decision, _ = evaluate_document_access(carol, "DOC-012", AccessLevel.CONFIDENTIAL)
        # Note: DOC-012 min_clearance=2 in ACL, allowed_users={"admin_dave", "mgr_carol"}
        assert decision == AuthDecision.ALLOW

    def test_specific_user_acl_denies_unlisted_employee_alice(self):
        alice = resolve_user_context("emp_alice")
        decision, reason = evaluate_document_access(alice, "DOC-012", AccessLevel.CONFIDENTIAL)
        assert decision == AuthDecision.DENY

    def test_restrictive_acl_overrides_high_clearance(self):
        # If an ACL specifies an allowed_users list without admin_dave, even clearance 3 is denied
        dave = resolve_user_context("admin_dave")
        custom_acl = DocumentACL(
            doc_id="DOC-EXCLUSIVE",
            min_clearance=1,
            allowed_users={"board_chair_only"},
        )
        DOCUMENT_ACLS["DOC-EXCLUSIVE"] = custom_acl
        try:
            decision, reason = evaluate_document_access(dave, "DOC-EXCLUSIVE", AccessLevel.CONFIDENTIAL)
            assert decision == AuthDecision.DENY
            assert "Restrictive ACL requires user membership" in reason
        finally:
            DOCUMENT_ACLS.pop("DOC-EXCLUSIVE", None)


class TestFailClosedGuarantees:
    """Verify strict fail-closed behavior on missing or invalid inputs."""

    def test_none_user_is_strictly_denied_for_public_doc(self):
        decision, reason = evaluate_document_access(None, "DOC-001", AccessLevel.PUBLIC)
        assert decision == AuthDecision.DENY
        assert "fail-closed" in reason.lower()

    def test_none_user_is_strictly_denied_for_confidential_doc(self):
        decision, reason = evaluate_document_access(None, "DOC-011", AccessLevel.CONFIDENTIAL)
        assert decision == AuthDecision.DENY


class TestCandidateFiltering:
    """Verify filtering behavior on retrieved search candidates."""

    @pytest.fixture
    def sample_candidates(self):
        return [
            SearchResult(
                doc_id="DOC-001",
                title="Public Overview",
                clearance=AccessLevel.PUBLIC,
                score=0.95,
                content="Public overview text content.",
            ),
            SearchResult(
                doc_id="DOC-005",
                title="Internal Roadmap",
                clearance=AccessLevel.INTERNAL,
                score=0.88,
                content="Internal roadmap secret architecture.",
            ),
            SearchResult(
                doc_id="DOC-011",
                title="Executive Compensation",
                clearance=AccessLevel.CONFIDENTIAL,
                score=0.92,
                content="CEO base salary $1,250,000 confidential.",
            ),
        ]

    def test_employee_gets_public_and_internal_only(self, sample_candidates):
        alice = resolve_user_context("emp_alice")
        decisions, authorized_context = filter_candidates(alice, sample_candidates)

        assert len(decisions) == 3
        # DOC-001: ALLOW
        assert decisions[0].decision == AuthDecision.ALLOW
        assert decisions[0].content_snippet is not None

        # DOC-005: ALLOW
        assert decisions[1].decision == AuthDecision.ALLOW
        assert decisions[1].content_snippet is not None

        # DOC-011: DENY, content_snippet MUST be None
        assert decisions[2].decision == AuthDecision.DENY
        assert decisions[2].content_snippet is None

        # Authorized context sent to LLM contains ONLY 2 chunks, excluding DOC-011
        assert len(authorized_context) == 2
        assert "CEO base salary" not in " ".join(authorized_context)

    def test_guest_gets_public_only(self, sample_candidates):
        guest = resolve_user_context("guest_anon")
        decisions, authorized_context = filter_candidates(guest, sample_candidates)

        assert len(authorized_context) == 1
        assert authorized_context[0] == "Public overview text content."
        assert decisions[1].content_snippet is None
        assert decisions[2].content_snippet is None

    def test_admin_gets_all_authorized(self, sample_candidates):
        admin = resolve_user_context("admin_dave")
        decisions, authorized_context = filter_candidates(admin, sample_candidates)

        assert len(authorized_context) == 3
        for d in decisions:
            assert d.decision == AuthDecision.ALLOW
            assert d.content_snippet is not None


class TestAuditLogger:
    """Verify thread-safe in-memory audit log operations."""

    def test_record_and_retrieve_events(self):
        logger = get_audit_logger()
        logger.clear()

        event1 = AuditEvent(
            user_id="emp_alice",
            user_role=UserRole.EMPLOYEE,
            user_clearance=2,
            request_id="req-123",
            query_text="salary query",
            mode=SystemMode.PROTECTED,
            doc_id="DOC-011",
            doc_title="Exec Comp",
            doc_access_level=AccessLevel.CONFIDENTIAL,
            similarity_score=0.92,
            decision=AuthDecision.DENY,
            policy_reason="Insufficient clearance",
            content_exposed=False,
        )
        logger.record_event(event1)

        events = logger.get_events(request_id="req-123")
        assert len(events) == 1
        assert events[0].user_id == "emp_alice"
        assert events[0].decision == AuthDecision.DENY
        assert events[0].content_exposed is False
