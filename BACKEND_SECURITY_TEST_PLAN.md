# RAGLeak — Backend Security Test Plan & Verification Procedures

**Project:** RAGLeak — Security Testing and Auditing System for RAG-Based AI Assistants  
**Track:** Safe & Trustworthy AI (Track 2)  
**Target Branch:** `backendandrag`  
**Reference Commit:** `d0a62e6`  
**Document Type:** Reproducible Security Test Plan and Verification Procedures  

---

## 1. Overview and Objectives

This test plan defines the test suites, test categories, execution commands, and expected outcomes required to independently verify the security claims of the RAGLeak backend.

### Verification Goals
1. **Clearance Hierarchy Enforcement:** Confirm that users cannot access documents requiring higher clearance tiers than their assigned level.
2. **Restrictive ACL Precedence:** Verify that document-specific user, role, and department restrictions override blanket clearance.
3. **Protected Context Isolation:** Guarantee that unauthorized chunks are excluded from `context_sent` and have `content_snippet = None`.
4. **Baseline Leakage Demonstration:** Confirm that baseline mode reproduces data leakage on synthetic corporate records for auditor metrics.
5. **Prompt Injection Containment:** Verify the distinction between clearance denials and prompt-injection handling within authorized contexts.
6. **Audit Log Access Control & Purge Tracking:** Ensure administrative endpoints (`/audit/logs`) reject unauthenticated and non-admin requests with `HTTP 403`, and record purge history on `DELETE`.
7. **DoS & Input Length Validation:** Verify that oversized queries (>4096 chars) and oversized identities (>64 chars) are rejected with `HTTP 422`.
8. **Fail-Closed Guarantees:** Ensure unknown users, malformed queries, and internal exceptions fail closed.

---

## 2. Test Environment & Execution Commands

### 2.1 Dependencies & Setup
Run from the root directory `c:\Users\USER\Downloads\backend&rag`:
```powershell
# Verify Python version (3.10+ recommended)
python --version

# Install dependencies if not already installed
pip install -r requirements.txt
```

### 2.2 Full Automated Test Suite Execution
```powershell
python -m pytest -v
```
*Expected post-remediation outcome:* **113 passed** in under 16 seconds (0 failed, 0 errors, 0 skipped).

### 2.3 Modular Test Execution
```powershell
# Run API endpoint and contract tests (17 tests)
python -m pytest -v tests/test_api.py

# Run security gateway and authorization tests (24 tests)
python -m pytest -v tests/test_security.py

# Run RAG engine dual-mode execution tests (13 tests)
python -m pytest -v tests/test_rag_engine.py

# Run baseline vs protected side-by-side benchmark tests (5 tests)
python -m pytest -v tests/test_rag_pipeline.py

# Run synthetic data store and TF-IDF fallback tests (54 tests)
python -m pytest -v tests/test_data_store.py
```

---

## 3. Security Test Scenarios & Matrices

### 3.1 Scenario Matrix: Clearance & Role Enforcement

| Test ID | Persona / `user_id` | Role | Clearance | Target Document | Doc Level | Expected Decision | Expected `content_snippet` | Expected Context Inclusion |
| :--- | :--- | :--- | :---: | :--- | :--- | :---: | :---: | :---: |
| **TC-SEC-01** | `guest_anon` / `ext_guest` | `GUEST` | 1 | `DOC-001` (Company Overview) | `PUBLIC` (1) | **ALLOW** | String (<=300 chars) | Included |
| **TC-SEC-02** | `guest_anon` / `ext_guest` | `GUEST` | 1 | `DOC-005` (Roadmap) | `INTERNAL` (2) | **DENY** | `None` | Excluded |
| **TC-SEC-03** | `guest_anon` / `ext_guest` | `GUEST` | 1 | `DOC-010` (Salary Bands) | `CONFIDENTIAL` (3) | **DENY** | `None` | Excluded |
| **TC-SEC-04** | `emp_alice` | `EMPLOYEE` | 2 | `DOC-005` (Roadmap) | `INTERNAL` (2) | **ALLOW** | String | Included |
| **TC-SEC-05** | `emp_alice` | `EMPLOYEE` | 2 | `DOC-010` (Salary Bands) | `CONFIDENTIAL` (3) | **DENY** | `None` | Excluded |
| **TC-SEC-06** | `admin_dave` | `ADMIN` | 3 | `DOC-010` (Salary Bands) | `CONFIDENTIAL` (3) | **ALLOW** | String | Included |

### 3.2 Scenario Matrix: Restrictive Document-Level ACLs

| Test ID | Persona | Target Document | ACL Rule | Clearance Check | ACL Check | Expected Decision |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **TC-ACL-01** | `mgr_carol` (Clearance 2) | `DOC-012` (HR Disciplinary) | `allowed_users={"admin_dave", "adm_charlie", "mgr_carol"}` | Pass (min 2) | Pass | **ALLOW** |
| **TC-ACL-02** | `emp_alice` (Clearance 2) | `DOC-012` (HR Disciplinary) | Same as above | Pass (min 2) | Fail (not in allowed list) | **DENY** |
| **TC-ACL-03** | `adm_charlie` (Clearance 3) | `DOC-EXCLUSIVE` | `allowed_users={"board_chair_only"}` | Pass (clearance 3) | Fail (not in list) | **DENY** |
| **TC-ACL-04** | `emp_alice` (Engineering) | `DOC-ENG-ONLY` | `require_department_match="Engineering"` | Pass (min 2) | Pass | **ALLOW** |
| **TC-ACL-05** | `emp_bob` (Procurement) | `DOC-ENG-ONLY` | `require_department_match="Engineering"` | Pass (min 2) | Fail (dept mismatch) | **DENY** |

### 3.3 Scenario Matrix: Baseline vs. Protected Mode Comparison

| Test ID | Query String | User | Mode | Expected `docs_allowed` | Confidential Data in `answer` | Audit `content_exposed` |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **TC-MODE-01** | "engineering salary bands and payroll compensation" | `emp_alice` | `baseline` | 5 / 5 | **Yes** ("$180,000" or "$72,000") | `True` |
| **TC-MODE-02** | "engineering salary bands and payroll compensation" | `emp_alice` | `protected` | <= 2 / 5 | **No** (Denied / Safe Refusal) | `False` (for `DOC-010`) |

### 3.4 Scenario Matrix: Prompt Injection & Adversarial Documents

| Test ID | Document ID | Description | Query Context | Mode | User | Expected System Handling |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-INJ-01** | `INJ-002` | Candidate feedback form with simulated admin override | HR candidate feedback | `protected` | `ext_guest` | **Blocked by ACL:** Guest clearance 1 < Internal clearance 2. Chunks omitted. |
| **TC-INJ-02** | `INJ-001` | Invoice note instructing AI to exfiltrate payroll data | Invoice #9914 vendor notes | `protected` | `emp_alice` | **Allowed by ACL:** Employee cleared for Internal procurement doc. Context entered, but deterministic answer generator does NOT execute injection instruction. |
| **TC-INJ-03** | `INJ-001` | Same as above | Invoice #9914 | `baseline` | `emp_alice` | **Demonstration Leak:** Baseline triggers simulated injection alert string. |
| **TC-INJ-04** | `INJ-001` | Authorized retrieval cross-context isolation | GlobalRoute Logistics contract renewal | `protected` | `emp_bob` | **Isolated:** `INJ-001` is allowed into context, but confidential payroll records (`DOC-010`) are strictly blocked from context and answer. |

### 3.5 Scenario Matrix: Input Length & Denial-of-Service Defense

| Test ID | Target Endpoint | Input Field | Payload Size | Expected Status Code | Policy Evaluation |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **TC-DOS-01** | `POST /query` | `query` | 4097 characters | `422 Unprocessable` | Rejected by Pydantic `max_length=4096`. Prevents vectorization DoS. |
| **TC-DOS-02** | `POST /query` | `user_id` | 65 characters | `422 Unprocessable` | Rejected by Pydantic `max_length=64`. Prevents directory lookup abuse. |

### 3.6 Scenario Matrix: Administrative Endpoint Access Control & Purge Tracking

| Test ID | Target Endpoint | Method | Caller Parameter / Header | Expected Status Code | Expected Response Body |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **TC-ADM-01** | `/audit/logs` | `GET` | *(None / Anonymous)* | `403 Forbidden` | `detail: "Forbidden: Audit logs are restricted to Administrator identities..."` |
| **TC-ADM-02** | `/audit/logs` | `GET` | `?caller_id=emp_alice` | `403 Forbidden` | `detail: "Forbidden..."` |
| **TC-ADM-03** | `/audit/logs` | `GET` | `X-User-Id: ext_guest` | `403 Forbidden` | `detail: "Forbidden..."` |
| **TC-ADM-04** | `/audit/logs` | `GET` | `?caller_id=adm_charlie` | `200 OK` | JSON Array of `AuditEvent` objects |
| **TC-ADM-05** | `/audit/logs` | `DELETE` | `?caller_id=emp_alice` | `403 Forbidden` | `detail: "Forbidden..."` |
| **TC-ADM-06** | `/audit/logs` | `DELETE` | `?caller_id=adm_charlie` | `200 OK` | `{"status": "success", "message": "Audit logs cleared.", "events_purged": N, "purged_by": "adm_charlie"}` |

---

## 4. End-to-End API Integration Verification (cURL / PowerShell)

With the backend running locally via:
```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Execute the following live tests to verify the running server:

### Test 1: Verify Health Endpoint
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/health" -Method Get | ConvertTo-Json
```
*Expected: Status healthy, backend sentence-transformers or tfidf, 15 indexed documents.*

### Test 2: Verify Protected Mode Refusal (Zero Leakage)
```powershell
$Body = @{
    user_id = "emp_alice"
    query = "What are the engineering department salary bands?"
    mode = "protected"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/query" -Method Post -ContentType "application/json" -Body $Body | ConvertTo-Json
```
*Expected: `docs_denied > 0`, `answer` contains "Access Denied", no salary numbers.*

### Test 3: Verify Baseline Mode Leakage
```powershell
$Body = @{
    user_id = "emp_alice"
    query = "What are the engineering department salary bands?"
    mode = "baseline"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/query" -Method Post -ContentType "application/json" -Body $Body | ConvertTo-Json
```
*Expected: `answer` leaks "$180,000", `docs_allowed == docs_retrieved`.*

### Test 4: Verify Admin Audit Log Access
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/audit/logs?caller_id=adm_charlie" -Method Get | ConvertTo-Json -Depth 3
```
*Expected: 200 OK with list of audit events.*

### Test 5: Verify Admin Audit Log Purge
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/audit/logs?caller_id=adm_charlie" -Method Delete | ConvertTo-Json
```
*Expected: 200 OK with `status: success`, `message: Audit logs cleared.`, `purged_by: adm_charlie`.*

---

## 5. Security Test Acceptance Criteria

1. **Deterministic Containment:** In Protected Mode, `context_sent` must NEVER contain snippets or text from unauthorized documents across 100% of test runs.
2. **Zero Fail-Open:** Any unknown identity (`resolve_user_context() == None`) must result in `docs_allowed = 0` and an access refusal.
3. **Audit Truthfulness:** In Protected Mode, every denied candidate must generate an audit event with `decision: "DENY"` and `content_exposed: false`.
4. **Purge Accountability:** Every log-clear operation must record the purging identity, timestamp, and event count.
5. **Offline Reproducibility:** Every test in the test suite must execute and pass without requiring external network connectivity or LLM API keys.
