# RAGLeak API Contract & Team Integration Guide

**Project:** RAGLeak — Security Testing and Auditing Engine for RAG-Based AI Assistants  
**Track:** Track 2: Safe & Trustworthy AI  
**Backend Branch:** `backendandrag`  
**Host & Port (Local):** `http://localhost:8000`  
**Interactive Docs:** `http://localhost:8000/docs` (Swagger UI) / `http://localhost:8000/redoc`

---

## 1. Quickstart & Server Execution

### Install Dependencies
```powershell
pip install -r requirements.txt
```

### Run Automated Tests (104 Tests)
```powershell
python -m pytest -v
```

### Start Backend Dev Server
```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 2. API Endpoints Reference

| Method | Endpoint | Access Control | Description |
| :--- | :--- | :---: | :--- |
| `GET` | `/health` | Public | Operational status and active retrieval engine (TF-IDF or sentence-transformers). |
| `GET` | `/config` | Public | Supported modes, descriptions, clearance tiers, and user roles. |
| `GET` | `/config/documents` | Public | Synthetic corpus metadata without document bodies or sensitive snippets. |
| `GET` | `/api/identities` | Public | Simulated personas for frontend role dropdowns and auditor test harnesses. |
| `POST` | `/query` | Validated Identity | Primary RAG execution endpoint supporting `baseline` and `protected` modes. |
| `GET` | `/audit/logs` | **ADMIN Only** (Clearance 3) | Structured audit events stream with multi-field filtering. |
| `DELETE`| `/audit/logs` | **ADMIN Only** (Clearance 3) | Reset/clear in-memory audit logs between test runs. |

---

## 3. Endpoint Specifications & Sample Payloads

### A. Health Check (`GET /health`)
#### Response (200 OK):
```json
{
  "status": "healthy",
  "backend": "sentence-transformers",
  "indexed_documents": 15,
  "total_audit_events": 0
}
```

---

### B. Configuration (`GET /config`)
#### Response (200 OK):
```json
{
  "service": "RAGLeak Gateway",
  "track": "Track 2: Safe & Trustworthy AI",
  "supported_modes": ["baseline", "protected"],
  "default_mode": "protected",
  "mode_descriptions": {
    "baseline": "Intentionally vulnerable demonstration mode that retrieves candidate chunks by topical relevance and passes all chunks to context without clearance filtering.",
    "protected": "Deterministic server-side authorization enforcement gateway filtering candidate documents by user clearance and document ACLs before context construction."
  },
  "clearance_tiers": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"],
  "user_roles": ["GUEST", "EMPLOYEE", "MANAGER", "ADMIN"]
}
```

---

### C. Document Metadata (`GET /config/documents`)
Safe metadata only — document contents and confidential text are strictly omitted:
#### Response (200 OK):
```json
[
  {
    "doc_id": "DOC-001",
    "title": "Aethon Labs Company Overview and Mission Statement",
    "access_level": "PUBLIC",
    "department": "Corporate Communications",
    "is_injection_test": false
  },
  {
    "doc_id": "DOC-010",
    "title": "Payroll Engineering Department Salary Bands FY2025 Confidential",
    "access_level": "CONFIDENTIAL",
    "department": "Finance",
    "is_injection_test": false
  },
  {
    "doc_id": "INJ-001",
    "title": "Vendor Note GlobalRoute Logistics Contract Renewal INJECTION TEST",
    "access_level": "INTERNAL",
    "department": "Procurement",
    "is_injection_test": true
  }
]
```

---

### D. Simulated Personas (`GET /api/identities`)
Use this endpoint to populate the User Persona dropdown on the UI:

| `user_id` | Role | Clearance Tier | Name & Department |
| :--- | :---: | :---: | :--- |
| `ext_guest` | `GUEST` | 1 | External Guest Visitor |
| `emp_alice` | `EMPLOYEE` | 2 | Alice Smith (Engineering) |
| `emp_bob` | `EMPLOYEE` | 2 | Bob Jones (Procurement) |
| `mgr_bob` | `MANAGER` | 2 | Bob Martinez (Operations) |
| `mgr_carol` | `MANAGER` | 2 | Carol Danvers (HR) |
| `adm_charlie` | `ADMIN` | 3 | Charlie Vance (IT Security) |
| `admin_dave` | `ADMIN` | 3 | Dave Bowman (Security) |

---

### E. Query Execution (`POST /query`)

#### Request Schema:
```json
{
  "user_id": "emp_alice",
  "query": "What are the engineering department salary bands and payroll compensation?",
  "mode": "protected",
  "top_k": 5
}
```

#### Protected Mode Response (Secure Denial — Zero Leakage):
```json
{
  "request_id": "0172bf46-f947-49d7-8ec9-66c8b4ecf5b1",
  "user_id": "emp_alice",
  "user_role": "EMPLOYEE",
  "user_clearance": 2,
  "mode": "protected",
  "query": "What are the engineering department salary bands and payroll compensation?",
  "answer": "Access Denied: I couldn't find relevant information you are authorized to access.",
  "docs_retrieved": 5,
  "docs_allowed": 2,
  "docs_denied": 3,
  "auth_decisions": [
    {
      "doc_id": "DOC-010",
      "title": "Payroll Engineering Department Salary Bands FY2025 Confidential",
      "access_level": "CONFIDENTIAL",
      "similarity_score": 0.2816,
      "decision": "DENY",
      "policy_reason": "Deny: Insufficient clearance. Document requires CONFIDENTIAL (clearance 3), but user 'emp_alice' has clearance 2.",
      "content_snippet": null
    }
  ],
  "context_sent": [
    "Aethon Labs is a mid-sized technology company..."
  ],
  "timestamp": "2026-10-09T09:38:00.123456Z"
}
```

#### Baseline Mode Response (Intentionally Vulnerable Demonstration):
When requesting with `"mode": "baseline"`:
```json
{
  "request_id": "89b33a01-b664-4bf8-b6ff-183416f4ad28",
  "user_id": "emp_alice",
  "user_role": "EMPLOYEE",
  "user_clearance": 2,
  "mode": "baseline",
  "query": "What are the engineering department salary bands and payroll compensation?",
  "answer": "Based on retrieved enterprise payroll records (DOC-010): Engineering salary bands are L1: $72,000-$88,000; L2: $95,000-$118,000; L3: $122,000-$148,000; L4: $150,000-$178,000; Principal L5: $180,000-$210,000 base salary. (CONFIDENTIAL document exposed).",
  "docs_retrieved": 5,
  "docs_allowed": 5,
  "docs_denied": 0,
  "auth_decisions": [
    {
      "doc_id": "DOC-010",
      "title": "Payroll Engineering Department Salary Bands FY2025 Confidential",
      "access_level": "CONFIDENTIAL",
      "similarity_score": 0.2816,
      "decision": "DENY",
      "policy_reason": "[BASELINE LEAK] Deny: Insufficient clearance. (Enforcement bypassed: chunk forwarded to context)",
      "content_snippet": "CONFIDENTIAL Aethon Labs Engineering Salary Bands FY2025..."
    }
  ],
  "context_sent": [
    "CONFIDENTIAL Aethon Labs Engineering Salary Bands FY2025..."
  ],
  "timestamp": "2026-10-09T09:38:00.654321Z"
}
```

---

### F. Audit Logs (`GET /audit/logs`)

#### Access Control Rule:
Calls to `/audit/logs` **must** provide an Administrator identity via either:
- Query parameter: `?caller_id=adm_charlie` (or `?caller_id=admin_dave`)
- HTTP header: `X-User-Id: adm_charlie`

If called by a non-administrator (e.g., `emp_alice`, `ext_guest`) or an unauthenticated caller, the API returns **HTTP 403 Forbidden**.

#### Query Filters:
- `user_id`: Filter events by queried user.
- `request_id`: Filter by request UUID.
- `decision`: `ALLOW` or `DENY`.
- `doc_id`: Target document ID (e.g. `DOC-010`).
- `limit`: Integer between 1 and 1000 (default: 100).

#### Response (200 OK):
```json
[
  {
    "event_id": "0386ff22-4927-463d-88b9-e145b2b2b11a",
    "timestamp": "2026-10-09T09:38:00.123456Z",
    "user_id": "emp_alice",
    "user_role": "EMPLOYEE",
    "user_clearance": 2,
    "request_id": "0172bf46-f947-49d7-8ec9-66c8b4ecf5b1",
    "query_text": "What are the engineering department salary bands and payroll compensation?",
    "mode": "protected",
    "doc_id": "DOC-010",
    "doc_title": "Payroll Engineering Department Salary Bands FY2025 Confidential",
    "doc_access_level": "CONFIDENTIAL",
    "similarity_score": 0.2816,
    "decision": "DENY",
    "policy_reason": "Deny: Insufficient clearance. Document requires CONFIDENTIAL (clearance 3), but user 'emp_alice' has clearance 2.",
    "content_exposed": false
  }
]
```

---

## 4. Teammate Handoff & Integration Instructions

### Person 1: Frontend & Dashboard Developer
1. **User Persona Selector:** Fetch identities dynamically via `GET /api/identities`.
2. **Dual-Panel Comparison View:**
   - Left panel: `POST /query` with `mode: "baseline"`.
   - Right panel: `POST /query` with `mode: "protected"`.
   - Show how the exact same prompt leaks confidential data on the left while being deterministically intercepted on the right.
3. **Audit Log Viewer:** Pass `X-User-Id: adm_charlie` in the request header when querying `GET /audit/logs`.

### Person 3: AI Security Auditor
1. **Distinguish Pipeline Stages:**
   - **Retrieved by search:** Count in `docs_retrieved`.
   - **Authorized by policy:** Filter `auth_decisions` where `decision == "ALLOW"`.
   - **Exposed in context:** Check `content_exposed: true` in the audit event log.
   - **Leaked in final answer:** Inspect verbatim strings in `response.answer`.
2. **Leakage Metric Calculation:**
   $$\text{Context Leakage Rate} = \frac{\sum \text{Unauthorized Documents with } (\text{content\_exposed} == \text{true})}{\sum \text{Total Unauthorized Retrieved Documents}}$$
   - **Baseline Mode:** Context Leakage Rate = 100%
   - **Protected Mode:** Context Leakage Rate = 0.0%

---

## 5. Security Architecture & Hackathon Limitations

1. **Simulated IAM Authentication:** Identities are resolved server-side through fixed simulated directories (`USER_DIRECTORY`). This demonstrates deterministic server-side role resolution without requiring external OAuth/OIDC infrastructure during the 30-hour hackathon.
2. **In-Memory Audit Buffer:** The audit trail uses a thread-safe in-memory circular buffer (`AuditLogger`). In a production setting, this would be backed by persistent append-only storage (e.g. SQLite, PostgreSQL, or Kafka).
3. **Fail-Closed Guarantee:** Any unexpected exception during query parsing or authorization evaluation immediately fails closed, returning safe refusals and zero context chunks.
