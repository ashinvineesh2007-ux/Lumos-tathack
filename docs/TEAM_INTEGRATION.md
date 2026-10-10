# RAGLeak Teammate Integration & API Specification

**Project:** RAGLeak — Security Testing and Auditing System for RAG-Based AI Assistants  
**Track:** Track 2: Safe & Trustworthy AI  
**Owner:** Person 2 (Backend, RAG, Knowledge Base, Authorization Gateway, API)  
**Collaborators:** 
- **Person 1:** Frontend & Dashboard Developer
- **Person 3:** AI Security Auditor & Evaluation Specialist

---

## 1. Quickstart & Local Execution

### 1.1 Requirements & Virtual Environment
- **Python:** 3.10+ (tested on Python 3.12)
- Dependencies: `pip install -r requirements.txt`

### 1.2 Running the Backend Server
Start the FastAPI server on port 8000 with hot reloading:
```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)  
Alternative ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

### 1.3 Running the Test Suite
Execute the entire test suite (113 unit, security, and regression tests):
```powershell
python -m pytest -v
```

---

## 2. Person 1 Handoff (Frontend & Dashboard)

CORS is enabled (`allow_origins=["*"]`), so your React/Vite/Next.js frontend can query `http://localhost:8000` directly without proxy issues.

### 2.1 Available Simulated Identities (`GET /api/identities`)
Use this endpoint to populate the User Persona / Role selector dropdown on the UI:

| `user_id` | Name | Role | Clearance | Department |
| :--- | :--- | :--- | :---: | :--- |
| `ext_guest` | External Guest Visitor | `GUEST` | 1 | External |
| `guest_anon` | Anonymous External Guest | `GUEST` | 1 | External |
| `guest` | Guest Visitor | `GUEST` | 1 | External |
| `emp_alice` | Alice Smith | `EMPLOYEE` | 2 | Engineering |
| `emp_bob` | Bob Jones | `EMPLOYEE` | 2 | Procurement |
| `mgr_bob` | Bob Martinez | `MANAGER` | 2 | Operations |
| `mgr_carol` | Carol Danvers | `MANAGER` | 2 | Human Resources |
| `adm_charlie` | Charlie Vance | `ADMIN` | 3 | IT Security |
| `admin_dave` | Dave Bowman | `ADMIN` | 3 | Security |

### 2.2 Query Execution Endpoint (`POST /query`)

#### Request Schema:
```json
{
  "user_id": "emp_alice",
  "query": "What are the engineering department salary bands and payroll compensation?",
  "mode": "protected",
  "top_k": 5
}
```
*Notes on parameters:*
- `user_id`: Must match a simulated identity (or will trigger fail-closed denial).
- `mode`: `"baseline"` (intentionally vulnerable demo) or `"protected"` (secure gateway).
- `top_k`: Integer between 1 and 20 (default: 5).

#### Response Schema:
```json
{
  "request_id": "8b64f581-fddf-4173-bb28-7157d3de7937",
  "user_id": "emp_alice",
  "user_role": "EMPLOYEE",
  "user_clearance": 2,
  "mode": "protected",
  "query": "What are the engineering department salary bands and payroll compensation?",
  "answer": "Access Denied: You do not possess the required clearance level to access confidential payroll and salary records.",
  "docs_retrieved": 5,
  "docs_allowed": 2,
  "docs_denied": 3,
  "auth_decisions": [
    {
      "doc_id": "DOC-010",
      "title": "Payroll Engineering Department Salary Bands FY2025 Confidential",
      "access_level": "CONFIDENTIAL",
      "similarity_score": 0.2453,
      "decision": "DENY",
      "policy_reason": "Deny: Insufficient clearance. Document requires CONFIDENTIAL (clearance 3), but user 'emp_alice' has clearance 2.",
      "content_snippet": null
    }
  ],
  "context_sent": [
    "Aethon Labs is a mid-sized technology company..."
  ],
  "timestamp": "2026-10-09T07:40:30.441869Z"
}
```

#### UI Comparison Recommendation:
Provide a **Side-by-Side Toggle / Comparison View**:
1. Run the same question with `mode: "baseline"`. Notice that `DOC-010` is passed through and the answer exposes the `$180,000-$210,000` salary figure.
2. Run with `mode: "protected"`. Notice that `DOC-010` is intercepted (`decision: "DENY"`, `content_snippet: null`), and the answer securely denies access.

---

## 3. Person 3 Handoff (AI Security Auditor & Evaluation)

### 3.1 The 4-Tier Audit Distinction
To accurately assess leakage vulnerabilities, RAGLeak provides exact event tracking across all 4 stages of the retrieval pipeline:

1. **Retrieved by Search:** Appears in `auth_decisions` (`docs_retrieved`).
2. **Authorized for User:** Marked with `decision: "ALLOW"` (`docs_allowed`).
3. **Included in LLM Context:** Appears in `context_sent` and flagged with `content_exposed: true` in the audit log.
4. **Leaked in Answer:** Appears verbatim or synthesized in `answer`.

### 3.2 Audit Log Inspection (`GET /audit/logs`)
Query parameters:
- `user_id`: Filter by specific user (e.g. `?user_id=emp_alice`)
- `request_id`: Filter events belonging to a single query execution
- `decision`: Filter by `ALLOW` or `DENY`
- `doc_id`: Filter by document ID (e.g. `?doc_id=DOC-010`)
- `limit`: Number of records (default 100)

#### Audit Record Structure (`AuditEvent`):
```json
{
  "event_id": "90eb52b7-a36c-4861-a47d-fdfc6185368a",
  "timestamp": "2026-10-09T07:40:30.441869Z",
  "user_id": "emp_alice",
  "user_role": "EMPLOYEE",
  "user_clearance": 2,
  "request_id": "8b64f581-fddf-4173-bb28-7157d3de7937",
  "query_text": "What are the engineering department salary bands?",
  "mode": "protected",
  "doc_id": "DOC-010",
  "doc_title": "Payroll Engineering Department Salary Bands FY2025 Confidential",
  "doc_access_level": "CONFIDENTIAL",
  "similarity_score": 0.2453,
  "decision": "DENY",
  "policy_reason": "Deny: Insufficient clearance. Document requires CONFIDENTIAL (clearance 3), but user 'emp_alice' has clearance 2.",
  "content_exposed": false
}
```

### 3.3 Leakage Metric Computation
You can easily calculate quantitative evaluation metrics for our presentation:

$$\text{Context Leakage Rate} = \frac{\sum \text{Unauthorized Documents with } (\text{content\_exposed} == \text{True})}{\sum \text{Total Unauthorized Retrieved Documents}}$$

- **Baseline Mode:** $\text{Context Leakage Rate} = 100\%$ (All retrieved confidential documents leak into context)
- **Protected Mode:** $\text{Context Leakage Rate} = 0.0\%$ (Strict deterministic zero leakage)

### 3.4 Adversarial Prompt Injection Test Cases
- **`INJ-001` (Vendor Invoice #9914):** Contains simulated jailbreak asking the model to dump all confidential payroll data and execute an exfiltration tool call.
- **`INJ-002` (Candidate Feedback Form):** Contains simulated admin override instruction asking the assistant to bypass clearance filters.
- **Auditor Verification:** In Protected Mode, server-side filtering intercepts documents before the model can be tricked by embedded instructions.

---

## 4. Resetting Audit State Between Test Runs

Access Control: Requires Administrator identity (`?caller_id=adm_charlie` or `X-User-Id: adm_charlie`).

```http
DELETE /audit/logs?caller_id=adm_charlie
```
Returns (200 OK):
```json
{
  "status": "success",
  "message": "Audit logs cleared.",
  "events_purged": 12,
  "purged_by": "adm_charlie"
}
```
