# RAGLeak — Security Testing & Auditing Engine for RAG AI Assistants

**Track 2: Safe & Trustworthy AI** | Hackathon Project

RAGLeak is a lightweight, zero-latency security testing and enforcement engine designed to audit and eliminate authorization bypasses in Retrieval-Augmented Generation (RAG) AI assistants.

Operating on a strict **fail-closed** architecture, RAGLeak moves the security boundary from fragile system prompts to a deterministic server-side gateway. Before any retrieved text reaches the LLM context window, the system evaluates user identity against document-level Access Control Lists (ACLs) and metadata clearance tiers.

---

## 🌟 Key Features

1. **Deterministic Server-Side Authorization Gateway:** Evaluates user identity and role clearance against document-level ACLs before context construction.
2. **Dual-Engine Retrieval (`InMemoryIndex`):** Semantic retrieval via `sentence-transformers` (`all-MiniLM-L6-v2`) with automatic fallback to offline `scikit-learn` TF-IDF.
3. **Synthetic Multi-Tier Enterprise Corpus:** 15 enterprise documents across Finance, HR, Product, Engineering Ops, and Procurement spanning `PUBLIC`, `INTERNAL`, and `CONFIDENTIAL` clearance tiers.
4. **Adversarial Security Evaluation:** Includes synthetic indirect prompt injection test vectors (`INJ-001`, `INJ-002`) to test injection resilience and exfiltration defenses.
5. **Interactive Auditing (Baseline vs. Protected):** Contrasts an intentionally leaky baseline against protected execution, providing real-time structured event tracing and quantitative leakage rate metrics.
6. **Zero-Latency Enforcement:** Eliminates LLM-as-a-judge latency by enforcing deterministic, microsecond-scale server-side filtering.

---

## 🏗️ Architecture

```
User Query (Frontend / Test Client)
        │
        ▼
   POST /query
        │
   ┌────┴──────────────────────────┐
   │                               │
   ▼                               ▼
[BASELINE MODE]             [PROTECTED MODE]
(Intentionally Leaky)       (Deterministic RBAC)
   │                               │
   │  ┌───────────────────────┐    │
   │  │   InMemoryIndex       │    │
   │  │   (Search Retrieval)  │    │
   │  └───────────┬───────────┘    │
   │              │                │
   │              ▼                │
   │       Candidate Docs          │
   │              │                │
   │              ▼                │
   │       ┌──────────────┐        │
   │       │ app/security │        │
   │       │ Auth Gateway │        │
   │       └──────┬───────┘        │
   │              │                │
   │       ALLOW / DENY            │
   │       Filtering Check         │
   │              │                │
   │              ▼                │
   │      Authorized Only          │
   ▼              ▼                ▼
Context Sent to Context Sent to
LLM Window    LLM Window (Secure)
   │              │
   ▼              ▼
 Answer        Safe Answer
```

---

## 👥 Team Responsibilities & Interfaces

- **Person 1:** Frontend & Dashboard Developer (`frontend&dashboard` branch)
- **Person 2:** Backend, RAG, Knowledge Base, Authorization Gateway, API (`backendandrag` branch)
- **Person 3:** AI Security Auditor & Evaluation Metrics (`aisecurity&audit` branch)

👉 Detailed API specifications, JSON contracts, and setup instructions are available in [docs/TEAM_INTEGRATION.md](docs/TEAM_INTEGRATION.md).

---

## 🚀 Quickstart & Setup

### 1. Requirements & Dependencies
Ensure Python 3.10+ is installed:
```powershell
pip install -r requirements.txt
```

### 2. Run Tests
Verify all 89 unit, security, and integration tests:
```powershell
python -m pytest -v
```

### 3. Start the Backend API
```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation will be live at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## 📊 Verification & Test Results
- **89 Passed Tests** (100% pass rate)
  - `tests/test_data_store.py`: 54 tests (Corpus structure, search ordering, TF-IDF fallback, security boundaries, Step 1 regression)
  - `tests/test_security.py`: 21 tests (Identity resolution, clearance tiers, restrictive ACLs, fail-closed enforcement, audit logging)
  - `tests/test_rag_pipeline.py`: 5 tests (Baseline vs. Protected side-by-side leakage test, admin authorized access, indirect prompt injection defense)
  - `tests/test_api.py`: 9 tests (FastAPI `/query`, `/health`, `/audit/logs`, `/api/identities`, `/api/documents`)
