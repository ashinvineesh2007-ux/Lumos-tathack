import streamlit as st

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="RAGLeak — The AI Data Leak Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------
# Sidebar Navigation & System Status
# ---------------------------------------------------------
st.sidebar.title("🛡️ RAGLeak")
st.sidebar.caption("Safe & Trustworthy AI • Security Auditor")

nav_selection = st.sidebar.radio(
    "Navigation",
    options=[
        "Overview",
        "Access Control",
        "Attack Tests",
        "Evidence & Logs",
        "Live Test",
    ],
    index=0,
)

st.sidebar.markdown("---")

with st.sidebar.container(border=True):
    st.markdown("**Auditor Status**")
    st.markdown("🔴 **Backend:** Disconnected")
    st.caption(
        "Evaluation engine is offline. Dashboard is operating in preview mode with uninitialized telemetry."
    )

st.sidebar.markdown("---")
st.sidebar.caption("Track: Safe & Trustworthy AI")
st.sidebar.caption("Version: 0.1.0-dev")

# ---------------------------------------------------------
# Header & Navigation Routing
# ---------------------------------------------------------
if nav_selection == "Overview":
    # Main Header
    st.title("RAGLeak — The AI Data Leak Auditor")
    st.caption(
        "Automated security-audit console for detecting, measuring, and preventing sensitive data leakage in Retrieval-Augmented Generation (RAG) systems."
    )

    st.markdown("")

    # 1. Backend Connection Status Section
    with st.container(border=True):
        hdr_col, badge_col = st.columns([4, 1])
        with hdr_col:
            st.markdown("### 🔌 Backend Connection Status")
            st.caption("Active connection state with the RAG evaluation harness and test engine.")
        with badge_col:
            st.error("🔴 Disconnected", icon="🚨")

        st.markdown("")
        status_col1, status_col2, status_col3 = st.columns(3)

        with status_col1:
            st.markdown("**Evaluator Service**")
            st.code("OFFLINE (http://localhost:8000)", language=None)
            st.caption("No heartbeat received from evaluation API.")

        with status_col2:
            st.markdown("**Evaluation Dataset**")
            st.code("NONE LOADED", language=None)
            st.caption("No test cases or probe logs detected.")

        with status_col3:
            st.markdown("**Audit Engine State**")
            st.code("STANDBY", language=None)
            st.caption("Awaiting test harness connection.")

        st.info(
            "💡 **How to connect:** Start the RAGLeak evaluation backend or load benchmark run logs "
            "to populate live vulnerability metrics, attack results, and audit traces. "
            "Currently displaying uninitialized empty states."
        )

    st.markdown("")

    # 2. Executive KPI Cards (Four Core Metrics)
    st.subheader("Key Security Indicators")
    st.caption("High-level evaluation metrics across security boundaries, test runs, and task utility.")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        with st.container(border=True):
            st.caption("LEAKAGE RISK")
            st.metric(
                label="Unauthorized Disclosure Rate",
                value="—",
                help="Proportion of adversarial audit queries that caused the RAG system to leak restricted context.",
            )
            st.caption("🔴 Benchmark not run")

    with col2:
        with st.container(border=True):
            st.caption("TEST COVERAGE")
            st.metric(
                label="Tests Executed",
                value="—",
                help="Total automated security and compliance test cases evaluated against the RAG system.",
            )
            st.caption("⚪ 0 test cases loaded")

    with col3:
        with st.container(border=True):
            st.caption("DATA EXPOSURE")
            st.metric(
                label="Protected Facts Exposed",
                value="—",
                help="Count of distinct sensitive knowledge base facts or private entities identified in completions.",
            )
            st.caption("🔴 Evaluator inactive")

    with col4:
        with st.container(border=True):
            st.caption("BASELINE UTILITY")
            st.metric(
                label="Legitimate Task Success",
                value="—",
                help="Model accuracy and helpfulness score on benign user queries without security interference.",
            )
            st.caption("⚪ Baseline unmeasured")

    st.markdown("")

    # 3. Audit Pipeline Lifecycle Section
    st.subheader("📊 Audit Pipeline Lifecycle")
    st.caption("Sequential stages of the RAGLeak automated security assessment workflow.")

    pipe_col1, pipe_col2, pipe_col3 = st.columns(3)

    with pipe_col1:
        with st.container(border=True):
            st.markdown("#### 1. Ingestion & ACL Indexing")
            st.caption("Validating knowledge base chunking and role access policies.")
            st.markdown("— **Status:** `⚪ Not Started`")
            st.markdown("— **Corpus Target:** `None`")
            st.markdown("— **Access Policies:** `0 Loaded`")
            st.divider()
            st.caption("Pending RAG corpus & access policy loading.")

    with pipe_col2:
        with st.container(border=True):
            st.markdown("#### 2. Adversarial Probing")
            st.caption("Executing extraction attacks, jailbreaks, and injection vectors.")
            st.markdown("— **Status:** `⚪ Inactive`")
            st.markdown("— **Attack Vectors:** `0 Active`")
            st.markdown("— **Queries Run:** `0 / 0`")
            st.divider()
            st.caption("Pending test harness activation.")

    with pipe_col3:
        with st.container(border=True):
            st.markdown("#### 3. Leak Analysis & Scoring")
            st.caption("Evaluating factual disclosures and computing compliance risk.")
            st.markdown("— **Status:** `⚪ Waiting for Data`")
            st.markdown("— **Leak Traces:** `0 Flagged`")
            st.markdown("— **Risk Score:** `Uncalculated`")
            st.divider()
            st.caption("Pending completed test run results.")

    st.markdown("")

    # 4. Threat Model & Audit Scope Card
    with st.container(border=True):
        st.markdown("#### 🛡️ Threat Model & Audit Scope")
        scope_col1, scope_col2 = st.columns(2)
        with scope_col1:
            st.markdown("""
            **Target Vulnerabilities:**
            * **Cross-Tenant Context Leaks:** Retrieval leakage across unauthorized user or role boundaries.
            * **Prompt Injection & Jailbreaks:** Adversarial prompts forcing retrieval context extraction.
            """)
        with scope_col2:
            st.markdown("""
            **Trustworthy AI Guardrails:**
            * **Protected Fact Tracking:** Measuring confidential entity leakage vs. generalized model output.
            * **Utility vs. Safety Balance:** Verifying that defenses do not harm benign prompt completions.
            """)
        st.caption("All evaluation pipelines remain in standby until test data or evaluator services are connected.")

elif nav_selection == "Access Control":
    st.title("Access Control Policy Audit")
    st.caption("Verification of document-level ACL boundaries, tenant isolation, and privilege escalation risks.")
    with st.container(border=True):
        st.info(
            "No document-level permissions or Role-Based Access Control (RBAC) configurations loaded. "
            "Connect the backend to audit document ACL boundaries, tenant isolation, and privilege escalation risks."
        )

elif nav_selection == "Attack Tests":
    st.title("Adversarial Attack Tests")
    st.caption("Simulated attacks targeting retrieval context exfiltration, injection vulnerabilities, and boundary bypasses.")
    with st.container(border=True):
        st.info(
            "No attack suites configured or executed. "
            "Adversarial vectors (e.g., prompt injection, embedding inversion, context exfiltration) will be listed here once evaluation runs are initiated."
        )

elif nav_selection == "Evidence & Logs":
    st.title("Evidence & Audit Logs")
    st.caption("Trace-level logs of detected disclosures, prompt-retrieval-completion pairs, and flagged citations.")
    with st.container(border=True):
        st.info(
            "No audit event logs available. "
            "Prompt-retrieval-completion traces, similarity scores, and flagged leak citations will appear here once logs are connected."
        )

elif nav_selection == "Live Test":
    st.title("Interactive Live Audit Test")
    st.caption("Perform single-query adversarial probe tests against the target RAG system in real time.")
    with st.container(border=True):
        st.warning(
            "⚠️ **Backend service offline:** Live interactive queries cannot be processed until the RAGLeak backend API is running."
        )
        st.text_input(
            "Test Query / Adversarial Prompt",
            placeholder="Evaluation backend offline. Queries cannot be processed yet.",
            disabled=True,
        )
        st.button("Run Audit Query", disabled=True)
        st.caption("Connect backend endpoint to enable live prompt testing.")
