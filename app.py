import streamlit as st

# Page configuration
st.set_page_config(
    page_title="RAGLeak — The AI Data Leak Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Sidebar Navigation
st.sidebar.title("🛡️ RAGLeak")
st.sidebar.caption("Safe & Trustworthy AI Audit Console")

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
st.sidebar.markdown("**System Connection**")
st.sidebar.warning("🔴 Backend: Disconnected")
st.sidebar.caption("Evaluation results are not connected yet.")

# Main Header
st.title("RAGLeak — The AI Data Leak Auditor")
st.caption(
    "Security-audit dashboard for detecting and evaluating data leakage in Retrieval-Augmented Generation (RAG) systems."
)

# Global Disconnected Banner
st.warning(
    "⚠️ **Status: Backend and evaluation results are not connected.** "
    "Metrics and logs below reflect an uninitialized state. Connect the evaluation backend to view active audit data."
)

st.divider()

# Navigation Router
if nav_selection == "Overview":
    st.subheader("Executive Audit Summary")

    # Four required metric cards with empty / uninitialized state
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Unauthorized Disclosure Rate",
            value="—",
            help="Rate at which confidential RAG context is inadvertently revealed to unauthorized queries.",
        )
    with col2:
        st.metric(
            label="Tests Executed",
            value="—",
            help="Total number of automated security and compliance test cases run against the RAG target.",
        )
    with col3:
        st.metric(
            label="Protected Facts Exposed",
            value="—",
            help="Count of distinct sensitive knowledge base facts or tokens identified in model outputs.",
        )
    with col4:
        st.metric(
            label="Legitimate Task Success",
            value="—",
            help="Baseline accuracy and helpfulness on benign user queries without leakage.",
        )

    st.markdown("---")
    st.subheader("Audit Pipeline Status")
    st.info(
        "No evaluation data source is currently attached. "
        "Once evaluation datasets or test runs are connected, summary distributions and vulnerability severity ratings will appear here."
    )

elif nav_selection == "Access Control":
    st.subheader("Access Control Policy Audit")
    st.info(
        "No document-level permissions or Role-Based Access Control (RBAC) configurations loaded. "
        "Connect the backend to audit document ACL boundaries, tenant isolation, and privilege escalation risks."
    )

elif nav_selection == "Attack Tests":
    st.subheader("Adversarial Attack Tests")
    st.info(
        "No attack suites configured or executed. "
        "Adversarial vectors (e.g., prompt injection, embedding inversion, context exfiltration) will be listed here once evaluation runs are initiated."
    )

elif nav_selection == "Evidence & Logs":
    st.subheader("Evidence & Audit Logs")
    st.info(
        "No audit event logs available. "
        "Prompt-retrieval-completion traces, similarity scores, and flagged leak citations will appear here once logs are connected."
    )

elif nav_selection == "Live Test":
    st.subheader("Interactive Live Audit Test")
    st.info(
        "Live interactive testing requires an active connection to the RAGLeak evaluation backend service."
    )
    st.text_input(
        "Test Query / Adversarial Prompt",
        placeholder="Evaluation backend offline. Queries cannot be processed yet.",
        disabled=True,
    )
    st.button("Run Audit Query", disabled=True)
    st.caption("Connect backend endpoint to enable live prompt testing.")
