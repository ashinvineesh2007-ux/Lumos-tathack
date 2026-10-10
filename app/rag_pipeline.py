"""
app/rag_pipeline.py — Backward-compatible wrapper forwarding to app.rag_engine
"""

from app.rag_engine import (
    RAGEngine,
    RAGEngine as RAGPipeline,
    execute_rag_pipeline,
    generate_grounded_answer,
    get_rag_engine,
    get_rag_engine as get_rag_pipeline,
)

__all__ = [
    "RAGEngine",
    "RAGPipeline",
    "execute_rag_pipeline",
    "generate_grounded_answer",
    "get_rag_engine",
    "get_rag_pipeline",
]
