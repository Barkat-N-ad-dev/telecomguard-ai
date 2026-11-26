"""RAG Evaluation Lab UI module."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from telecomguard.config import SUPPORTED_GEMINI_MODELS
from telecomguard.frontend.styles import render_empty_state, render_kpi_card, render_page_header
from telecomguard.services.rag_engine import rag_engine


def render() -> None:
    render_page_header(
        "RAG Evaluation Lab",
        "Ingest telecom policy documents into ChromaDB, inspect retrieved chunks, and measure Recall@K, Precision@K, MRR, and Groundedness.",
    )

    kbs = rag_engine.list_knowledge_bases()
    kb_map = {f"{kb['name']} ({kb['document_count']} docs, {kb['total_chunks']} chunks)": kb["id"] for kb in kbs}

    col_kb, col_btn = st.columns([2.5, 1.5])
    with col_kb:
        selected_kb_label = st.selectbox("Active Knowledge Base", list(kb_map.keys()))
        kb_id = kb_map[selected_kb_label]
    with col_btn:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        if st.button("Index Built-In Telecom Policies", use_container_width=True):
            added = rag_engine.ingest_builtin_policies(kb_id)
            st.success(f"Indexed {added} policy document(s) into knowledge base.")
            st.rerun()

    tab_qa, tab_docs = st.tabs(["Ask & Evaluate Groundedness", "Knowledge Base & Documents"])

    with tab_qa:
        with st.form("rag_eval_form"):
            query = st.text_input(
                "Ask a telecom policy or operations question",
                value="What is the maximum automated refund limit and when must a request be escalated?",
            )
            c1, c2, c3 = st.columns([1.2, 2.0, 1.5])
            with c1:
                top_k = st.slider("Top-K Chunks", min_value=1, max_value=8, value=4)
            with c2:
                labels_raw = st.text_input(
                    "Labeled Relevant Terms/Filenames (comma-separated for Recall@K / MRR)",
                    value="POL-BILL-01, $25.00, Tier-2",
                )
            with c3:
                model_name = st.selectbox("Gemini Model", SUPPORTED_GEMINI_MODELS, index=0)
            run_rag = st.form_submit_button("Retrieve & Evaluate RAG Answer", type="primary", use_container_width=True)

        if run_rag and query.strip():
            labels = [s.strip() for s in labels_raw.split(",") if s.strip()]
            with st.spinner("Retrieving chunks from ChromaDB and evaluating groundedness..."):
                res = rag_engine.ask_and_evaluate(
                    kb_id=kb_id,
                    query=query.strip(),
                    top_k=top_k,
                    relevant_labels=labels,
                    model_name=model_name,
                )
            st.session_state["last_rag_result"] = res

        res = st.session_state.get("last_rag_result")
        if res:
            m = res["metrics"]
            k1, k2, k3, k4, k5 = st.columns(5)
            with k1:
                render_kpi_card("Recall@K", f"{m['recall_at_k']:.2f}", f"Top-{len(res['chunks'])} retrieval", "#22D3EE")
            with k2:
                render_kpi_card("Precision@K", f"{m['precision_at_k']:.2f}", "Chunk hit precision", "#06B6D4")
            with k3:
                render_kpi_card("MRR", f"{m['mrr']:.2f}", "Mean Reciprocal Rank", "#10B981")
            with k4:
                render_kpi_card("Context Relevance", f"{m['context_relevance']:.2f}", "Mean cosine similarity", "#10B981")
            with k5:
                g_color = "#10B981" if m["groundedness"] >= 0.75 else "#F59E0B"
                render_kpi_card("Groundedness", f"{m['groundedness']:.2f}", f"Mode: {res['execution_mode']}", g_color)

            st.subheader("Generated Answer & Citation Audit")
            st.markdown(f"<div class='tg-card'>{res['answer']}</div>", unsafe_allow_html=True)
            st.caption(f"Audit Explanation: {res['explanation']}")

            col_u, col_m = st.columns(2)
            with col_u:
                st.markdown("**Unsupported Claims Detected**")
                if res["unsupported_claims"]:
                    for uc in res["unsupported_claims"]:
                        st.warning(uc)
                else:
                    st.success("Zero unsupported claims detected.")
            with col_m:
                st.markdown("**Missing Citations Detected**")
                if res["missing_citations"]:
                    for mc in res["missing_citations"]:
                        st.warning(mc)
                else:
                    st.success("All claims properly cited.")

            st.subheader("Retrieved Source Chunks")
            for ch in res["chunks"]:
                with st.expander(f"Rank #{ch['rank']} | {ch['source_filename']} ({ch['chunk_id']}) | Similarity: {ch['similarity_score']:.4f}"):
                    st.write(ch["text"])

    with tab_docs:
        col_up, col_new = st.columns(2)
        with col_up:
            st.subheader("Upload Documents (.pdf, .txt, .docx)")
            doc_file = st.file_uploader("Upload Policy / Knowledge Document (max 10 MB)", type=["pdf", "txt", "docx"])
            if st.button("Ingest Document into ChromaDB"):
                if doc_file is None:
                    st.error("Select a file first.")
                else:
                    try:
                        info = rag_engine.ingest_document(kb_id, doc_file.name, doc_file.getvalue())
                        st.success(f"Indexed '{info['filename']}' ({info['chunk_count']} chunks, sha256={info['sha256']}).")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Document ingestion failed: {exc}")

        with col_new:
            st.subheader("Create New Knowledge Base")
            with st.form("create_kb_form"):
                kb_name = st.text_input("Knowledge Base Name", placeholder="e.g., 5G Roaming Tariffs KB")
                kb_desc = st.text_input("Description")
                emb_backend = st.selectbox("Embedding Backend", ["local-hash-projection", "gemini", "sentence-transformer"])
                if st.form_submit_button("Create Knowledge Base"):
                    if not kb_name.strip():
                        st.error("Knowledge base name is required.")
                    else:
                        rag_engine.create_knowledge_base(kb_name, kb_desc, embedding_backend=emb_backend)
                        st.success(f"Created knowledge base '{kb_name}'.")
                        st.rerun()

        st.subheader("Indexed Documents")
        docs = rag_engine.list_documents(kb_id)
        if docs:
            st.dataframe(pd.DataFrame(docs), use_container_width=True, hide_index=True)
        else:
            render_empty_state(
                "Knowledge Base Has No Documents",
                "Click 'Index Built-In Telecom Policies' above or upload a PDF, TXT, or DOCX file.",
            )
