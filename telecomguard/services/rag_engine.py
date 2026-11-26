"""RAG Pipeline & Retrieval/Groundedness Evaluation Lab powered by ChromaDB and Gemini."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("telecomguard.rag")


class _LocalVectorCollection:
    """Persistent JSON-backed cosine-similarity vector collection matching ChromaDB's subset API."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._records: Dict[str, Dict[str, Any]] = {}
        if self._path.exists():
            try:
                self._records = json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                self._records = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._records), encoding="utf-8")

    def count(self) -> int:
        return len(self._records)

    def upsert(self, ids: List[str], documents: List[str], embeddings: List[List[float]], metadatas: List[Dict[str, Any]]) -> None:
        for cid, doc, emb, meta in zip(ids, documents, embeddings, metadatas):
            self._records[cid] = {"document": doc, "embedding": emb, "metadata": meta}
        self._save()

    def query(self, query_embeddings: List[List[float]], n_results: int = 4) -> Dict[str, Any]:
        q = query_embeddings[0]
        q_norm = math.sqrt(sum(x * x for x in q)) or 1.0
        scored = []
        for cid, rec in self._records.items():
            v = rec["embedding"]
            v_norm = math.sqrt(sum(x * x for x in v)) or 1.0
            dot = sum(a * b for a, b in zip(q, v))
            sim = dot / (q_norm * v_norm)
            dist = max(0.0, 1.0 - sim)
            scored.append((dist, cid, rec))
        scored.sort(key=lambda item: item[0])
        top = scored[:n_results]
        return {
            "ids": [[item[1] for item in top]],
            "documents": [[item[2]["document"] for item in top]],
            "metadatas": [[item[2]["metadata"] for item in top]],
            "distances": [[item[0] for item in top]],
        }


class _LocalVectorClient:
    """Fallback vector store client used only if host ChromaDB cannot import."""

    def __init__(self, persist_dir: Path) -> None:
        self._persist_dir = persist_dir

    def get_or_create_collection(self, name: str, metadata: Dict[str, Any] | None = None) -> _LocalVectorCollection:
        return _LocalVectorCollection(self._persist_dir / f"{name}.json")


def _build_vector_client(persist_dir: Path):
    try:
        import chromadb

        return chromadb.PersistentClient(path=str(persist_dir)), "chromadb"
    except Exception as exc:
        logger.warning("ChromaDB unavailable (%s); using local persistent vector store fallback.", exc)
        return _LocalVectorClient(persist_dir), "local-vector-fallback"

from telecomguard.backend.database import get_db
from telecomguard.backend.models import AuditLog, Document, KnowledgeBase, RetrievedChunk
from telecomguard.backend.schemas import RagGroundednessSchema
from telecomguard.config import settings
from telecomguard.services.gemini_service import GeminiService, gemini_service


def _hash_projection_embedding(text: str, dim: int = 256) -> List[float]:
    """Deterministic local n-gram vector fallback when offline or embedding model unavailable."""
    vec = [0.0] * dim
    tokens = re.findall(r"[a-z0-9]{2,}", text.lower())
    for tok in tokens:
        digest = hashlib.sha256(tok.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:2], "big") % dim
        sign = 1.0 if (digest[2] % 2 == 0) else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [round(v / norm, 6) for v in vec]


class RAGEngine:
    """Handles document validation, chunking, ChromaDB indexing, retrieval, IR metrics, and groundedness."""

    def __init__(self, llm: GeminiService | None = None, persist_dir: Path | None = None) -> None:
        self.llm = llm or gemini_service
        self.persist_dir = persist_dir or settings.chroma_persist_dir
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self._client, self.vector_backend = _build_vector_client(self.persist_dir)
        self._st_model = None

    def _embed_texts(self, texts: List[str], backend: str = "local") -> List[List[float]]:
        if backend == "gemini" and self.llm.is_configured():
            gemini_vecs = self.llm.embed_texts(texts)
            if gemini_vecs:
                return gemini_vecs
        # Try local SentenceTransformer only if already cached (avoid slow offline failures)
        try:
            if self._st_model is None and backend == "sentence-transformer":
                from sentence_transformers import SentenceTransformer

                self._st_model = SentenceTransformer("all-MiniLM-L6-v2", local_files_only=True)
            if self._st_model is not None:
                return [list(map(float, v)) for v in self._st_model.encode(texts)]
        except Exception:
            pass
        return [_hash_projection_embedding(t) for t in texts]

    @staticmethod
    def validate_and_extract_text(filename: str, raw_bytes: bytes) -> tuple[str, str]:
        """Validate upload extension & size, then extract text safely."""
        if len(raw_bytes) > settings.max_upload_bytes:
            raise ValueError(f"File '{filename}' exceeds {settings.max_upload_bytes // (1024 * 1024)} MB cap.")
        safe_name = Path(filename).name
        ext = Path(safe_name).suffix.lower()
        if ext not in settings.allowed_doc_extensions:
            raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(settings.allowed_doc_extensions)}")

        if ext == ".txt":
            if b"\x00" in raw_bytes[:4096]:
                raise ValueError(f"Binary content detected in text upload '{safe_name}'.")
            text = raw_bytes.decode("utf-8", errors="replace")
        elif ext == ".pdf":
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(raw_bytes))
            pages = [page.extract_text() or "" for page in reader.pages]
            text = "\n\n".join(pages).strip()
        elif ext == ".docx":
            import docx

            doc = docx.Document(io.BytesIO(raw_bytes))
            text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        else:
            raise ValueError(f"Unsupported extension: {ext}")

        if not text.strip():
            raise ValueError(f"No readable text extracted from '{safe_name}'.")
        return ext.lstrip("."), text.strip()

    @staticmethod
    def chunk_text(text: str, chunk_size: int = 450, chunk_overlap: int = 60) -> List[str]:
        words = text.split()
        if not words:
            return []
        chunks: List[str] = []
        step = max(chunk_size - chunk_overlap, 50)
        # Convert char-approx chunk_size (~6 chars/word) to word count cleanly
        words_per_chunk = max(chunk_size // 6, 40)
        word_step = max(step // 6, 20)
        idx = 0
        while idx < len(words):
            segment = " ".join(words[idx : idx + words_per_chunk]).strip()
            if segment:
                chunks.append(segment)
            if idx + words_per_chunk >= len(words):
                break
            idx += word_step
        return chunks

    def list_knowledge_bases(self) -> List[Dict[str, Any]]:
        with get_db() as db:
            kbs = db.query(KnowledgeBase).order_by(KnowledgeBase.id.asc()).all()
            return [
                {
                    "id": kb.id,
                    "name": kb.name,
                    "description": kb.description,
                    "collection_name": kb.collection_name,
                    "embedding_backend": kb.embedding_backend,
                    "document_count": len(kb.documents),
                    "total_chunks": sum(d.chunk_count for d in kb.documents),
                }
                for kb in kbs
            ]

    def list_documents(self, kb_id: int) -> List[Dict[str, Any]]:
        with get_db() as db:
            docs = db.query(Document).filter(Document.knowledge_base_id == kb_id).order_by(Document.created_at.desc()).all()
            return [
                {
                    "id": d.id,
                    "filename": d.filename,
                    "file_type": d.file_type,
                    "file_size_bytes": d.file_size_bytes,
                    "chunk_count": d.chunk_count,
                    "sha256_hash": d.sha256_hash[:12],
                    "created_at": d.created_at.isoformat(),
                }
                for d in docs
            ]

    def create_knowledge_base(self, name: str, description: str = "", embedding_backend: str = "local") -> int:
        slug = re.sub(r"[^a-zA-Z0-9_]+", "_", name.strip().lower()).strip("_") or "kb"
        collection_name = f"tg_{slug}_{hashlib.md5(name.encode()).hexdigest()[:6]}"
        with get_db() as db:
            kb = KnowledgeBase(
                name=name.strip(),
                description=description.strip(),
                collection_name=collection_name,
                embedding_backend=embedding_backend,
            )
            db.add(kb)
            db.flush()
            return int(kb.id)

    def ingest_document(self, kb_id: int, filename: str, raw_bytes: bytes) -> Dict[str, Any]:
        file_type, text = self.validate_and_extract_text(filename, raw_bytes)
        sha256_hex = hashlib.sha256(raw_bytes).hexdigest()

        with get_db() as db:
            kb = db.query(KnowledgeBase).filter(KnowledgeBase.id == kb_id).first()
            if not kb:
                raise ValueError(f"KnowledgeBase id={kb_id} not found.")

            chunks = self.chunk_text(text, kb.chunk_size, kb.chunk_overlap)
            doc = Document(
                knowledge_base_id=kb.id,
                filename=Path(filename).name,
                file_type=file_type,
                file_size_bytes=len(raw_bytes),
                sha256_hash=sha256_hex,
                chunk_count=len(chunks),
            )
            db.add(doc)
            db.flush()

            collection = self._client.get_or_create_collection(
                name=kb.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            embeddings = self._embed_texts(chunks, backend=kb.embedding_backend)
            ids = [f"doc{doc.id}_chunk{i}" for i in range(len(chunks))]
            metadatas = [
                {"doc_id": doc.id, "filename": doc.filename, "chunk_index": i}
                for i in range(len(chunks))
            ]
            collection.upsert(ids=ids, documents=chunks, embeddings=embeddings, metadatas=metadatas)

            db.add(
                AuditLog(
                    actor="eval_engineer",
                    role="analyst",
                    action="rag_document_ingest",
                    resource=f"{kb.name}/{doc.filename}",
                    decision="ALLOWED",
                    reason=f"Indexed {len(chunks)} chunks into ChromaDB collection '{kb.collection_name}'.",
                )
            )
            return {
                "document_id": doc.id,
                "filename": doc.filename,
                "chunk_count": len(chunks),
                "sha256": sha256_hex[:12],
            }

    def ingest_builtin_policies(self, kb_id: int) -> int:
        """Index telecom_policies.json into the specified KB if not already indexed."""
        policies_path = settings.data_dir / "telecom_policies.json"
        policies = json.loads(policies_path.read_text(encoding="utf-8"))
        existing = {d["filename"] for d in self.list_documents(kb_id)}
        ingested = 0
        for pol in policies:
            fname = f"{pol['policy_id']}_{pol['category'].replace(' ', '_')}.txt"
            if fname in existing:
                continue
            body = f"Policy ID: {pol['policy_id']}\nTitle: {pol['title']}\nCategory: {pol['category']}\n\n{pol['content']}"
            self.ingest_document(kb_id, fname, body.encode("utf-8"))
            ingested += 1
        return ingested

    def retrieve(self, kb_id: int, query: str, top_k: int = 4) -> List[Dict[str, Any]]:
        with get_db() as db:
            kb = db.query(KnowledgeBase).filter(KnowledgeBase.id == kb_id).first()
            if not kb:
                raise ValueError(f"KnowledgeBase id={kb_id} not found.")
            collection = self._client.get_or_create_collection(
                name=kb.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            count = collection.count()
            if count == 0:
                return []

            q_emb = self._embed_texts([query], backend=kb.embedding_backend)[0]
            res = collection.query(query_embeddings=[q_emb], n_results=min(top_k, count))
            docs = (res.get("documents") or [[]])[0]
            metas = (res.get("metadatas") or [[]])[0]
            ids = (res.get("ids") or [[]])[0]
            dists = (res.get("distances") or [[]])[0]

            retrieved: List[Dict[str, Any]] = []
            for rank, (cid, text, meta, dist) in enumerate(zip(ids, docs, metas, dists), start=1):
                sim = round(max(0.0, 1.0 - float(dist)), 4)
                doc_id = meta.get("doc_id")
                src_name = meta.get("filename", "unknown")
                retrieved.append(
                    {
                        "rank": rank,
                        "chunk_id": cid,
                        "document_id": doc_id,
                        "source_filename": src_name,
                        "text": text,
                        "similarity_score": sim,
                    }
                )
                db.add(
                    RetrievedChunk(
                        knowledge_base_id=kb.id,
                        document_id=doc_id,
                        query_text=query,
                        chunk_id=cid,
                        source_filename=src_name,
                        chunk_text=text,
                        similarity_score=sim,
                        rank_position=rank,
                    )
                )
            return retrieved

    @staticmethod
    def compute_retrieval_metrics(
        retrieved_chunks: List[Dict[str, Any]],
        relevant_keywords_or_filenames: List[str],
        k: int | None = None,
    ) -> Dict[str, float]:
        """Compute Precision@K, Recall@K, and Mean Reciprocal Rank (MRR) using labeled relevance judgments."""
        if not retrieved_chunks or not relevant_keywords_or_filenames:
            return {"precision_at_k": 0.0, "recall_at_k": 0.0, "mrr": 0.0}

        top_chunks = retrieved_chunks[: (k or len(retrieved_chunks))]
        labels = [lbl.strip().lower() for lbl in relevant_keywords_or_filenames if lbl.strip()]
        if not labels:
            return {"precision_at_k": 0.0, "recall_at_k": 0.0, "mrr": 0.0}

        rel_flags: List[bool] = []
        matched_labels: set[str] = set()
        for ch in top_chunks:
            haystack = f"{ch['source_filename']} {ch['text']}".lower()
            is_rel = False
            for lbl in labels:
                if lbl in haystack:
                    is_rel = True
                    matched_labels.add(lbl)
            rel_flags.append(is_rel)

        precision_at_k = round(sum(1 for f in rel_flags if f) / len(top_chunks), 4)
        recall_at_k = round(len(matched_labels) / len(labels), 4)
        mrr = 0.0
        for idx, flag in enumerate(rel_flags, start=1):
            if flag:
                mrr = round(1.0 / idx, 4)
                break
        return {"precision_at_k": precision_at_k, "recall_at_k": recall_at_k, "mrr": mrr}

    def ask_and_evaluate(
        self,
        kb_id: int,
        query: str,
        top_k: int = 4,
        relevant_labels: List[str] | None = None,
        model_name: str | None = None,
    ) -> Dict[str, Any]:
        """Retrieve chunks, generate cited answer, and evaluate groundedness + retrieval metrics."""
        chunks = self.retrieve(kb_id, query, top_k=top_k)
        if not chunks:
            return {
                "query": query,
                "answer": "Knowledge base is empty. Upload documents or index built-in telecom policies first.",
                "chunks": [],
                "metrics": {"precision_at_k": 0.0, "recall_at_k": 0.0, "mrr": 0.0, "context_relevance": 0.0, "groundedness": 0.0},
                "unsupported_claims": [],
                "missing_citations": [],
                "explanation": "No indexed chunks found.",
                "execution_mode": "empty",
            }

        context_block = "\n\n".join(
            f"[{c['source_filename']} | {c['chunk_id']} | sim={c['similarity_score']}]\n{c['text']}"
            for c in chunks
        )

        execution_mode = "local_synthetic"
        if self.llm.is_configured():
            ans_res = self.llm.generate_text(
                prompt=(
                    f"Retrieved Context:\n{context_block}\n\n"
                    f"Question: {query}\n\n"
                    "Answer strictly using ONLY the Retrieved Context. Cite sources inline as [filename]."
                ),
                system_instruction="You are a strictly grounded telecom compliance assistant. Never invent claims outside context.",
                model_name=model_name,
                metadata={"component": "rag_qa"},
            )
            if ans_res.success and ans_res.text:
                answer = ans_res.text
                execution_mode = "gemini"
            else:
                answer = self._extractive_cited_answer(chunks)
        else:
            answer = self._extractive_cited_answer(chunks)

        # Evaluate groundedness
        unsupported_claims: List[str] = []
        missing_citations: List[str] = []
        context_relevance = round(sum(c["similarity_score"] for c in chunks) / len(chunks), 4)
        groundedness_score = self._heuristic_groundedness(answer, chunks, unsupported_claims, missing_citations)
        explanation = "Deterministic lexical groundedness & citation check completed."

        if self.llm.is_configured():
            judge_res = self.llm.generate_structured(
                prompt=(
                    f"Question: {query}\n"
                    f"Retrieved Context:\n{context_block}\n\n"
                    f"Generated Answer:\n{answer}\n\n"
                    "Audit whether every factual claim is supported by Retrieved Context and properly cited."
                ),
                schema_model=RagGroundednessSchema,
                system_instruction="You are a RAG groundedness & hallucination detector.",
                model_name=model_name,
                metadata={"component": "rag_groundedness"},
            )
            if judge_res.success and judge_res.parsed is not None:
                parsed: RagGroundednessSchema = judge_res.parsed
                groundedness_score = round(parsed.groundedness_score, 4)
                context_relevance = round(parsed.context_relevance, 4)
                unsupported_claims = parsed.unsupported_claims
                missing_citations = parsed.missing_citations
                explanation = parsed.explanation

        ir_metrics = self.compute_retrieval_metrics(chunks, relevant_labels or [], k=top_k)
        return {
            "query": query,
            "answer": answer,
            "chunks": chunks,
            "metrics": {
                **ir_metrics,
                "context_relevance": context_relevance,
                "groundedness": groundedness_score,
            },
            "unsupported_claims": unsupported_claims,
            "missing_citations": missing_citations,
            "explanation": explanation,
            "execution_mode": execution_mode,
        }

    @staticmethod
    def _extractive_cited_answer(chunks: List[Dict[str, Any]]) -> str:
        top = chunks[:2]
        snippets = [f"{c['text']} [{c['source_filename']}]" for c in top]
        return " ".join(snippets)

    @staticmethod
    def _heuristic_groundedness(
        answer: str,
        chunks: List[Dict[str, Any]],
        unsupported_claims: List[str],
        missing_citations: List[str],
    ) -> float:
        context_tokens = set(re.findall(r"[a-z0-9]{3,}", " ".join(c["text"] for c in chunks).lower()))
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", answer) if len(s.strip()) > 15]
        if not sentences:
            return 1.0 if answer.strip() else 0.0
        supported = 0
        for sent in sentences:
            sent_tokens = set(re.findall(r"[a-z0-9]{3,}", sent.lower()))
            overlap = len(sent_tokens & context_tokens) / max(len(sent_tokens), 1)
            if overlap >= 0.35:
                supported += 1
            else:
                unsupported_claims.append(sent)
            if "[" not in sent and not any(c["source_filename"].split(".")[0].lower() in sent.lower() for c in chunks):
                missing_citations.append(sent)
        return round(supported / len(sentences), 4)


rag_engine = RAGEngine()
