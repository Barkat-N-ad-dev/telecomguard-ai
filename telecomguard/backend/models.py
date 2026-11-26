"""SQLAlchemy ORM models for all 14 TelecomGuard AI tables."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base declarative class for TelecomGuard ORM models."""


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    display_name = Column(String(128), nullable=False)
    role = Column(String(32), nullable=False, default="analyst")  # admin, analyst, viewer, customer
    email = Column(String(128), nullable=True)
    password_hash = Column(String(256), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ModelConfiguration(Base):
    __tablename__ = "model_configurations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    provider = Column(String(32), nullable=False, default="gemini")
    model_id = Column(String(64), nullable=False, default="gemini-4-hydrogen")
    prompt_version = Column(String(32), nullable=False, default="v1.0")
    system_prompt = Column(Text, nullable=True)
    pass_threshold = Column(Float, nullable=False, default=0.75)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class EvaluationDataset(Base):
    __tablename__ = "evaluation_datasets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    source_type = Column(String(32), nullable=False, default="builtin")  # builtin, csv, json, custom
    created_by = Column(String(64), nullable=False, default="system")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    cases = relationship("EvaluationCase", back_populates="dataset", cascade="all, delete-orphan")
    runs = relationship("EvaluationRun", back_populates="dataset")


class EvaluationCase(Base):
    __tablename__ = "evaluation_cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dataset_id = Column(Integer, ForeignKey("evaluation_datasets.id", ondelete="CASCADE"), nullable=False)
    case_code = Column(String(64), nullable=False, index=True)
    category = Column(String(64), nullable=False)
    customer_id = Column(String(32), nullable=True)
    user_query = Column(Text, nullable=False)
    expected_answer = Column(Text, nullable=False)
    rubric = Column(Text, nullable=True)
    required_facts = Column(JSON, nullable=True)
    forbidden_patterns = Column(JSON, nullable=True)
    requires_escalation = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    dataset = relationship("EvaluationDataset", back_populates="cases")
    results = relationship("EvaluationResult", back_populates="case")


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_code = Column(String(64), unique=True, nullable=False, index=True)
    dataset_id = Column(Integer, ForeignKey("evaluation_datasets.id", ondelete="SET NULL"), nullable=True)
    model_name = Column(String(64), nullable=False)
    prompt_version = Column(String(32), nullable=False, default="v1.0")
    execution_mode = Column(String(32), nullable=False, default="gemini")  # gemini | local_synthetic
    pass_threshold = Column(Float, nullable=False, default=0.75)
    total_cases = Column(Integer, nullable=False, default=0)
    passed_cases = Column(Integer, nullable=False, default=0)
    pass_rate = Column(Float, nullable=False, default=0.0)
    avg_overall_score = Column(Float, nullable=False, default=0.0)
    dimension_averages = Column(JSON, nullable=True)
    total_tokens = Column(Integer, nullable=False, default=0)
    duration_ms = Column(Float, nullable=False, default=0.0)
    status = Column(String(32), nullable=False, default="completed")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    dataset = relationship("EvaluationDataset", back_populates="runs")
    results = relationship("EvaluationResult", back_populates="run", cascade="all, delete-orphan")


class EvaluationResult(Base):
    __tablename__ = "evaluation_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("evaluation_runs.id", ondelete="CASCADE"), nullable=False)
    case_id = Column(Integer, ForeignKey("evaluation_cases.id", ondelete="SET NULL"), nullable=True)
    case_code = Column(String(64), nullable=False)
    category = Column(String(64), nullable=False)
    user_query = Column(Text, nullable=False)
    expected_answer = Column(Text, nullable=False)
    actual_response = Column(Text, nullable=False)
    gemini_evaluation = Column(JSON, nullable=True)
    deterministic_checks = Column(JSON, nullable=True)
    dimension_scores = Column(JSON, nullable=False)
    overall_score = Column(Float, nullable=False)
    passed = Column(Boolean, nullable=False)
    explanation = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    human_review_status = Column(String(32), nullable=False, default="Pending")  # Pending, Approved, Overridden
    human_review_notes = Column(Text, nullable=True)
    latency_ms = Column(Float, nullable=False, default=0.0)
    tokens_used = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    run = relationship("EvaluationRun", back_populates="results")
    case = relationship("EvaluationCase", back_populates="results")


class RedTeamScenario(Base):
    __tablename__ = "redteam_scenarios"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scenario_code = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(160), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="High")
    attack_prompt = Column(Text, nullable=False)
    target_customer_id = Column(String(32), nullable=True)
    expected_defense = Column(Text, nullable=False)
    forbidden_outcomes = Column(JSON, nullable=True)
    is_custom = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class RedTeamRun(Base):
    __tablename__ = "redteam_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_code = Column(String(64), unique=True, nullable=False, index=True)
    scenario_id = Column(Integer, ForeignKey("redteam_scenarios.id", ondelete="SET NULL"), nullable=True)
    scenario_code = Column(String(64), nullable=False)
    category = Column(String(64), nullable=False)
    target_name = Column(String(64), nullable=False, default="TelecomSupportSimulator")
    model_name = Column(String(64), nullable=False)
    attack_prompt = Column(Text, nullable=False)
    target_response = Column(Text, nullable=False)
    resisted = Column(Boolean, nullable=False)
    severity = Column(String(16), nullable=False)
    vulnerability_summary = Column(Text, nullable=True)
    remediation_recommendation = Column(Text, nullable=True)
    analysis_metadata = Column(JSON, nullable=True)
    execution_mode = Column(String(32), nullable=False, default="gemini")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_code = Column(String(64), unique=True, nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False, index=True)  # Critical, High, Medium, Low
    evidence = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=False)
    recommended_fix = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="Open")  # Open, In Progress, Fixed, Retested, Accepted Risk
    assigned_owner = Column(String(64), nullable=False, default="AI Security Team")
    retest_result = Column(String(64), nullable=True)
    source_run_code = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class KnowledgeBase(Base):
    __tablename__ = "knowledge_bases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    collection_name = Column(String(128), unique=True, nullable=False)
    embedding_backend = Column(String(64), nullable=False, default="local-minilm")
    chunk_size = Column(Integer, nullable=False, default=500)
    chunk_overlap = Column(Integer, nullable=False, default=80)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    documents = relationship("Document", back_populates="knowledge_base", cascade="all, delete-orphan")


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    knowledge_base_id = Column(Integer, ForeignKey("knowledge_bases.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(256), nullable=False)
    file_type = Column(String(16), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    chunk_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    knowledge_base = relationship("KnowledgeBase", back_populates="documents")
    chunks = relationship("RetrievedChunk", back_populates="document")


class RetrievedChunk(Base):
    __tablename__ = "retrieved_chunks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    knowledge_base_id = Column(Integer, ForeignKey("knowledge_bases.id", ondelete="CASCADE"), nullable=False)
    document_id = Column(Integer, ForeignKey("documents.id", ondelete="SET NULL"), nullable=True)
    query_text = Column(Text, nullable=False)
    chunk_id = Column(String(128), nullable=False)
    source_filename = Column(String(256), nullable=False)
    chunk_text = Column(Text, nullable=False)
    similarity_score = Column(Float, nullable=False)
    rank_position = Column(Integer, nullable=False)
    is_relevant_label = Column(Boolean, nullable=True)
    groundedness_score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    document = relationship("Document", back_populates="chunks")


class RegressionRun(Base):
    __tablename__ = "regression_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    regression_code = Column(String(64), unique=True, nullable=False, index=True)
    baseline_run_code = Column(String(64), nullable=False)
    candidate_run_code = Column(String(64), nullable=False)
    baseline_model = Column(String(64), nullable=False)
    candidate_model = Column(String(64), nullable=False)
    baseline_prompt_version = Column(String(32), nullable=False)
    candidate_prompt_version = Column(String(32), nullable=False)
    min_acceptance_threshold = Column(Float, nullable=False, default=0.75)
    score_delta = Column(Float, nullable=False)
    pass_rate_delta = Column(Float, nullable=False)
    newly_failed_cases = Column(JSON, nullable=True)
    newly_introduced_vulnerabilities = Column(Integer, nullable=False, default=0)
    regression_detected = Column(Boolean, nullable=False, default=False)
    summary = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor = Column(String(64), nullable=False)
    role = Column(String(32), nullable=False)
    action = Column(String(128), nullable=False, index=True)
    resource = Column(String(128), nullable=True)
    decision = Column(String(32), nullable=False)  # ALLOWED, BLOCKED, ERROR, INFO
    reason = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
