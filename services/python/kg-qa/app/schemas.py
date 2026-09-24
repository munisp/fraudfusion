"""Pydantic schemas for the kg-qa API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    question: str = Field(min_length=3)
    max_hops: int = Field(default=3, ge=1, le=5)
    max_paths: int = Field(default=5, ge=1, le=25)


class Hop(BaseModel):
    src: str
    dst: str
    type: str
    ts: str | None = None
    count: int = 1


class ScoredPath(BaseModel):
    score: float
    hops: list[Hop]
    text: str


class Citation(BaseModel):
    entity_id: str
    label: str
    role: str = "path-node"


class AskResponse(BaseModel):
    question: str
    answer: str
    llm_used: bool
    llm_model: str | None = None
    store_mode: str
    linked_entities: list[Citation]
    citations: list[Citation]
    paths: list[ScoredPath]


class RefreshRequest(BaseModel):
    full_rebuild: bool = False


class RefreshResponse(BaseModel):
    status: str
    stats: dict
