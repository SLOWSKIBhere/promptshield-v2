from __future__ import annotations  # BUG-06 FIX: lowercase tuple[] works on Python 3.8+

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXTRACTION = "data_extraction"
    JAILBREAK = "jailbreak"
    ROLE_CONFUSION = "role_confusion"
    MULTI_TURN = "multi_turn"


def _default_categories() -> List[AttackCategory]:
    """BUG-16 FIX: factory prevents shared mutable default across instances."""
    return list(AttackCategory)


class ScanTarget(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    # BUG-17 FIX: length constraints on all free-text inputs
    system_prompt: str = Field(..., min_length=10, max_length=50_000)
    endpoint_url: Optional[str] = Field(None, max_length=500)
    api_key: Optional[str] = Field(None, max_length=500)
    model_name: Optional[str] = Field(None, max_length=100)
    feature_description: str = Field(..., min_length=5, max_length=1_000)
    scan_name: str = Field(..., min_length=3, max_length=200)
    categories: List[AttackCategory] = Field(
        default_factory=_default_categories,
        max_length=len(AttackCategory),
    )

    @field_validator("categories")
    @classmethod
    def categories_must_be_unique_and_nonempty(
        cls, value: List[AttackCategory]
    ) -> List[AttackCategory]:
        if not value:
            raise ValueError("Select at least one attack category")
        if len(set(value)) != len(value):
            raise ValueError("Attack categories must not contain duplicates")
        return value


class AttackPrompt(BaseModel):
    id: str
    category: str
    name: str
    description: str
    payload: str
    severity: RiskLevel
    owasp_ref: str
    expected_safe_behavior: str


class AttackResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    attack_id: str
    attack_name: str
    category: str
    severity: RiskLevel
    owasp_ref: str
    payload: str
    model_response: str
    is_exploited: bool
    confidence: float
    judge_reasoning: str
    remediation: str


class ScanResult(BaseModel):
    scan_id: str
    scan_name: str
    feature_description: str
    system_prompt_preview: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: ScanStatus
    total_attacks: int = 0
    exploited_count: int = 0
    overall_score: float = 100.0
    letter_grade: str = "A+"
    findings: List[AttackResult] = Field(default_factory=list)
    summary: Optional[str] = None
    current_attack_index: int = 0
    current_attack_name: Optional[str] = None
    failure_reason: Optional[str] = None


class ScanSummary(BaseModel):
    scan_id: str
    scan_name: str
    letter_grade: str
    overall_score: float
    total_attacks: int
    exploited_count: int
    critical_count: int
    high_count: int
    medium_count: int
    started_at: datetime
    completed_at: Optional[datetime]
    status: ScanStatus


class ScanProgress(BaseModel):
    scan_id: str
    status: ScanStatus
    current: int
    total: int
    current_attack: str
    failure_reason: Optional[str] = None
