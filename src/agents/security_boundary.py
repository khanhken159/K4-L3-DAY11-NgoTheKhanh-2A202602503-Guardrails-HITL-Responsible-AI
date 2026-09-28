"""Reference security boundary for the Day 11 Guards Agent.

This is deliberately framework-independent so students can inspect the policy
and reason about the difference between untrusted content and an authorised
action. It is not a solution for the TODOs in ``src/assignment``.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlparse


TRUSTED_EGRESS_HOSTS = frozenset({
    "api.vinbank.example",
    "cases.vinbank.example",
    "api.vinbank.vn",
})
HIGH_RISK_ACTIONS = frozenset({
    "transfer_money", "close_account", "change_password",
    "delete_data", "update_personal_info",
})
ZERO_WIDTH = "\u200b\u200c\u200d\ufeff\u2060"
SECRET_PATTERNS = (
    r"\badmin123\b",
    r"sk-[a-z0-9-]{8,}",
    r"db\.vinbank\.internal(?::\d+)?",
    r"(?:password|mật\s*khẩu)\s*[:=]\s*\S+",
)
INSTRUCTION_OVERRIDE_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:previous|above|prior)?\s*instructions?",
    r"(?:system|developer)\s+(?:prompt|instruction)|system\s+override",
    r"(?:reveal|disclose|translate|encode|summarize)\b.*(?:secret|password|credential|api\s*key|internal)",
    r"bỏ\s+qua\s+(?:mọi\s+)?hướng\s+dẫn|tiết\s+lộ\s+(?:mật\s*khẩu|api|thông\s*tin\s*nội\s*bộ)",
)


@dataclass(frozen=True)
class ExternalContent:
    """Data retrieved from email/RAG/web; never an instruction authority."""

    source: str
    text: str
    trusted: bool = False


@dataclass(frozen=True)
class ActionRequest:
    """A proposed side effect awaiting deterministic policy and human approval."""

    action: str
    destination: str
    payload: str
    approval_id: str | None = None
    reviewer_id: str | None = None


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    reason: str
    requires_human: bool


def normalize_for_security(text: str) -> str:
    """Canonicalize Unicode and remove invisible separators before policy checks."""
    normalized = unicodedata.normalize("NFKC", text or "")
    return normalized.translate(str.maketrans("", "", ZERO_WIDTH))


def contains_secret(text: str) -> bool:
    """Detect a synthetic lab secret even when punctuation/spacing is altered."""
    normalized = re.sub(r"[^a-z0-9]", "", normalize_for_security(text).casefold())
    secrets = ("admin123", "skvinbanksecret2024", "dbvinbankinternal")
    return any(secret in normalized for secret in secrets) or any(
        re.search(pattern, normalize_for_security(text), re.IGNORECASE)
        for pattern in SECRET_PATTERNS
    )


def contains_instruction_override(text: str) -> bool:
    """Identify instruction-like text after Unicode normalization."""
    normalized = normalize_for_security(text)
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in INSTRUCTION_OVERRIDE_PATTERNS)


def assess_external_content(content: ExternalContent) -> ActionDecision:
    """Treat third-party content as data and reject attempts to change policy."""
    if content.trusted:
        return ActionDecision(True, "trusted source metadata", False)
    if contains_instruction_override(content.text):
        return ActionDecision(False, "untrusted content contains an instruction override", False)
    return ActionDecision(True, "untrusted content is data only", False)


def authorize_action(request: ActionRequest) -> ActionDecision:
    """Enforce exact destination allowlist, secret egress block and HITL for risk."""
    destination = urlparse(request.destination)
    if destination.scheme != "https" or destination.hostname not in TRUSTED_EGRESS_HOSTS:
        return ActionDecision(False, "destination is not allowlisted", False)
    if contains_secret(request.payload):
        return ActionDecision(False, "payload contains protected data", False)
    if request.action in HIGH_RISK_ACTIONS:
        approved = bool(
            request.reviewer_id
            and request.approval_id
            and re.fullmatch(r"HITL-[A-Z0-9]{8}", request.approval_id)
        )
        if not approved:
            return ActionDecision(False, "high-risk action needs recorded human approval", True)
    return ActionDecision(True, "least-privilege policy permits this action", False)
