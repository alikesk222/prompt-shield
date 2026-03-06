"""
Core detection engine.
Combines rule-based pattern matching with heuristic anomaly scoring.
"""

import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from .patterns import PATTERNS, Pattern


# ── Result types ─────────────────────────────────────────────────────────────

@dataclass
class MatchedRule:
    name: str
    category: str
    weight: float
    description: str
    matched_text: str


@dataclass
class DetectionResult:
    """
    Result returned by Shield.detect() and shield() / detect() functions.

    Attributes:
        is_injection   True if the input is classified as a prompt injection attempt
        score          Float 0.0-1.0 representing threat level
        threat_level   'none' | 'low' | 'medium' | 'high' | 'critical'
        matched_rules  List of pattern rules that fired
        heuristic_score Heuristic/anomaly component of the score
        input_length   Length of the analyzed input
        sanitized      Sanitized version of the input (if sanitize=True was used)
    """
    is_injection: bool
    score: float
    threat_level: str
    matched_rules: list[MatchedRule] = field(default_factory=list)
    heuristic_score: float = 0.0
    input_length: int = 0
    sanitized: Optional[str] = None

    @property
    def categories(self) -> list[str]:
        return list({r.category for r in self.matched_rules})

    def __bool__(self) -> bool:
        """Allows: `if shield.detect(text): block()`"""
        return self.is_injection


# ── Heuristic scorers ─────────────────────────────────────────────────────────

def _instruction_density(text: str) -> float:
    """Score based on density of imperative verbs and command words."""
    commands = re.findall(
        r"\b(ignore|forget|disregard|override|bypass|pretend|act|roleplay|repeat|print|reveal|"
        r"show|tell|execute|run|perform|do|say|write|output|display|provide|give|list|explain)\b",
        text, re.IGNORECASE,
    )
    words = max(len(text.split()), 1)
    density = len(commands) / words
    return min(density * 5, 1.0)  # normalize: 0.2 cmd/word = score 1.0


def _delimiter_density(text: str) -> float:
    """Score based on suspicious delimiter patterns."""
    delimiters = re.findall(r"(#{3,}|={3,}|-{3,}|_{3,}|\*{3,}|<[a-z]+>|</[a-z]+>|\[/?[A-Z]+\])", text)
    return min(len(delimiters) * 0.15, 1.0)


def _special_char_ratio(text: str) -> float:
    """Score based on unusual ratio of special/control characters."""
    if not text:
        return 0.0
    special = sum(1 for c in text if unicodedata.category(c) in ("Cf", "Cc", "Co") or ord(c) < 32)
    return min(special / len(text) * 20, 1.0)


def _entropy(text: str) -> float:
    """Shannon entropy of the text — high entropy may indicate encoding."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    h = -sum((f / n) * math.log2(f / n) for f in freq.values())
    # Typical English text: ~4.0 bits/char; base64: ~6.0; random: ~8.0
    normalized = max(0.0, (h - 4.5) / 3.5)  # 0 at 4.5, 1 at 8.0
    return min(normalized, 1.0)


def _length_penalty(text: str) -> float:
    """Very long inputs get a small additional score."""
    return min(max(0.0, len(text) - 500) / 5000, 0.3)


def _compute_heuristic(text: str) -> float:
    scores = [
        _instruction_density(text) * 0.35,
        _delimiter_density(text) * 0.25,
        _special_char_ratio(text) * 0.20,
        _entropy(text) * 0.10,
        _length_penalty(text) * 0.10,
    ]
    return min(sum(scores), 1.0)


# ── Threat level mapping ──────────────────────────────────────────────────────

def _threat_level(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.40:
        return "medium"
    if score >= 0.20:
        return "low"
    return "none"


# ── Detector ─────────────────────────────────────────────────────────────────

class Detector:
    """
    Core detection engine. Instantiate once and reuse.
    Thread-safe (stateless per call).
    """

    def __init__(
        self,
        threshold: float = 0.5,
        heuristic_weight: float = 0.3,
        pattern_weight: float = 0.7,
        disabled_categories: Optional[list[str]] = None,
        custom_patterns: Optional[list[Pattern]] = None,
    ):
        """
        Args:
            threshold           Score at/above which is_injection=True (default 0.5)
            heuristic_weight    Weight of anomaly/heuristic score (default 0.3)
            pattern_weight      Weight of pattern-match score (default 0.7)
            disabled_categories Categories to skip during detection
            custom_patterns     Additional Pattern objects to include
        """
        if abs(heuristic_weight + pattern_weight - 1.0) > 0.01:
            raise ValueError("heuristic_weight + pattern_weight must equal 1.0")

        self.threshold = threshold
        self.heuristic_weight = heuristic_weight
        self.pattern_weight = pattern_weight
        self.disabled_categories = set(disabled_categories or [])

        self._patterns = [
            p for p in PATTERNS if p.category not in self.disabled_categories
        ]
        if custom_patterns:
            self._patterns.extend(custom_patterns)

    def detect(self, text: str) -> DetectionResult:
        """
        Analyze `text` for prompt injection signals.

        Returns a DetectionResult. The result is truthy if is_injection=True,
        allowing: `if detector.detect(user_input): raise InjectionError()`
        """
        if not text or not text.strip():
            return DetectionResult(
                is_injection=False, score=0.0, threat_level="none",
                input_length=len(text),
            )

        matched_rules: list[MatchedRule] = []
        pattern_score = 0.0

        for pattern in self._patterns:
            m = pattern.regex.search(text)
            if m:
                matched_text = m.group(0)[:120]
                matched_rules.append(MatchedRule(
                    name=pattern.name,
                    category=pattern.category,
                    weight=pattern.weight,
                    description=pattern.description,
                    matched_text=matched_text,
                ))
                # Combine scores: take max within a category, accumulate across categories
                pattern_score = max(pattern_score, pattern.weight)

        # Aggregate pattern score across multiple matches
        if matched_rules:
            weights = sorted([r.weight for r in matched_rules], reverse=True)
            # Diminishing returns: each extra hit adds less
            combined = weights[0]
            for w in weights[1:]:
                combined = combined + w * (1.0 - combined) * 0.4
            pattern_score = min(combined, 1.0)

        heuristic_score = _compute_heuristic(text)

        final_score = (
            pattern_score * self.pattern_weight
            + heuristic_score * self.heuristic_weight
        )
        final_score = min(final_score, 1.0)

        return DetectionResult(
            is_injection=final_score >= self.threshold,
            score=round(final_score, 4),
            threat_level=_threat_level(final_score),
            matched_rules=matched_rules,
            heuristic_score=round(heuristic_score, 4),
            input_length=len(text),
        )

    def is_safe(self, text: str) -> bool:
        """Returns True if the input is NOT an injection attempt."""
        return not self.detect(text).is_injection
