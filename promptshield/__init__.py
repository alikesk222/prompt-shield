"""
prompt-shield — Real-time prompt injection detection and prevention library.

Quick start:
    from promptshield import Shield, detect, is_safe

    # One-liner check
    if not is_safe(user_input):
        return "I cannot process that request."

    # Detailed result
    result = detect(user_input)
    print(result.score, result.threat_level, result.categories)

    # Full Shield instance (reusable, configurable)
    shield = Shield(threshold=0.5, strict=False)
    result = shield.scan(user_input)

    # Sanitize + scan
    clean, result = shield.sanitize_and_scan(user_input)

    # Decorator
    @shield.wrap
    def chat(message: str) -> str:
        return call_llm(message)
"""

__version__ = "1.0.0"

from .detector import Detector, DetectionResult, MatchedRule
from .middleware import Shield, InjectionDetected
from .sanitizer import sanitize

# Module-level convenience functions using a default Shield instance
_default_shield = Shield(threshold=0.5, log=True)


def detect(text: str) -> DetectionResult:
    """
    Scan text for prompt injection using default settings.

    Returns DetectionResult (is_injection, score, threat_level, matched_rules).
    """
    return _default_shield.scan(text)


def is_safe(text: str) -> bool:
    """
    Returns True if text does NOT appear to be a prompt injection attempt.

    Usage:
        if not is_safe(user_input):
            return error_response()
    """
    return _default_shield.is_safe(text)


def scan(text: str) -> DetectionResult:
    """Alias for detect()."""
    return detect(text)


__all__ = [
    "Shield",
    "Detector",
    "DetectionResult",
    "MatchedRule",
    "InjectionDetected",
    "sanitize",
    "detect",
    "scan",
    "is_safe",
    "__version__",
]
