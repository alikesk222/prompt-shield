"""
Input sanitizer — strips/normalizes dangerous characters from user input
before it reaches the LLM. Use alongside detection, not as a replacement.
"""

import re
import unicodedata


# Zero-width and invisible characters (often used for smuggling)
_INVISIBLE = re.compile(
    r"[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u00ad\u034f\u17b4\u17b5\u180b-\u180d\ufe00-\ufe0f]"
)

# Control characters (except newline \n, carriage return \r, tab \t)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# LLM conversation delimiter tags that should never appear in user input
_DELIMITERS = re.compile(
    r"\[/?INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>"
    r"|</?system>|</?prompt>|</?instructions?>",
    re.IGNORECASE,
)

# Excessive whitespace: more than 2 consecutive newlines
_EXCESS_NEWLINES = re.compile(r"\n{3,}")


def strip_invisible(text: str) -> str:
    """Remove zero-width and invisible Unicode characters."""
    return _INVISIBLE.sub("", text)


def strip_control_chars(text: str) -> str:
    """Remove ASCII control characters (preserves \\n, \\r, \\t)."""
    return _CONTROL.sub("", text)


def strip_delimiters(text: str) -> str:
    """Remove known LLM conversation delimiter tags from user input."""
    return _DELIMITERS.sub("", text)


def normalize_unicode(text: str, form: str = "NFC") -> str:
    """Unicode normalization (NFC by default). Collapses lookalike variations."""
    return unicodedata.normalize(form, text)


def collapse_whitespace(text: str) -> str:
    """Collapse 3+ consecutive newlines to 2."""
    return _EXCESS_NEWLINES.sub("\n\n", text)


def truncate(text: str, max_length: int) -> str:
    """Hard truncate to max_length characters."""
    if len(text) <= max_length:
        return text
    return text[:max_length]


def sanitize(
    text: str,
    *,
    remove_invisible: bool = True,
    remove_control: bool = True,
    remove_delimiters: bool = True,
    normalize: bool = True,
    collapse_newlines: bool = True,
    max_length: int = 0,
) -> str:
    """
    Apply all sanitization steps to user input.

    Args:
        text                Input string to sanitize
        remove_invisible    Strip zero-width/invisible chars (default True)
        remove_control      Strip ASCII control chars (default True)
        remove_delimiters   Strip LLM delimiter tags (default True)
        normalize           Unicode NFC normalization (default True)
        collapse_newlines   Collapse 3+ newlines to 2 (default True)
        max_length          If > 0, truncate to this many characters (default 0 = no limit)

    Returns:
        Sanitized string
    """
    if normalize:
        text = normalize_unicode(text)
    if remove_invisible:
        text = strip_invisible(text)
    if remove_control:
        text = strip_control_chars(text)
    if remove_delimiters:
        text = strip_delimiters(text)
    if collapse_newlines:
        text = collapse_whitespace(text)
    if max_length > 0:
        text = truncate(text, max_length)
    return text
