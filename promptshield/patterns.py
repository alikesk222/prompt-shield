"""
Regex pattern library for prompt injection detection.
Patterns are organized by attack category with associated severity weights.
"""

import re
from dataclasses import dataclass


@dataclass
class Pattern:
    name: str
    regex: re.Pattern
    category: str
    weight: float  # 0.0 - 1.0 contribution to threat score
    description: str


def _c(pattern: str, flags: int = re.IGNORECASE | re.DOTALL) -> re.Pattern:
    return re.compile(pattern, flags)


PATTERNS: list[Pattern] = [
    # ── Direct Override ─────────────────────────────────────────────────────
    Pattern("ignore_instructions", _c(
        r"ignore\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|context|rules?|constraints?|directives?)"
    ), "direct_override", 0.9,
        "Classic 'ignore previous instructions' injection"),

    Pattern("forget_instructions", _c(
        r"forget\s+(everything|all|your|the|any)\s*(previous|prior|above|earlier|instructions?|prompts?|rules?|training)?"
    ), "direct_override", 0.85,
        "Instruction reset attempt"),

    Pattern("disregard_instructions", _c(
        r"(disregard|override|bypass|circumvent|overwrite)\s+(all\s+)?(previous|prior|your|the|any)\s*(instructions?|rules?|guidelines?|constraints?)"
    ), "direct_override", 0.85,
        "Instruction disregard attempt"),

    Pattern("new_instructions", _c(
        r"(new|updated?|revised?|actual|real|true)\s+instructions?\s*(follow|are|below|:)"
    ), "direct_override", 0.75,
        "New instructions injection"),

    Pattern("end_of_prompt", _c(
        r"(end\s+of\s+(prompt|system|instructions?|context)|---+\s*end\s*---+|\[END\s+SYSTEM\])"
    ), "direct_override", 0.7,
        "False end-of-prompt delimiter"),

    Pattern("priority_override", _c(
        r"(highest|top|absolute|maximum|critical)\s+priority\s*(instruction|directive|command|order)"
    ), "direct_override", 0.7,
        "Priority escalation injection"),

    # ── Role Confusion ───────────────────────────────────────────────────────
    Pattern("you_are_now", _c(
        r"you\s+are\s+now\s+(a|an|the|no\s+longer)?\s*\w"
    ), "role_confusion", 0.75,
        "Role reassignment attempt"),

    Pattern("act_as", _c(
        r"(act|behave|pretend|roleplay|play)\s+(as|like)\s+(a|an|the)?\s*\w"
    ), "role_confusion", 0.65,
        "Role persona injection"),

    Pattern("dan_jailbreak", _c(
        r"\bDAN\b|do\s+anything\s+now|jailbreak(ed|ing)?\b|unrestricted\s+(AI|mode|version)"
    ), "role_confusion", 0.95,
        "DAN jailbreak pattern"),

    Pattern("evil_mode", _c(
        r"(evil|dark|unrestricted|unfiltered|uncensored|dev(eloper)?)\s+(mode|version|persona|twin|AI)"
    ), "role_confusion", 0.85,
        "Evil/developer mode injection"),

    Pattern("no_restrictions", _c(
        r"(without|no|without\s+any)\s+(restrictions?|limitations?|filters?|guidelines?|rules?|ethics?|morals?)"
    ), "role_confusion", 0.7,
        "Restriction removal request"),

    Pattern("grandma_exploit", _c(
        r"(my\s+(grand(ma|pa|mother|father)|deceased|dead)|(bedtime\s+story|childhood\s+memory).*\bused\s+to\b)"
    ), "role_confusion", 0.6,
        "Grandma/emotional context exploit"),

    # ── Prompt Extraction ────────────────────────────────────────────────────
    Pattern("repeat_system_prompt", _c(
        r"(repeat|print|output|show|reveal|tell\s+me|display|write\s+out)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|original\s+prompt|prompt\s+above)"
    ), "prompt_extraction", 0.9,
        "System prompt extraction attempt"),

    Pattern("what_were_instructions", _c(
        r"what\s+(were|are)\s+(your|the)\s+(instructions?|system\s+prompt|initial\s+(instructions?|prompt)|rules?|guidelines?)"
    ), "prompt_extraction", 0.85,
        "Instruction inquiry extraction"),

    Pattern("start_with", _c(
        r"(start|begin|respond)\s+with\s+(\"|\')?(your\s+)?(first|opening|initial|exact)\s*(words?|sentence|instruction|line)"
    ), "prompt_extraction", 0.8,
        "First-words extraction technique"),

    Pattern("base64_leak", _c(
        r"(encode|output|print|show)\s+(your\s+)?(system\s+prompt|instructions?)\s+(in\s+)?(base64|hex|binary|rot13)"
    ), "prompt_extraction", 0.85,
        "Encoded prompt extraction"),

    # ── Delimiter Injection ──────────────────────────────────────────────────
    Pattern("human_assistant_tags", _c(
        r"(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|\[SYSTEM\]|\[/SYSTEM\]|<\|system\|>|<\|user\|>|<\|assistant\|>)"
    ), "delimiter_injection", 0.9,
        "LLM conversation delimiter injection"),

    Pattern("system_tag_injection", _c(
        r"(<system>|</system>|<prompt>|</prompt>|<instructions?>|</instructions?>|\{system\}|\{prompt\})"
    ), "delimiter_injection", 0.8,
        "System/prompt XML tag injection"),

    Pattern("triple_delimiter", _c(
        r"(###\s*(system|instruction|prompt|human|assistant)|---\s*(system|instruction|new\s+prompt)|===\s*(system|instruction))"
    ), "delimiter_injection", 0.75,
        "Triple-delimiter section injection"),

    Pattern("json_injection", _c(
        r"\{\s*\"role\"\s*:\s*\"(system|user|assistant)\"\s*,\s*\"content\"\s*:"
    ), "delimiter_injection", 0.85,
        "JSON message format injection"),

    # ── Encoding / Obfuscation ───────────────────────────────────────────────
    Pattern("base64_instruction", _c(
        r"(decode|execute|run|follow)\s+(the\s+)?(following\s+)?(base64|encoded)\s*(instruction|command|prompt|message)"
    ), "encoding", 0.85,
        "Base64-encoded instruction execution"),

    Pattern("zero_width_chars", _c(
        r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]"
    ), "encoding", 0.7,
        "Zero-width / invisible characters"),

    Pattern("unicode_lookalikes", _c(
        r"[\u0430\u0435\u043e\u0440\u0441\u0445\u0440\u04cf\u0456].*\b(ignore|system|prompt|instruction)\b"
        r"|"
        r"\b(ignore|system|prompt|instruction)\b.*[\u0430\u0435\u043e\u0440\u0441\u0445\u0440\u04cf\u0456]"
    ), "encoding", 0.75,
        "Cyrillic lookalike character substitution"),

    # ── Indirect Injection ───────────────────────────────────────────────────
    Pattern("web_injection_marker", _c(
        r"(<!-- .*injection|injection.*payload|<script>.*prompt|prompt\s+injection\s+payload)"
    ), "indirect_injection", 0.9,
        "Web content injection marker"),

    Pattern("hidden_instruction_comment", _c(
        r"(<!--|/\*|#)\s*(ignore|system\s+prompt|new\s+instruction|you\s+are)"
    ), "indirect_injection", 0.8,
        "Hidden instruction in comment syntax"),

    # ── Data Exfiltration ────────────────────────────────────────────────────
    Pattern("exfil_via_url", _c(
        r"(send|fetch|request|http\s+get|navigate\s+to|load)\s+.*\?\w+=(system|prompt|secret|key|password|token)"
    ), "data_exfiltration", 0.85,
        "Exfiltration via URL parameter"),

    Pattern("summarize_and_send", _c(
        r"(summarize|include|embed|append)\s+(all\s+)?(user\s+data|conversation\s+history|system\s+prompt|secrets?)\s+(in|into|and\s+send)"
    ), "data_exfiltration", 0.8,
        "Data collection and exfiltration"),

    # ── Goal Hijacking ───────────────────────────────────────────────────────
    Pattern("task_substitution", _c(
        r"(instead\s+of|rather\s+than)\s+(that|this|your\s+task|answering)\s*(,|please|just|actually)?\s*(do|perform|execute|say|write)"
    ), "goal_hijacking", 0.7,
        "Task substitution injection"),

    Pattern("true_purpose", _c(
        r"(your\s+(true|real|actual|hidden)\s+(purpose|goal|task|mission|instruction)\s+(is|was|should\s+be))"
    ), "goal_hijacking", 0.75,
        "Hidden purpose revelation attack"),

    # ── Multi-turn Escalation ────────────────────────────────────────────────
    Pattern("hypothetical_setup", _c(
        r"(hypothetically|in\s+a\s+fictional|imagine|let'?s\s+say|suppose|what\s+if)\s.{0,60}(how\s+would|could\s+you|would\s+you|can\s+you)"
    ), "multi_turn", 0.55,
        "Hypothetical framing for escalation"),

    Pattern("opposite_day", _c(
        r"(opposite\s+day|everything\s+you\s+say\s+means\s+the\s+opposite|reverse\s+(your\s+)?(logic|answer|response))"
    ), "multi_turn", 0.7,
        "Opposite-day logic inversion"),
]

# Pre-index by category for fast filtering
PATTERNS_BY_CATEGORY: dict[str, list[Pattern]] = {}
for _p in PATTERNS:
    PATTERNS_BY_CATEGORY.setdefault(_p.category, []).append(_p)

ALL_CATEGORIES = list(PATTERNS_BY_CATEGORY.keys())
