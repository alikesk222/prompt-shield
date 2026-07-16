# prompt-shield

> Real-time **prompt injection detection and prevention** for LLM applications.
> Zero dependencies. One line to integrate.

[![CI](https://github.com/alikesk222/prompt-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/alikesk222/prompt-shield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/prompt-shield.svg)](https://pypi.org/project/prompt-shield/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-zero-brightgreen?style=flat-square)](#)
[![Security](https://img.shields.io/badge/Topic-AI%20Security-red?style=flat-square)](#)

**prompt-shield** sits between your users and your LLM. It detects prompt injection attempts in real-time using multi-layer analysis — pattern matching + heuristic anomaly scoring — and blocks them before they reach the model.

---

## Install

```bash
pip install prompt-shield
```

---

## Quick Start

```python
from promptshield import is_safe, detect, Shield

# One-liner guard
if not is_safe(user_input):
    return "I cannot process that request."

# Detailed result
result = detect(user_input)
print(result.score)        # 0.0 - 1.0
print(result.threat_level) # 'none' | 'low' | 'medium' | 'high' | 'critical'
print(result.categories)   # ['direct_override', 'role_confusion']
print(result.is_injection) # True / False

# Result is truthy — use it directly in if statements
if detect(user_input):
    return reject_response()
```

---

## Detection Layers

prompt-shield uses two complementary approaches:

### 1. Rule-Based Pattern Matching
30+ compiled regex patterns covering 8 attack categories:

| Category | Examples |
|----------|---------|
| `direct_override` | "ignore previous instructions", "disregard all rules" |
| `role_confusion` | DAN jailbreak, "act as", "you are now", evil mode |
| `prompt_extraction` | "repeat your system prompt", "what were your instructions" |
| `delimiter_injection` | `[INST]`, `<\|im_start\|>`, `<system>`, JSON role injection |
| `encoding` | base64 instructions, zero-width chars, Cyrillic lookalikes |
| `indirect_injection` | HTML comment injection, hidden instruction markers |
| `data_exfiltration` | URL parameter exfil, "summarize and send" |
| `goal_hijacking` | Task substitution, "your true purpose is" |

### 2. Heuristic Anomaly Scoring
- **Instruction density** — ratio of command verbs to total words
- **Delimiter density** — suspicious `###`, `===`, XML tag frequency
- **Special character ratio** — control/invisible character abuse
- **Shannon entropy** — detects encoded/obfuscated payloads
- **Length penalty** — unusually long inputs

Final score = `pattern_score × 0.7 + heuristic_score × 0.3`

---

## Shield Class

```python
from promptshield import Shield

shield = Shield(
    threshold=0.5,      # score threshold (default 0.5)
    strict=False,       # if True, raises InjectionDetected instead of returning
    sanitize=True,      # auto-sanitize input before scanning
    log=True,           # log detections via logging module
)

# Scan
result = shield.scan(user_input)

# Sanitize + scan in one step
clean_input, result = shield.sanitize_and_scan(user_input)
if not result.is_injection:
    response = call_llm(clean_input)

# Strict mode — raises exception
try:
    shield_strict = Shield(strict=True)
    shield_strict.scan(user_input)
except InjectionDetected as e:
    print(e.result.score)
```

---

## Framework Integrations

### FastAPI — ASGI Middleware

```python
from fastapi import FastAPI
from promptshield.middleware import make_fastapi_middleware

app = FastAPI()
make_fastapi_middleware(app)  # scans "message", "prompt", "query", "input" fields

@app.post("/chat")
async def chat(body: ChatRequest):
    return {"response": call_llm(body.message)}
```

### FastAPI — Dependency Injection

```python
from fastapi import FastAPI, Depends
from promptshield.middleware import fastapi_dependency

app = FastAPI()
guard = fastapi_dependency()

@app.post("/chat")
async def chat(body: ChatRequest, _=Depends(guard)):
    return {"response": call_llm(body.message)}
```

### Flask

```python
from flask import Flask
from promptshield.middleware import init_flask

app = Flask(__name__)
init_flask(app)  # registers before_request hook

@app.route("/chat", methods=["POST"])
def chat():
    ...
```

### Decorator

```python
from promptshield import Shield

shield = Shield()

@shield.wrap
def process_message(message: str) -> str:
    # message is auto-sanitized before reaching here
    return call_llm(message)
```

---

## Input Sanitizer

Use the sanitizer independently to clean inputs before sending to your LLM:

```python
from promptshield import sanitize

clean = sanitize(
    user_input,
    remove_invisible=True,   # strip zero-width chars
    remove_control=True,     # strip control characters
    remove_delimiters=True,  # strip [INST], <|im_start|>, etc.
    normalize=True,          # Unicode NFC normalization
    collapse_newlines=True,  # collapse 3+ newlines to 2
    max_length=4096,         # hard truncate
)
```

---

## Custom Patterns

```python
import re
from promptshield import Shield
from promptshield.patterns import Pattern
from promptshield.detector import Detector

custom = Pattern(
    name="my_secret_keyword",
    regex=re.compile(r"ACME_INTERNAL_BYPASS", re.IGNORECASE),
    category="custom",
    weight=1.0,
    description="Internal bypass keyword",
)

shield = Shield(detector_kwargs={"custom_patterns": [custom]})
```

---

## Tune the Threshold

```python
# More sensitive — flag more (may have more false positives)
shield = Shield(threshold=0.35)

# Less sensitive — only flag obvious attacks
shield = Shield(threshold=0.70)
```

---

## Detection Result

```python
result = detect(text)

result.is_injection      # bool
result.score             # float 0.0-1.0
result.threat_level      # 'none' | 'low' | 'medium' | 'high' | 'critical'
result.categories        # list[str] — attack categories found
result.matched_rules     # list[MatchedRule] — detailed rule matches
result.heuristic_score   # float — anomaly component
result.input_length      # int — input character count
result.sanitized         # str | None — sanitized text (if sanitize=True)
bool(result)             # True if is_injection
```

---

## Benchmark

On a 2021 MacBook Pro (M1), detecting a typical input (~200 chars):

| Operation | Time |
|-----------|------|
| `detect()` | ~0.1ms |
| `sanitize()` | ~0.05ms |
| `sanitize_and_scan()` | ~0.15ms |

Zero external dependencies — runs anywhere Python runs.

---

## vs. llm-prompt-injector

| | prompt-shield | llm-prompt-injector |
|--|---------------|---------------------|
| **Purpose** | Defensive — protect your app | Offensive — test your app |
| **Use in production** | Yes | No (pen-testing only) |
| **Integration** | Library / middleware | CLI tool |
| **Install** | `pip install prompt-shield` | `pip install llm-prompt-injector` |

Use **llm-prompt-injector** to find vulnerabilities. Use **prompt-shield** to fix them.

---

## License

MIT — See [LICENSE](LICENSE)

---

> Built by [Ali Kesik](https://github.com/alikesk222)
