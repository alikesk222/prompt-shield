"""
Framework middleware and decorators for prompt-shield.

Supported integrations:
  - FastAPI (ASGI middleware + dependency)
  - Flask (before_request hook)
  - WSGI (generic)
  - Decorator (@shield_route)
  - Standalone: Shield class
"""

import functools
import json
import logging
from typing import Any, Callable, Optional, Union

from .detector import Detector, DetectionResult
from .sanitizer import sanitize as _sanitize

logger = logging.getLogger("promptshield")


class InjectionDetected(Exception):
    """Raised when prompt injection is detected in strict mode."""

    def __init__(self, result: DetectionResult):
        self.result = result
        super().__init__(
            f"Prompt injection detected (score={result.score:.2f}, "
            f"threat={result.threat_level}, "
            f"categories={result.categories})"
        )


class Shield:
    """
    High-level shield interface. Instantiate once and use across your app.

    Basic usage:
        shield = Shield()
        result = shield.scan(user_input)
        if result.is_injection:
            return "I cannot process that request."

    Sanitize + scan in one step:
        clean_input, result = shield.sanitize_and_scan(user_input)
        if not result.is_injection:
            call_llm(clean_input)

    Strict mode (raises on injection):
        shield = Shield(strict=True)
        shield.scan(user_input)  # raises InjectionDetected if flagged
    """

    def __init__(
        self,
        threshold: float = 0.5,
        strict: bool = False,
        sanitize: bool = True,
        log: bool = True,
        on_injection: Optional[Callable[[DetectionResult], Any]] = None,
        detector_kwargs: Optional[dict] = None,
    ):
        """
        Args:
            threshold       Score threshold for is_injection (default 0.5)
            strict          If True, raise InjectionDetected instead of returning result
            sanitize        If True, sanitize input before scanning (default True)
            log             If True, log detections via logging module (default True)
            on_injection    Optional callback(result) called on every detection
            detector_kwargs Extra kwargs passed to Detector constructor
        """
        self.strict = strict
        self.do_sanitize = sanitize
        self.log = log
        self.on_injection = on_injection
        self._detector = Detector(threshold=threshold, **(detector_kwargs or {}))

    def scan(self, text: str) -> DetectionResult:
        """
        Scan text for prompt injection.

        Returns DetectionResult (truthy if injection detected).
        If strict=True, raises InjectionDetected instead of returning.
        """
        if self.do_sanitize:
            clean = _sanitize(text)
            result = self._detector.detect(clean)
            result.sanitized = clean
        else:
            result = self._detector.detect(text)

        if result.is_injection:
            if self.log:
                logger.warning(
                    "prompt-shield: injection detected | score=%.2f threat=%s categories=%s input_len=%d",
                    result.score, result.threat_level, result.categories, result.input_length,
                )
            if self.on_injection:
                self.on_injection(result)
            if self.strict:
                raise InjectionDetected(result)

        return result

    def sanitize_and_scan(self, text: str) -> tuple[str, DetectionResult]:
        """
        Sanitize text and scan for injections.

        Returns (sanitized_text, DetectionResult).
        """
        clean = _sanitize(text)
        result = self._detector.detect(clean)
        result.sanitized = clean

        if result.is_injection:
            if self.log:
                logger.warning(
                    "prompt-shield: injection detected | score=%.2f threat=%s categories=%s",
                    result.score, result.threat_level, result.categories,
                )
            if self.on_injection:
                self.on_injection(result)
            if self.strict:
                raise InjectionDetected(result)

        return clean, result

    def is_safe(self, text: str) -> bool:
        """Returns True if text does NOT contain an injection."""
        return not self.scan(text).is_injection

    def wrap(self, func: Callable) -> Callable:
        """
        Decorator: scan the first positional string argument of a function.

        Usage:
            shield = Shield()

            @shield.wrap
            def chat(user_message: str) -> str:
                return call_llm(user_message)
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Scan first string argument
            new_args = list(args)
            for i, arg in enumerate(new_args):
                if isinstance(arg, str):
                    result = self.scan(arg)
                    if result.sanitized is not None:
                        new_args[i] = result.sanitized
                    break
            return func(*new_args, **kwargs)
        return wrapper


# ── FastAPI integration ───────────────────────────────────────────────────────

def make_fastapi_middleware(
    app,
    shield: Optional[Shield] = None,
    fields: Optional[list[str]] = None,
    rejection_status: int = 400,
    rejection_body: Optional[dict] = None,
):
    """
    Attach prompt-shield as ASGI middleware to a FastAPI app.

    Args:
        app               FastAPI application instance
        shield            Shield instance (creates default if None)
        fields            JSON body fields to scan (default: ["message", "prompt", "query", "input", "content"])
        rejection_status  HTTP status code returned on injection (default 400)
        rejection_body    JSON body returned on injection

    Usage:
        from fastapi import FastAPI
        from promptshield.middleware import make_fastapi_middleware

        app = FastAPI()
        make_fastapi_middleware(app)
    """
    try:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request
        from starlette.responses import JSONResponse
    except ImportError:
        raise ImportError("FastAPI/Starlette is required. pip install fastapi")

    _shield = shield or Shield()
    _fields = fields or ["message", "prompt", "query", "input", "content", "text"]
    _rejection = rejection_body or {"error": "Input rejected: potential prompt injection detected."}

    class ShieldMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    body = await request.body()
                    data = json.loads(body)
                    for field in _fields:
                        value = data.get(field)
                        if isinstance(value, str):
                            result = _shield._detector.detect(value)
                            if result.is_injection:
                                logger.warning(
                                    "prompt-shield [FastAPI]: injection in field=%s score=%.2f",
                                    field, result.score,
                                )
                                return JSONResponse(
                                    status_code=rejection_status,
                                    content={**_rejection, "field": field, "score": result.score},
                                )
                except Exception:
                    pass
            return await call_next(request)

    app.add_middleware(ShieldMiddleware)
    return app


def fastapi_dependency(
    shield: Optional[Shield] = None,
    fields: Optional[list[str]] = None,
):
    """
    FastAPI dependency that scans request body for injections.

    Usage:
        from fastapi import FastAPI, Depends
        from promptshield.middleware import fastapi_dependency

        app = FastAPI()
        shield_dep = fastapi_dependency()

        @app.post("/chat")
        async def chat(body: ChatRequest, _=Depends(shield_dep)):
            ...
    """
    try:
        from fastapi import Request, HTTPException
    except ImportError:
        raise ImportError("FastAPI is required. pip install fastapi")

    _shield = shield or Shield()
    _fields = fields or ["message", "prompt", "query", "input", "content", "text"]

    async def dependency(request: Request):
        try:
            body = await request.json()
            for field in _fields:
                value = body.get(field)
                if isinstance(value, str):
                    result = _shield._detector.detect(value)
                    if result.is_injection:
                        raise HTTPException(
                            status_code=400,
                            detail={
                                "error": "Potential prompt injection detected.",
                                "field": field,
                                "score": result.score,
                                "threat_level": result.threat_level,
                            },
                        )
        except HTTPException:
            raise
        except Exception:
            pass

    return dependency


# ── Flask integration ─────────────────────────────────────────────────────────

def init_flask(
    app,
    shield: Optional[Shield] = None,
    fields: Optional[list[str]] = None,
    rejection_status: int = 400,
):
    """
    Register prompt-shield as a Flask before_request hook.

    Usage:
        from flask import Flask
        from promptshield.middleware import init_flask

        app = Flask(__name__)
        init_flask(app)
    """
    try:
        from flask import request, jsonify
    except ImportError:
        raise ImportError("Flask is required. pip install flask")

    _shield = shield or Shield()
    _fields = fields or ["message", "prompt", "query", "input", "content", "text"]

    @app.before_request
    def _shield_check():
        if request.is_json:
            try:
                data = request.get_json(silent=True) or {}
                for field in _fields:
                    value = data.get(field)
                    if isinstance(value, str):
                        result = _shield._detector.detect(value)
                        if result.is_injection:
                            logger.warning(
                                "prompt-shield [Flask]: injection field=%s score=%.2f",
                                field, result.score,
                            )
                            return jsonify({
                                "error": "Input rejected: potential prompt injection detected.",
                                "field": field,
                                "score": result.score,
                                "threat_level": result.threat_level,
                            }), rejection_status
            except Exception:
                pass
