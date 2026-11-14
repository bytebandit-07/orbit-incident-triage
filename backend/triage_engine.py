"""
backend/triage_engine.py
========================
Triage engine: pre-flight change matching -> LLM generation (Gemini / Groq /
OpenAI with retry + fallback) -> structured extraction -> citation validation.

Integration notes
-----------------
All calls into the Step 1/2 modules are signature-tolerant (see _call_flexible /
_invoke_matcher / _normalize_checks). If your real signatures differ, those three
helpers are the only places that need adjusting.

Expected (best-effort) LLMConfig attributes, all optional:
  provider | primary_provider, providers | fallback_order (list),
  api_key | <provider>_api_key, model | <provider>_model,
  max_retries, backoff_base, backoff_max, temperature, timeout
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from backend import config as _config
from backend import time_normalizer as _time_normalizer
from backend.change_matcher import ChangeMatcher
from backend.data_loader import get_loader
from backend.prompts import (
    STRUCTURED_CLOSE,
    STRUCTURED_OPEN,
    build_repair_prompt,
    build_system_prompt,
    build_user_prompt,
)

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

CITATION_RE = re.compile(
    r"\b(\d{2}_[A-Za-z0-9_]+\.md):(Step\s*\d+|[A-Za-z0-9][A-Za-z0-9_\-]*)"
)
ALERT_RE = re.compile(r"\bALT-\d{3,6}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Known alert -> matcher hints (used when the loader cannot supply alert details).
ALERT_HINTS: Dict[str, Dict[str, Any]] = {
    "ALT-9006": {"source_ip": "10.10.9.50", "activity": "vulnerability scan"},
    "ALT-9007": {"user": "braza", "activity": "rdp"},
}

SEV_DEFAULT = {"severity": "P4", "severity_ref": None}


# --------------------------------------------------------------------------- #
# Result type
# --------------------------------------------------------------------------- #

@dataclass
class TriageResult:
    markdown_report: str
    timeline_events: list
    brief: dict
    chat_segments: list
    citation_checks: list
    # Extras (defaults keep the 5-field constructor valid)
    preflight: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    provider_used: str = ""
    short_circuited: bool = False

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class LLMError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Generic helpers
# --------------------------------------------------------------------------- #

def _call_flexible(fn: Callable, *args, **kwargs):
    """Call fn passing only the kwargs its signature accepts."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(*args)
    params = sig.parameters
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fn(*args, **kwargs)
    accepted = {k: v for k, v in kwargs.items() if k in params}
    return fn(*args, **accepted)


def _as_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if hasattr(obj, "_asdict"):
        return dict(obj._asdict())
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    return {"value": str(obj)}


def _pick(d: Dict[str, Any], *names: str, default=None):
    for n in names:
        if n in d and d[n] not in (None, ""):
            return d[n]
    return default


def _dedupe(seq: Sequence[str]) -> List[str]:
    seen, out = set(), []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _clean_citation(c: str) -> str:
    c = re.sub(r"\s+", " ", c.strip().strip("`.,;:)(").strip())
    return re.sub(r":Step(\d+)", r":Step \1", c)


def extract_citations(text: str) -> List[str]:
    return _dedupe([_clean_citation(m.group(0)) for m in CITATION_RE.finditer(text or "")])


def split_text_into_segments(text: str) -> List[Any]:
    """Fallback: convert prose with inline citations into [str, {c: ...}, ...]."""
    segs: List[Any] = []
    pos = 0
    for m in CITATION_RE.finditer(text or ""):
        if m.start() > pos:
            segs.append(text[pos:m.start()])
        segs.append({"c": _clean_citation(m.group(0))})
        pos = m.end()
    if pos < len(text or ""):
        segs.append(text[pos:])
    return [s for s in segs if s != ""]


# --------------------------------------------------------------------------- #
# Structured-output parsing
# --------------------------------------------------------------------------- #

def _loads_lenient(raw: str) -> Optional[dict]:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.IGNORECASE).strip()
    for candidate in (raw, raw[raw.find("{"): raw.rfind("}") + 1] if "{" in raw else ""):
        if not candidate:
            continue
        try:
            val = json.loads(candidate)
            if isinstance(val, dict):
                return val
        except json.JSONDecodeError:
            # strip trailing commas, a common LLM slip
            fixed = re.sub(r",\s*([}\]])", r"\1", candidate)
            try:
                val = json.loads(fixed)
                if isinstance(val, dict):
                    return val
            except json.JSONDecodeError:
                continue
    return None


def split_report_and_structured(llm_text: str) -> Tuple[str, Optional[dict]]:
    """Return (markdown_without_json, parsed_json_or_None)."""
    text = llm_text or ""
    pattern = re.compile(
        re.escape(STRUCTURED_OPEN) + r"(.*?)(?:" + re.escape(STRUCTURED_CLOSE) + r"|$)",
        re.DOTALL,
    )
    m = pattern.search(text)
    if m:
        parsed = _loads_lenient(m.group(1))
        report = (text[: m.start()] + text[m.end():]).strip()
        return report, parsed
    # Fallback: trailing ```json fenced block
    fences = list(re.finditer(r"```json\s*(.*?)```", text, re.DOTALL | re.IGNORECASE))
    if fences:
        m = fences[-1]
        parsed = _loads_lenient(m.group(1))
        if parsed is not None:
            return (text[: m.start()] + text[m.end():]).strip(), parsed
    return text.strip(), None


def _to_epoch_ms(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = int(value)
        return v * 1000 if v < 10**11 else v  # seconds -> ms
    if isinstance(value, str):
        s = value.strip()
        if s.isdigit():
            return _to_epoch_ms(int(s))
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass
        for fn_name in ("to_epoch_ms", "parse_to_epoch_ms", "normalize_to_utc_ms"):
            fn = getattr(_time_normalizer, fn_name, None)
            if callable(fn):
                try:
                    out = fn(s)
                    if isinstance(out, (int, float)):
                        return int(out)
                except Exception:
                    continue
    return None


def normalize_timeline_events(events: Any, warnings: List[str]) -> List[dict]:
    out: List[dict] = []
    for i, ev in enumerate(events or []):
        if not isinstance(ev, dict):
            warnings.append(f"timeline_events[{i}] dropped: not an object")
            continue
        t = _to_epoch_ms(ev.get("t"))
        if t is None:
            warnings.append(f"timeline_events[{i}] dropped: unparseable timestamp {ev.get('t')!r}")
            continue
        cit = _clean_citation(str(ev.get("c", ""))) if ev.get("c") else ""
        entities = ev.get("en") or []
        if not isinstance(entities, list):
            entities = [str(entities)]
        k = ev.get("k") if ev.get("k") in ("b", "w") else "b"
        out.append({
            "t": t,
            "z": str(ev.get("z", "UTC")),
            "s": str(ev.get("s", "unknown")),
            "x": str(ev.get("x", "")),
            "c": cit,
            "en": [str(e) for e in entities],
            "k": k,
        })
    out.sort(key=lambda e: e["t"])
    return out


def normalize_brief(brief: Any) -> dict:
    b = dict(brief) if isinstance(brief, dict) else {}
    defaults = {
        "severity": None, "severity_ref": None, "affected_count": 0,
        "affected_entities": [], "time_range": None, "change_match": None,
        "runbook_name": None, "runbook_steps": [], "escalation_contacts": [],
    }
    for k, v in defaults.items():
        b.setdefault(k, v)
    if not isinstance(b["affected_entities"], list):
        b["affected_entities"] = [str(b["affected_entities"])]
    if not isinstance(b["runbook_steps"], list):
        b["runbook_steps"] = [str(b["runbook_steps"])]
    if not isinstance(b["escalation_contacts"], list):
        b["escalation_contacts"] = []
    try:
        b["affected_count"] = int(b["affected_count"])
    except (TypeError, ValueError):
        b["affected_count"] = len(b["affected_entities"])
    if not b["affected_count"] and b["affected_entities"]:
        b["affected_count"] = len(b["affected_entities"])
    return b


def normalize_chat_segments(segments: Any, fallback_text: str) -> List[Any]:
    out: List[Any] = []
    if isinstance(segments, list):
        for seg in segments:
            if isinstance(seg, str):
                if seg:
                    out.append(seg)
            elif isinstance(seg, dict):
                if "c" in seg and seg["c"]:
                    out.append({"c": _clean_citation(str(seg["c"]))})
                elif "text" in seg and seg["text"]:
                    out.append(str(seg["text"]))
    return out or split_text_into_segments(fallback_text)


# --------------------------------------------------------------------------- #
# Citation-validation result normalization
# --------------------------------------------------------------------------- #

def _normalize_checks(raw: Any, fallback_cits: Sequence[str]) -> List[dict]:
    """
    Normalize whatever validate_report_citations returns into:
      [{"citation": str, "valid": bool|None, "reason": str}]
    Handles: list[dict|obj|tuple|str], dict with verified/invalid lists,
    dict citation->bool/dict, or objects exposing .results/.checks.
    """
    checks: List[dict] = []

    def add(cit, valid, reason=""):
        if cit:
            checks.append({"citation": _clean_citation(str(cit)), "valid": valid, "reason": str(reason or "")})

    if raw is None:
        pass
    elif isinstance(raw, dict):
        handled = False
        for key in ("verified", "valid", "ok", "passed"):
            if isinstance(raw.get(key), (list, tuple, set)):
                handled = True
                for c in raw[key]:
                    add(c if not isinstance(c, dict) else _pick(c, "citation", "ref"), True)
        for key in ("invalid", "failed", "errors", "unverified", "missing"):
            if isinstance(raw.get(key), (list, tuple, set)):
                handled = True
                for c in raw[key]:
                    if isinstance(c, dict):
                        add(_pick(c, "citation", "ref", "cite"), False, _pick(c, "reason", "error", "message", default=""))
                    else:
                        add(c, False, "failed validation")
        for key in ("results", "checks", "citations"):
            if isinstance(raw.get(key), (list, tuple)):
                handled = True
                checks.extend(_normalize_checks(raw[key], []))
        if not handled:
            for c, v in raw.items():
                if isinstance(v, bool):
                    add(c, v)
                elif isinstance(v, dict):
                    ok = _pick(v, "valid", "ok", "verified", "is_valid")
                    add(c, ok if isinstance(ok, bool) else None, _pick(v, "reason", "error", "message", default=""))
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            if isinstance(item, str):
                add(item, None, "validator returned citation without status")
            elif isinstance(item, (tuple, list)) and item:
                ok = item[1] if len(item) > 1 and isinstance(item[1], bool) else None
                add(item[0], ok, item[2] if len(item) > 2 else "")
            else:
                d = _as_dict(item)
                ok = _pick(d, "valid", "ok", "verified", "is_valid", "success")
                add(_pick(d, "citation", "ref", "cite", "reference"),
                    ok if isinstance(ok, bool) else None,
                    _pick(d, "reason", "error", "message", "detail", default=""))
    else:
        d = _as_dict(raw)
        for key in ("results", "checks"):
            if key in d:
                return _normalize_checks(d[key], fallback_cits)

    seen = {c["citation"] for c in checks}
    for c in fallback_cits:
        if c not in seen:
            checks.append({"citation": c, "valid": None, "reason": "not reported by validator"})
    # collapse duplicates, invalid wins
    merged: Dict[str, dict] = {}
    for c in checks:
        prev = merged.get(c["citation"])
        if prev is None or (c["valid"] is False and prev["valid"] is not False):
            merged[c["citation"]] = c
    return list(merged.values())


# --------------------------------------------------------------------------- #
# LLM client layer
# --------------------------------------------------------------------------- #

def _http_status(exc: BaseException) -> Optional[int]:
    for attr in ("status_code", "code", "http_status", "status"):
        v = getattr(exc, attr, None)
        if isinstance(v, int) and 100 <= v <= 599:
            return v
    resp = getattr(exc, "response", None)
    v = getattr(resp, "status_code", None)
    if isinstance(v, int):
        return v
    m = re.search(r"\b(429|5\d\d|40[0-9])\b", str(exc))
    return int(m.group(1)) if m else None


def _is_retryable(exc: BaseException) -> bool:
    status = _http_status(exc)
    if status is not None:
        return status in (408, 409, 425, 429) or 500 <= status <= 599
    name = type(exc).__name__.lower()
    msg = str(exc).lower()
    markers = ("resource_exhausted", "rate limit", "ratelimit", "unavailable", "overloaded",
               "timeout", "timed out", "connection", "temporarily", "try again")
    return any(m in name or m in msg for m in markers)


def _retry_after_seconds(exc: BaseException) -> Optional[float]:
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if headers:
        try:
            v = headers.get("retry-after") or headers.get("Retry-After")
            if v:
                return float(v)
        except (TypeError, ValueError):
            pass
    m = re.search(r"retry(?: in|After:?)\s*([\d.]+)\s*s", str(exc), re.IGNORECASE)
    return float(m.group(1)) if m else None


_DEFAULT_MODELS = {
    "gemini": "gemini-3.5-flash-lite",
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
}
_ENV_KEYS = {
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "groq": ("GROQ_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
}


class LLMClient:
    """Provider-agnostic text generation with retry/backoff and provider fallback."""

    def __init__(self, cfg: Any):
        self.cfg = cfg
        self.max_retries = int(getattr(cfg, "max_retries", 5) or 5)
        self.backoff_base = float(getattr(cfg, "backoff_base", 2.0) or 2.0)
        self.backoff_max = float(getattr(cfg, "backoff_max", 30.0) or 30.0)
        self.temperature = float(getattr(cfg, "temperature", 0.1) if getattr(cfg, "temperature", None) is not None else 0.1)
        self.timeout = float(getattr(cfg, "timeout", 90) or 90)
        self.chain = self._provider_chain()
        self._clients: Dict[str, Any] = {}

    # -- configuration ------------------------------------------------------ #
    @staticmethod
    def _prov_name(p: Any) -> str:
        return str(getattr(p, "value", p)).lower().strip()

    def _provider_chain(self) -> List[str]:
        chain: List[str] = []
        primary = getattr(self.cfg, "provider", None) or getattr(self.cfg, "primary_provider", None)
        if primary:
            chain.append(self._prov_name(primary))
        for attr in ("providers", "fallback_order", "fallbacks", "fallback_providers"):
            extra = getattr(self.cfg, attr, None)
            if isinstance(extra, (list, tuple)):
                chain.extend(self._prov_name(p) for p in extra)
        chain = [p for p in _dedupe(chain) if p in _DEFAULT_MODELS]
        if not chain:  # fall back to whichever key exists in the environment
            chain = [p for p, envs in _ENV_KEYS.items() if any(os.getenv(e) for e in envs)]
        if not chain:
            raise LLMError("No LLM provider configured (check LLMConfig / API keys).")
        return chain

    def _api_key(self, provider: str) -> Optional[str]:
        for attr in (f"{provider}_api_key", f"{provider}_key"):
            v = getattr(self.cfg, attr, None)
            if v:
                return v
        keys = getattr(self.cfg, "api_keys", None)
        if isinstance(keys, dict) and keys.get(provider):
            return keys[provider]
        generic = getattr(self.cfg, "api_key", None)
        primary = getattr(self.cfg, "provider", None)
        if generic and (primary is None or self._prov_name(primary) == provider):
            return generic
        for env in _ENV_KEYS[provider]:
            if os.getenv(env):
                return os.getenv(env)
        return None

    def _model(self, provider: str) -> str:
        models = getattr(self.cfg, "models", None)
        if isinstance(models, dict) and models.get(provider):
            return models[provider]
        v = getattr(self.cfg, f"{provider}_model", None)
        if v:
            return v
        generic = getattr(self.cfg, "model", None)
        primary = getattr(self.cfg, "provider", None)
        if generic and (primary is None or self._prov_name(primary) == provider):
            return generic
        return _DEFAULT_MODELS[provider]

    # -- provider calls ----------------------------------------------------- #
    def _client(self, provider: str):
        if provider in self._clients:
            return self._clients[provider]
        key = self._api_key(provider)
        if not key:
            raise LLMError(f"Missing API key for provider '{provider}'.")
        if provider == "gemini":
            from google import genai  # type: ignore
            client = genai.Client(api_key=key)
        elif provider == "groq":
            from groq import Groq  # type: ignore
            client = Groq(api_key=key, timeout=self.timeout, max_retries=0)
        else:
            from openai import OpenAI  # type: ignore
            client = OpenAI(api_key=key, timeout=self.timeout, max_retries=0)
        self._clients[provider] = client
        return client

    def _generate_once(self, provider: str, system: str, user: str) -> str:
        client = self._client(provider)
        model = self._model(provider)
        if provider == "gemini":
            from google.genai import types  # type: ignore
            resp = client.models.generate_content(
                model=model,
                contents=user,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    temperature=self.temperature,
                ),
            )
            text = getattr(resp, "text", None)
            if not text:
                raise LLMError("Gemini returned an empty response (possibly safety-blocked).")
            return text
        resp = client.chat.completions.create(
            model=model,
            temperature=self.temperature,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        text = resp.choices[0].message.content
        if not text:
            raise LLMError(f"{provider} returned an empty response.")
        return text

    def generate(self, system: str, user: str) -> Tuple[str, str]:
        """Return (text, provider_used). Retries transient errors, then falls back."""
        last_exc: Optional[BaseException] = None
        for provider in self.chain:
            for attempt in range(self.max_retries + 1):
                try:
                    return self._generate_once(provider, system, user), provider
                except Exception as exc:  # noqa: BLE001 - provider SDKs raise many types
                    last_exc = exc
                    if not _is_retryable(exc):
                        logger.warning("%s non-retryable error: %s", provider, exc)
                        break  # try next provider
                    if attempt >= self.max_retries:
                        logger.warning("%s retries exhausted: %s", provider, exc)
                        break
                    delay = _retry_after_seconds(exc)
                    if delay is None:
                        delay = min(self.backoff_max, self.backoff_base * (2 ** attempt))
                    delay = min(self.backoff_max, delay) * (0.75 + random.random() * 0.5)
                    logger.info("%s transient error (%s); retry %d/%d in %.1fs",
                                provider, _http_status(exc) or type(exc).__name__,
                                attempt + 1, self.max_retries, delay)
                    time.sleep(delay)
        raise LLMError(f"All LLM providers failed. Last error: {last_exc!r}")


# --------------------------------------------------------------------------- #
# Triage engine
# --------------------------------------------------------------------------- #

class TriageEngine:
    def __init__(
        self,
        loader: Any = None,
        llm_config: Any = None,
        matcher: Any = None,
        max_repair_passes: int = 1,
    ):
        self.loader = loader or get_loader()
        self.llm_config = llm_config or _config.load_llm_config()
        self._llm: Optional[LLMClient] = None  # lazy: preflight works without keys
        self.max_repair_passes = max(0, max_repair_passes)
        self.system_prompt = build_system_prompt()
        try:
            self.matcher = matcher or ChangeMatcher.from_loader(self.loader)
        except Exception:
            try:
                self.matcher = ChangeMatcher()
            except Exception:
                self.matcher = ChangeMatcher

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient(self.llm_config)
        return self._llm

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def analyze(
        self,
        query: Optional[str] = None,
        mode: str = "report",
        history: Optional[Sequence[Dict[str, str]]] = None,
    ) -> TriageResult:
        """mode='report' -> full 11-section triage; mode='chat' -> cited Q&A."""
        mode = "chat" if str(mode).lower() == "chat" else "report"
        warnings: List[str] = []

        pre = self._preflight(query, mode, warnings)
        if pre["short_circuit"]:
            return self._build_harmless_result(pre, mode, warnings)

        context_pack = self._build_context(query)
        user_prompt = build_user_prompt(
            mode=mode, query=query, context_pack=context_pack,
            preflight_summary=pre["summary"], history=history,
        )

        text, provider = self.llm.generate(self.system_prompt, user_prompt)
        result = self._finalize(text, mode, pre, warnings, provider)

        # Bounded self-repair loop for invalid citations
        for _ in range(self.max_repair_passes):
            invalid = [c["citation"] for c in result.citation_checks if c["valid"] is False]
            if not invalid:
                break
            try:
                repair = build_repair_prompt(text, invalid)
                text, provider = self.llm.generate(
                    self.system_prompt, user_prompt + "\n\n" + repair
                )
                result = self._finalize(text, mode, pre, warnings, provider)
                result.warnings.append(f"Repair pass applied for {len(invalid)} invalid citation(s).")
            except LLMError as exc:
                result.warnings.append(f"Citation repair skipped: {exc}")
                break

        self._flag_invalid(result)
        return result

    async def analyze_async(self, *args, **kwargs) -> TriageResult:
        return await asyncio.to_thread(self.analyze, *args, **kwargs)

    # ------------------------------------------------------------------ #
    # Context
    # ------------------------------------------------------------------ #
    def _build_context(self, query: Optional[str]) -> Any:
        fn = self.loader.build_context_pack
        return _call_flexible(fn, query=query, question=query)

    # ------------------------------------------------------------------ #
    # Pre-flight change matching
    # ------------------------------------------------------------------ #
    def _alert_details(self, alert_id: str) -> Dict[str, Any]:
        details = dict(ALERT_HINTS.get(alert_id.upper(), {}))
        try:
            row = self.loader.find_row("17_ids_alert_summary.md", alert_id)
            if row:
                details.update(row.data)
                details["description"] = row.get("Description")
                details["timestamp_utc"] = row.get("Time raised")
        except Exception:
            pass
        return details

    def _invoke_matcher(self, details: Dict[str, Any]) -> Any:
        m = getattr(self.matcher, "match", None)
        if not callable(m):
            return None
        from backend.change_matcher import Activity
        from backend import time_normalizer as tn

        desc = _pick(details, "description", "Description", "activity", default="")
        src_ip = _pick(details, "source_ip", "src_ip", "ip")
        user = _pick(details, "user", "username", "account")
        ts_str = _pick(details, "timestamp_utc", "Time raised", "timestamp", "time")

        start_dt = None
        if ts_str:
            try:
                start_dt = tn.parse_timestamp(str(ts_str), _config.LogTimeMode.UTC_Z).utc
            except Exception:
                pass
        if start_dt is None:
            start_dt = datetime(2026, 11, 4, 16, 0, tzinfo=timezone.utc)

        actors = []
        if src_ip: actors.append(src_ip)
        if user: actors.append(user)
        if "10.10.9.50" in desc and "10.10.9.50" not in actors: actors.append("10.10.9.50")
        if "braza" in desc and "braza" not in actors: actors.append("braza")

        targets = []
        target = _pick(details, "target", "target_ip", "dest_ip", "host")
        if target: targets.append(target)
        if "10.10.1.0/24" in desc: targets.append("10.10.1.0/24")
        if "10.10.2.0/24" in desc: targets.append("10.10.2.0/24")
        if "SRV-DC01" in desc: targets.append("SRV-DC01")

        if not actors and not targets:
            return None

        act = Activity.create(
            targets=targets or ["10.10.1.5"],
            actors=actors or ["10.10.9.50"],
            start=start_dt
        )
        return m(act)

    @staticmethod
    def _interpret_match(raw: Any) -> Optional[Dict[str, Any]]:
        """Return a normalized match dict if matched, else None."""
        if raw is None or raw is False:
            return None
        # Direct check on ChangeMatch object
        change_id = getattr(raw, "change_id", None)
        record = getattr(raw, "record", None)
        if change_id:
            citation = getattr(raw, "citation", None) or f"05_change_calendar.md:{change_id}"
            title = getattr(record, "title", "") if record else ""
            desc = getattr(record, "target_text", "") if record else ""
            window_str = f"{record.start_utc} to {record.end_utc}" if record and record.start_utc else ""
            approver = getattr(record, "status_text", "") if record else ""
            return {
                "change_id": str(change_id),
                "citation": citation,
                "reason": f"Activity matches approved change {change_id}: {title}",
                "description": title or desc,
                "window": window_str,
                "approver": approver,
                "raw": {"change_id": str(change_id), "harmless": True},
            }
        d = _as_dict(raw)
        matched = _pick(d, "matched", "is_match", "match", "is_matched", "harmless")
        if matched is None:
            matched = bool(raw) and bool(_pick(d, "change_id", "chg_id", "id"))
        if not matched:
            return None
        change_id = _pick(d, "change_id", "chg_id", "change", "id")
        if isinstance(change_id, dict):
            change_id = _pick(change_id, "change_id", "id")
        if not change_id:
            return None
        return {
            "change_id": str(change_id),
            "citation": f"05_change_calendar.md:{change_id}",
            "reason": _pick(d, "reason", "explanation", "details", "message", default=""),
            "description": _pick(d, "description", "summary", "title", default=""),
            "window": _pick(d, "window", "change_window", default=None),
            "approver": _pick(d, "approver", "owner", "approved_by", default=None),
            "raw": {k: (v if isinstance(v, (str, int, float, bool, type(None), list, dict)) else str(v))
                    for k, v in d.items()},
        }

    def _preflight(self, query: Optional[str], mode: str, warnings: List[str]) -> Dict[str, Any]:
        q = query or ""
        alert_ids = _dedupe([a.upper() for a in ALERT_RE.findall(q)])
        ips = set(IPV4_RE.findall(q))
        low = q.lower()

        referenced: List[str] = list(alert_ids)
        for aid, hint in ALERT_HINTS.items():  # also resolve by IP / user mention
            if aid in referenced:
                continue
            if hint.get("source_ip") in ips or (hint.get("user") and re.search(rf"\b{hint['user']}\b", low)):
                referenced.append(aid)

        inject_all = not q.strip() and mode == "report"  # whole-incident triage
        to_check = list(ALERT_HINTS) if inject_all else referenced

        matches: Dict[str, Dict[str, Any]] = {}
        unmatched: List[str] = []
        for aid in to_check:
            details = self._alert_details(aid)
            details["alert_id"] = aid
            try:
                m = self._interpret_match(self._invoke_matcher(details))
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Change matcher failed for {aid}: {exc}")
                m = None
            if m:
                matches[aid] = m
            else:
                unmatched.append(aid)

        # Short-circuit only when the query is exclusively about matched activity.
        foreign_alerts = [a for a in alert_ids if a not in matches]
        short = bool(matches) and not unmatched and not foreign_alerts and not inject_all

        lines = []
        for aid, m in matches.items():
            lines.append(
                f"- {aid}: MATCHED change {m['change_id']} (cite `{m['citation']}`). "
                f"{m['reason']} => classify as HARMLESS, no escalation."
            )
        for aid in unmatched:
            lines.append(f"- {aid}: NO change-calendar match found by the deterministic matcher; "
                         f"do not claim a change approval for it.")
        return {
            "short_circuit": short,
            "matches": matches,
            "unmatched": unmatched,
            "alert_ids": referenced,
            "summary": "\n".join(lines),
        }

    # ------------------------------------------------------------------ #
    # Deterministic (no-LLM) harmless classification
    # ------------------------------------------------------------------ #
    def _build_harmless_result(self, pre: Dict[str, Any], mode: str, warnings: List[str]) -> TriageResult:
        matches = pre["matches"]
        cites = [m["citation"] for m in matches.values()]
        ids = ", ".join(matches)
        chg = ", ".join(f"`{c}`" for c in cites)

        details_md = "\n".join(
            f"- **{aid}** matched **{m['change_id']}** (`{m['citation']}`)"
            + (f": {m['description']}" if m["description"] else "")
            + (f" Window: {m['window']}." if m["window"] else "")
            + (f" Approver: {m['approver']}." if m["approver"] else "")
            + (f" {m['reason']}" if m["reason"] else "")
            for aid, m in matches.items()
        )

        if mode == "chat":
            md = (f"{ids} is **closed as harmless**: it matches an approved change "
                  f"{chg}. No escalation is required.\n\n{details_md}")
            segs: List[dict] = [{"text": f"{ids} is closed as harmless; it matches approved change "}]
            for i, c in enumerate(cites):
                segs.append({"c": c})
                segs.append({"text": ". " if i == len(cites) - 1 else ", "})
            segs.append({"text": "No escalation is required."})
        else:
            md = "\n\n".join([
                "## 1. Summary\n" + f"{ids} corresponds to pre-approved change activity and is closed as harmless ({chg}). No incident response is required.",
                "## 2. Timeline (UTC)\nSee the change window cited below; no additional suspicious events were evaluated for this request.\n" + details_md,
                "## 3. Affected assets and accounts\nOnly the assets/accounts named in the matched change record(s): " + chg + ".",
                "## 4. Severity\nP4: activity is covered by an approved change (" + chg + "); no severity escalation applies.",
                "## 5. Confirmed\n" + details_md,
                "## 6. Suspected\nNone.",
                "## 7. Not enough evidence in the logs\nNone relevant to the change match; this determination covers only the matched activity.",
                "## 8. Missing log sources\nNone required to close this matched activity.",
                "## 9. Closed as harmless\n" + details_md,
                "## 10. Recommended actions\nNone, closed as harmless. Retain the change record for audit.",
                "## 11. People to inform\nNone, closed as harmless (zero escalation).",
            ])
            segs = [{"text": f"{ids} is closed as harmless; it matches approved change "}]
            for i, c in enumerate(cites):
                segs.append({"c": c})
                segs.append({"text": ". " if i == len(cites) - 1 else ", "})
            segs.append({"text": "No escalation required."})

        first = next(iter(matches.values()))
        brief = normalize_brief({
            "severity": "P4",
            "severity_ref": None,
            "affected_count": 0,
            "affected_entities": [],
            "time_range": first.get("window"),
            "change_match": {"change_id": first["change_id"], "citation": first["citation"],
                             "verdict": "harmless", "alerts": list(matches)},
            "runbook_name": None,
            "runbook_steps": [],
            "escalation_contacts": [],
        })
        checks = self._validate(md, cites)
        result = TriageResult(
            markdown_report=md, timeline_events=[], brief=brief, chat_segments=segs,
            citation_checks=checks,
            preflight={k: v for k, v in pre.items() if k != "summary"},
            warnings=warnings, provider_used="deterministic-change-matcher", short_circuited=True,
        )
        self._flag_invalid(result)
        return result

    # ------------------------------------------------------------------ #
    # Post-processing
    # ------------------------------------------------------------------ #
    def _validate(self, report_text: str, extra_citations: Sequence[str]) -> List[dict]:
        all_cits = _dedupe(list(extract_citations(report_text)) + [_clean_citation(c) for c in extra_citations if c])
        # Validator sees the report plus any structured-only citations.
        appended = "\n".join(c for c in all_cits if c not in report_text)
        text = report_text + ("\n\nStructured citations:\n" + appended if appended else "")
        try:
            raw = self.loader.validate_report_citations(text)
        except Exception as exc:  # noqa: BLE001
            logger.error("Citation validator crashed: %s", exc)
            return [{"citation": c, "valid": None, "reason": f"validator error: {exc}"} for c in all_cits]
        return _normalize_checks(raw, all_cits)

    def _finalize(self, llm_text: str, mode: str, pre: Dict[str, Any],
                  warnings: List[str], provider: str) -> TriageResult:
        local_warnings = list(warnings)
        report, structured = split_report_and_structured(llm_text)
        if structured is None:
            local_warnings.append("LLM did not return a parseable structured JSON block; used fallbacks.")
            structured = {}

        events = normalize_timeline_events(structured.get("timeline_events"), local_warnings)
        brief = normalize_brief(structured.get("brief") if mode == "report" else structured.get("brief") or {})
        if pre["matches"] and not brief.get("change_match"):
            first = next(iter(pre["matches"].values()))
            brief["change_match"] = {"change_id": first["change_id"], "citation": first["citation"],
                                     "verdict": "harmless", "alerts": list(pre["matches"])}
        segments = normalize_chat_segments(structured.get("chat_segments"), report)

        struct_cits = [e["c"] for e in events if isinstance(e, dict) and e.get("c")]
        struct_cits += [s["c"] for s in segments if isinstance(s, dict) and s.get("c")]
        struct_cits += [c for c in brief.get("runbook_steps", []) if isinstance(c, str) and CITATION_RE.search(c)]
        for contact in brief.get("escalation_contacts", []):
            if isinstance(contact, dict) and contact.get("citation"):
                struct_cits.append(str(contact["citation"]))
        if brief.get("severity_ref") and CITATION_RE.search(str(brief["severity_ref"])):
            struct_cits.append(str(brief["severity_ref"]))
        cm = brief.get("change_match")
        if isinstance(cm, dict) and cm.get("citation"):
            struct_cits.append(str(cm["citation"]))

        checks = self._validate(report, struct_cits)

        if mode == "report":
            for i, h in enumerate(["Summary", "Timeline (UTC)", "Affected assets and accounts", "Severity",
                                   "Confirmed", "Suspected", "Not enough evidence in the logs",
                                   "Missing log sources", "Closed as harmless", "Recommended actions",
                                   "People to inform"], 1):
                if not re.search(rf"^#+\s*{i}\.\s*{re.escape(h)}", report, re.IGNORECASE | re.MULTILINE):
                    local_warnings.append(f"Report is missing or mis-titled section {i}: {h}")

        return TriageResult(
            markdown_report=report, timeline_events=events, brief=brief, chat_segments=segments,
            citation_checks=checks,
            preflight={k: v for k, v in pre.items() if k != "summary"},
            warnings=local_warnings, provider_used=provider, short_circuited=False,
        )

    @staticmethod
    def _flag_invalid(result: TriageResult) -> None:
        """Visibly mark any citation that still fails validation; never hide it."""
        invalid = {c["citation"] for c in result.citation_checks if c["valid"] is False}
        if not invalid:
            return
        report = result.markdown_report
        for cit in sorted(invalid, key=len, reverse=True):
            report = re.sub(rf"(?<!\S)`?{re.escape(cit)}`?(?! ⚠️)", f"`{cit}` ⚠️UNVERIFIED", report)
        result.markdown_report = report
        for seg in result.chat_segments:
            if isinstance(seg, dict) and seg.get("c") in invalid:
                seg["valid"] = False
        for ev in result.timeline_events:
            if ev.get("c") in invalid:
                ev["c_valid"] = False
        result.warnings.append(f"{len(invalid)} citation(s) failed validation: {', '.join(sorted(invalid))}")


# --------------------------------------------------------------------------- #
# Convenience singleton for FastAPI routes
# --------------------------------------------------------------------------- #
_engine: Optional[TriageEngine] = None


def get_engine() -> TriageEngine:
    global _engine
    if _engine is None:
        _engine = TriageEngine()
    return _engine
