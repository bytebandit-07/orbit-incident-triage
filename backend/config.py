"""
backend/config.py
=================
Single source of truth for constants used across the triage pipeline:

  * filesystem paths (data dir is resolved relative to the project root)
  * timezone constants (PKT = UTC+05:00 is the company clock, UTC is the report clock)
  * severity levels + notification SLAs
  * a registry describing each of the 20 data files (kind, timezone, primary key)
  * known log-coverage gaps (the "traps" the rubric rewards us for knowing)
  * LLM provider / model / retry configuration, driven by environment variables

Only the standard library is required. `python-dotenv` is used if installed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import time, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Tuple

# --------------------------------------------------------------------------- #
# Optional .env support (never a hard dependency)
# --------------------------------------------------------------------------- #
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env", override=False)
except ImportError:
    pass


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
# TRIAGE_DATA_DIR lets the judges' unseen test set live elsewhere without code
# changes. A relative override is resolved against the project root.
def _resolve_data_dir() -> Path:
    override = os.getenv("TRIAGE_DATA_DIR", "").strip()
    if override:
        p = Path(override).expanduser()
        return p if p.is_absolute() else (PROJECT_ROOT / p).resolve()
    return (PROJECT_ROOT / "problem_c_data").resolve()


DATA_DIR: Path = _resolve_data_dir()
OUTPUT_DIR: Path = PROJECT_ROOT / "outputs"
FRONTEND_DIR: Path = PROJECT_ROOT / "frontend"

# --------------------------------------------------------------------------- #
# Time constants
# --------------------------------------------------------------------------- #
# Company rule: internal time is PKT (UTC+5, no DST). Every timestamp in the
# final report must be normalized to UTC.
PKT_OFFSET: timedelta = timedelta(hours=5)
PKT_TZ: timezone = timezone(PKT_OFFSET, name="PKT")
UTC_TZ: timezone = timezone.utc

# Default rendering of a UTC timestamp in the report. If 01_company_security_rules.md
# prescribes a different literal format, change it here once and everything follows.
UTC_OUTPUT_FORMAT: str = "%Y-%m-%dT%H:%M:%SZ"


class LogTimeMode(str, Enum):
    """How timestamps are written inside a given data file."""

    UTC_Z = "utc_z"              # ISO-8601 with trailing Z
    PKT_NAIVE = "pkt_naive"      # no zone marker -> MUST be treated as PKT
    OFFSET_IN_LINE = "offset"    # each line carries its own +HH:MM offset
    NONE = "none"                # not a time-series file


# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #
class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"

    @property
    def rank(self) -> int:
        """1 = most severe. Handy for max()/sorted()."""
        return int(self.value[1])

    @classmethod
    def from_text(cls, text: str) -> Optional["Severity"]:
        """Pull the first P1..P4 token out of free text ('P2 - High' -> P2)."""
        m = re.search(r"\bP\s*([1-4])\b", text or "", flags=re.IGNORECASE)
        return cls(f"P{m.group(1)}") if m else None


SEVERITY_LEVELS: Tuple[str, ...] = tuple(s.value for s in Severity)
CRITICALITY_LEVELS: Tuple[str, ...] = ("Critical", "High", "Medium", "Low")

# Evidence labels mandated by 01_company_security_rules.md.
EVIDENCE_CONFIRMED = "Confirmed"
EVIDENCE_SUSPECTED = "Suspected"
EVIDENCE_NONE = "Not enough evidence in the logs"
EVIDENCE_LABELS: Tuple[str, ...] = (EVIDENCE_CONFIRMED, EVIDENCE_SUSPECTED, EVIDENCE_NONE)

# Notification deadlines (minutes from detection). Source of truth is
# 04_escalation_and_contacts.md; these defaults mirror the brief so the engine
# can compute deadlines deterministically. P4 = next business day (None here).
ESCALATION_SLA_MINUTES: Dict[Severity, Dict[str, Optional[int]]] = {
    Severity.P1: {"CISO": 15, "IT Director": 30, "Legal / Data Owner": 60},
    Severity.P2: {"Security Manager": 60, "Asset Owner": 120},
    Severity.P3: {"SOC Lead": 240},
    Severity.P4: {"SOC Lead": None},  # next business day
}

# --------------------------------------------------------------------------- #
# Known coverage gaps / time traps (used by prompts + validators)
# --------------------------------------------------------------------------- #
# 12_windows_dc_auth_log.md only covers 03:00-19:00 UTC: silence outside that
# window is NOT evidence of absence.
DC_LOG_COVERAGE_UTC: Tuple[time, time] = (time(3, 0, 0), time(19, 0, 0))

# 15_firewall_internal_log.md: device rebooted; nothing was logged in this PKT
# window. Sessions are logged at CLOSE time with a duration in seconds, so the
# session START = close time - duration.
FW_INTERNAL_REBOOT_PKT: Tuple[time, time] = (time(11, 32, 0), time(12, 28, 59))

# Scanner host that the change calendar may name as the "performed by" actor. Used by
# change_matcher only as a HINT when a calendar row says "scanner" without listing an IP.
APPROVED_SCANNER_IPS: Tuple[str, ...] = ("10.10.9.50",)

# Log sources that do not exist (file 20). Anything that would need these must be
# answered "Not enough evidence in the logs" and cite file 20.
MISSING_LOG_SOURCES: Tuple[str, ...] = (
    "SRV-FS01 audit log",
    "SRV-DB01 query log",
    "web proxy log",
    "EDR logs",
)


# --------------------------------------------------------------------------- #
# File registry
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FileSpec:
    number: int
    filename: str
    key: str                                   # short alias, e.g. "vpn_auth_log"
    category: str                              # rules | table | runbook | log | alerts | coverage
    time_mode: LogTimeMode = LogTimeMode.NONE
    expects_code_block: bool = False           # log files: citations are line numbers
    primary_key_candidates: Tuple[str, ...] = ()  # normalized header names, tried in order
    description: str = ""


def _fs(number, filename, key, category, time_mode=LogTimeMode.NONE,
        code=False, pk=(), desc="") -> FileSpec:
    return FileSpec(number, filename, key, category, time_mode, code, tuple(pk), desc)


FILE_SPECS: Tuple[FileSpec, ...] = (
    _fs(1, "01_company_security_rules.md", "security_rules", "rules",
        desc="11-section report format, time rule, evidence labels, citation rules"),
    _fs(2, "02_asset_inventory.md", "asset_inventory", "table",
        pk=("asset tag", "asset id", "tag"),
        desc="Asset tag, hostname, IP, criticality, owner"),
    _fs(3, "03_severity_matrix.md", "severity_matrix", "table",
        pk=("incident type", "type", "category"),
        desc="Incident type x asset criticality -> P1..P4"),
    _fs(4, "04_escalation_and_contacts.md", "escalation", "table",
        pk=("role", "contact role", "contact"),
        desc="Contacts and notification deadlines"),
    _fs(5, "05_change_calendar.md", "change_calendar", "table",
        pk=("change id", "chg id", "id"),
        desc="Approved changes; approved actions are NOT incidents"),
    _fs(6, "06_runbook_phishing.md", "runbook_phishing", "runbook"),
    _fs(7, "07_runbook_credential_compromise.md", "runbook_credential", "runbook"),
    _fs(8, "08_runbook_web_attack.md", "runbook_web", "runbook"),
    _fs(9, "09_runbook_data_exfiltration.md", "runbook_exfil", "runbook"),
    _fs(10, "10_runbook_scanning_recon.md", "runbook_scanning", "runbook"),
    _fs(11, "11_vpn_auth_log.md", "vpn_auth_log", "log", LogTimeMode.UTC_Z, True,
        desc="VPN authentication events (UTC, ISO with Z)"),
    _fs(12, "12_windows_dc_auth_log.md", "dc_auth_log", "log", LogTimeMode.UTC_Z, True,
        desc="Windows DC auth events (UTC, only 03:00-19:00 UTC covered)"),
    _fs(13, "13_web_server_log.md", "web_server_log", "log", LogTimeMode.OFFSET_IN_LINE, True,
        desc="Web server access log (local time + offset on every line)"),
    _fs(14, "14_firewall_perimeter_log.md", "fw_perimeter_log", "log", LogTimeMode.UTC_Z, True,
        desc="Perimeter firewall (UTC, logged at session start)"),
    _fs(15, "15_firewall_internal_log.md", "fw_internal_log", "log", LogTimeMode.PKT_NAIVE, True,
        desc="Internal firewall (PKT, no zone mark, logged at close, duration in s)"),
    _fs(16, "16_email_gateway_log.md", "email_gateway_log", "log", LogTimeMode.PKT_NAIVE, True,
        desc="Email gateway (PKT)"),
    _fs(17, "17_ids_alert_summary.md", "ids_alerts", "alerts", LogTimeMode.UTC_Z,
        pk=("alert id", "id"),
        desc="IDS alert summary ALT-9001..ALT-9008 (UTC)"),
    _fs(18, "18_user_directory.md", "user_directory", "table",
        pk=("username", "user name", "user", "samaccountname"),
        desc="User profiles, usernames, emails"),
    _fs(19, "19_dhcp_lease_log.md", "dhcp_lease_log", "log", LogTimeMode.OFFSET_IN_LINE, True,
        desc="DHCP leases (local time + offset)"),
    _fs(20, "20_log_source_coverage.md", "log_coverage", "coverage",
        pk=("log source", "source", "system", "host"),
        desc="Which log sources exist / are missing"),
)

FILE_BY_NAME: Dict[str, FileSpec] = {s.filename: s for s in FILE_SPECS}
FILE_BY_KEY: Dict[str, FileSpec] = {s.key: s for s in FILE_SPECS}
FILE_BY_NUMBER: Dict[int, FileSpec] = {s.number: s for s in FILE_SPECS}

RUNBOOK_FILES: Tuple[str, ...] = tuple(s.filename for s in FILE_SPECS if s.category == "runbook")
LOG_FILES: Tuple[str, ...] = tuple(s.filename for s in FILE_SPECS if s.category == "log")

# Row-ID shapes, used to sanity-check citations and as a fallback when a table
# cannot be parsed. Deliberately permissive on the tail digits.
ID_PATTERNS: Dict[str, re.Pattern] = {
    "asset": re.compile(r"\bA-\d{4}\b"),
    "change": re.compile(r"\bCHG-\d{4}-\d{4}-\d{2}\b"),
    "alert": re.compile(r"\bALT-\d{4}\b"),
}


# --------------------------------------------------------------------------- #
# LLM configuration (Gemini 2.5 Flash / Groq / OpenAI via env)
# --------------------------------------------------------------------------- #
SUPPORTED_PROVIDERS: Tuple[str, ...] = ("gemini", "groq", "openai")

DEFAULT_MODELS: Dict[str, str] = {
    "gemini": "gemini-3.5-flash",
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
}

# Each provider may expose its key under more than one conventional env name.
API_KEY_ENV_VARS: Dict[str, Tuple[str, ...]] = {
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "groq": ("GROQ_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "gemini"
    model: str = DEFAULT_MODELS["gemini"]
    api_key: Optional[str] = field(default=None, repr=False)  # repr=False: never log keys
    temperature: float = 0.0          # deterministic output helps the automated leaderboard
    max_output_tokens: int = 8192
    timeout_s: float = 120.0
    max_retries: int = 5              # for 429 / 5xx / timeouts
    backoff_base_s: float = 2.0       # delay = base * 2**attempt (+ jitter in the client)
    backoff_max_s: float = 60.0
    fallback_provider: Optional[str] = None   # optional second provider if the first keeps failing

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def validate(self) -> None:
        if self.provider not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported LLM_PROVIDER '{self.provider}'. Choose one of {SUPPORTED_PROVIDERS}."
            )
        if not self.api_key:
            names = " or ".join(API_KEY_ENV_VARS[self.provider])
            raise RuntimeError(f"Missing API key for provider '{self.provider}': set {names}.")


def _read_api_key(provider: str) -> Optional[str]:
    for name in API_KEY_ENV_VARS.get(provider, ()):
        val = os.getenv(name, "").strip()
        if val:
            return val
    return None


def load_llm_config(provider: Optional[str] = None) -> LLMConfig:
    """
    Build an LLMConfig from the environment.

      LLM_PROVIDER           gemini | groq | openai        (default: gemini)
      LLM_MODEL              overrides the provider default
      LLM_FALLBACK_PROVIDER  optional second provider
      LLM_TEMPERATURE / LLM_MAX_OUTPUT_TOKENS / LLM_TIMEOUT_S
      LLM_MAX_RETRIES / LLM_BACKOFF_BASE_S / LLM_BACKOFF_MAX_S
      <PROVIDER>_API_KEY     see API_KEY_ENV_VARS
    """
    prov = (provider or os.getenv("LLM_PROVIDER", "gemini")).strip().lower()
    if prov not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported LLM_PROVIDER '{prov}'. Choose one of {SUPPORTED_PROVIDERS}.")

    # LLM_MODEL only applies to the primary provider, not to an explicit override
    # (otherwise a Gemini model name would be sent to Groq during fallback).
    model = DEFAULT_MODELS[prov]
    if provider is None:
        model = os.getenv("LLM_MODEL", "").strip() or model

    fb = os.getenv("LLM_FALLBACK_PROVIDER", "").strip().lower() or None
    if fb and fb not in SUPPORTED_PROVIDERS:
        fb = None

    return LLMConfig(
        provider=prov,
        model=model,
        api_key=_read_api_key(prov),
        temperature=_env_float("LLM_TEMPERATURE", 0.0),
        max_output_tokens=_env_int("LLM_MAX_OUTPUT_TOKENS", 8192),
        timeout_s=_env_float("LLM_TIMEOUT_S", 120.0),
        max_retries=_env_int("LLM_MAX_RETRIES", 5),
        backoff_base_s=_env_float("LLM_BACKOFF_BASE_S", 2.0),
        backoff_max_s=_env_float("LLM_BACKOFF_MAX_S", 60.0),
        fallback_provider=fb if fb != prov else None,
    )
