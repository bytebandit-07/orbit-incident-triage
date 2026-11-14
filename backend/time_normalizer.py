"""
backend/time_normalizer.py
==========================
Deterministic time handling. The LLM never does timezone arithmetic.

Company rule: internal clock is PKT (UTC+05:00); every timestamp in the report is UTC.

Per-source behaviour (driven by `config.LogTimeMode`):

  UTC_Z           files 11, 12, 14, 17   ISO-8601 with Z. A missing zone is assumed UTC.
  PKT_NAIVE       files 15, 16           no zone mark -> MUST be read as PKT, then shifted -5h.
  OFFSET_IN_LINE  files 13, 19           each line carries its own offset (+05:00, +0500 ...);
                                         a line WITHOUT one is an error, we refuse to guess.

Rules that hold everywhere:
  * An explicit zone/offset in the text always wins over the file's default.
  * Naive datetimes never leak out: every public function returns timezone-aware values.
  * File 15 logs sessions at CLOSE time with a duration in seconds, so
        session start = close time - duration
    and the internal firewall has a known logging gap (reboot) that is exposed here.

Stdlib only.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from typing import Iterator, List, Optional, Pattern, Tuple, Union

from . import config
from .config import LogTimeMode, PKT_TZ, UTC_TZ

log = logging.getLogger(__name__)

INTERNAL_FW_FILE = "15_firewall_internal_log.md"


# =========================================================================== #
# Errors
# =========================================================================== #
class TimeParseError(ValueError):
    """A timestamp was found but cannot be interpreted safely."""


class NoTimestampError(TimeParseError):
    """The text contains no recognizable timestamp at all (e.g. a header/comment line)."""


# =========================================================================== #
# Zone helpers
# =========================================================================== #
def tz_from_text(token: str) -> tzinfo:
    """'Z'/'UTC'/'GMT' -> UTC, 'PKT' -> PKT, '+05:00' / '+0500' / '+05' / '-0330' -> fixed offset."""
    t = token.strip()
    up = t.upper()
    if up in ("Z", "UTC", "GMT"):
        return UTC_TZ
    if up == "PKT":
        return PKT_TZ
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})?", t)
    if not m:
        raise TimeParseError(f"Unrecognized zone token {token!r}")
    sign, hh, mm = m.group(1), int(m.group(2)), int(m.group(3) or 0)
    if hh > 14 or mm > 59:
        raise TimeParseError(f"Implausible UTC offset {token!r}")
    delta = timedelta(hours=hh, minutes=mm)
    if sign == "-":
        delta = -delta
    if delta == timedelta(0):
        return UTC_TZ
    if delta == config.PKT_OFFSET:
        return PKT_TZ
    return timezone(delta)


def _require_aware(dt: datetime, what: str = "datetime") -> datetime:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"{what} must be timezone-aware (got naive {dt!r}); refusing to guess a zone")
    return dt


def to_utc(dt: datetime, assume: Optional[tzinfo] = None) -> datetime:
    """
    Convert to UTC. A naive `dt` is only accepted when `assume` says which zone it is in
    (e.g. PKT_TZ for internal logs); otherwise ValueError, never a silent guess.
    """
    if dt.tzinfo is None or dt.utcoffset() is None:
        if assume is None:
            raise ValueError(f"Naive datetime {dt!r} needs an explicit `assume` zone")
        dt = dt.replace(tzinfo=assume)
    return dt.astimezone(UTC_TZ)


def pkt_to_utc(dt: datetime) -> datetime:
    """PKT wall-clock (naive, or aware in any zone) -> UTC. Naive is interpreted as PKT."""
    return to_utc(dt, assume=PKT_TZ)


def utc_to_pkt(dt: datetime) -> datetime:
    return _require_aware(dt).astimezone(PKT_TZ)


# =========================================================================== #
# Timestamp discovery + parsing
# =========================================================================== #
# ISO-ish: 2026-11-04T08:15:00Z | 2026-11-04 13:15:00 | 2026-11-04T13:15:00+05:00 |
#          2026-11-04 13:15:00 +0500 | 2026-11-04 13:15:00 PKT | 2026/11/04 13:15
_ISO_RE = re.compile(
    r"""
    (?<![\d])(?P<y>\d{4})[-/](?P<mo>\d{2})[-/](?P<d>\d{2})
    [T\ ](?P<h>\d{2}):(?P<mi>\d{2})(?::(?P<s>\d{2})(?:[.,](?P<f>\d{1,9}))?)?
    (?P<tz>
        Z(?![A-Za-z])
      | \ ?(?:UTC|GMT|PKT)(?![A-Za-z])
      | [+-]\d{2}:?\d{2}(?!\d)
      | \ [+-]\d{2}:?\d{2}(?!\d)
      | [+-]\d{2}(?![\d:])
    )?
    """,
    re.X,
)

# Apache/Nginx common-log style: 04/Nov/2026:13:15:00 +0500
_CLF_RE = re.compile(
    r"(?P<d>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:\ (?P<tz>[+-]\d{4}))?"
)
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}


@dataclass(frozen=True)
class ParsedTimestamp:
    utc: datetime                 # always aware, always UTC
    text: str                     # the exact substring that was parsed
    zone_basis: str               # 'explicit' | 'assumed_utc' | 'assumed_pkt'
    start: int                    # character offset in the source text
    end: int

    def __str__(self) -> str:
        return format_utc(self.utc)


def _naive_from_groups(y, mo, d, h, mi, s, f=None) -> datetime:
    micro = int((f or "0").ljust(6, "0")[:6])
    try:
        return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0), micro)
    except ValueError as exc:
        raise TimeParseError(f"Invalid date/time {y}-{mo}-{d} {h}:{mi}:{s}: {exc}") from exc


def _apply_mode(naive: datetime, tz_token: Optional[str], mode: Optional[LogTimeMode],
                text: str) -> Tuple[datetime, str]:
    """Attach a zone to a parsed naive datetime according to explicit token / file mode."""
    if tz_token:
        return naive.replace(tzinfo=tz_from_text(tz_token)).astimezone(UTC_TZ), "explicit"
    if mode == LogTimeMode.UTC_Z:
        return naive.replace(tzinfo=UTC_TZ), "assumed_utc"
    if mode == LogTimeMode.PKT_NAIVE:
        return naive.replace(tzinfo=PKT_TZ).astimezone(UTC_TZ), "assumed_pkt"
    if mode == LogTimeMode.OFFSET_IN_LINE:
        raise TimeParseError(
            f"Timestamp {text!r} has no UTC offset, but this source is supposed to carry one on "
            "every line; refusing to guess its zone"
        )
    raise TimeParseError(f"Timestamp {text!r} has no zone and no source mode was given")


def find_timestamps(text: str, mode: Optional[LogTimeMode] = None) -> List[ParsedTimestamp]:
    """All timestamps in `text`, left to right, converted to UTC under `mode`'s rules."""
    hits: List[Tuple[int, int, datetime, Optional[str], str]] = []
    for m in _ISO_RE.finditer(text):
        naive = _naive_from_groups(m["y"], m["mo"], m["d"], m["h"], m["mi"], m["s"], m["f"])
        hits.append((m.start(), m.end(), naive, (m["tz"] or "").strip() or None, m.group(0)))
    for m in _CLF_RE.finditer(text):
        mon = _MONTHS.get(m["mon"].lower())
        if not mon:
            continue
        naive = _naive_from_groups(m["y"], mon, m["d"], m["h"], m["mi"], m["s"])
        hits.append((m.start(), m.end(), naive, m["tz"], m.group(0)))
    hits.sort(key=lambda h: h[0])

    out: List[ParsedTimestamp] = []
    last_end = -1
    for start, end, naive, tz_token, raw in hits:
        if start < last_end:      # overlapping candidate - keep the earlier one
            continue
        utc, basis = _apply_mode(naive, tz_token, mode, raw)
        out.append(ParsedTimestamp(utc=utc, text=raw, zone_basis=basis, start=start, end=end))
        last_end = end
    return out


def parse_timestamp(text: str, mode: Optional[LogTimeMode] = None, index: int = 0) -> ParsedTimestamp:
    """
    Parse the `index`-th timestamp in `text` (default: the first) to UTC.
    Raises NoTimestampError if there is none, TimeParseError if it is ambiguous/invalid.
    """
    # Fast "is there anything?" check so header/comment lines raise the soft error.
    if not (_ISO_RE.search(text) or _CLF_RE.search(text)):
        raise NoTimestampError(f"No timestamp found in {text[:80]!r}")
    found = find_timestamps(text, mode)
    if not found:
        raise NoTimestampError(f"No timestamp found in {text[:80]!r}")
    try:
        return found[index]
    except IndexError:
        raise NoTimestampError(f"Only {len(found)} timestamp(s) in line; wanted #{index}") from None


def parse_for_file(filename: str, text: str, index: int = 0) -> ParsedTimestamp:
    """Parse using the time mode registered for `filename` in config (e.g. '16_email_gateway_log.md')."""
    spec = config.FILE_BY_NAME.get(filename) or config.FILE_BY_KEY.get(filename)
    if spec is None:
        raise KeyError(f"Unknown data file {filename!r}")
    return parse_timestamp(text, spec.time_mode, index)


# =========================================================================== #
# Formatting
# =========================================================================== #
def format_utc(dt: datetime) -> str:
    """Report format for a UTC instant (aware input of any zone is converted first)."""
    return _require_aware(dt).astimezone(UTC_TZ).strftime(config.UTC_OUTPUT_FORMAT)


def format_pkt(dt: datetime) -> str:
    """Debug/analyst format: '2026-11-04 13:15:00 PKT'."""
    return _require_aware(dt).astimezone(PKT_TZ).strftime("%Y-%m-%d %H:%M:%S PKT")


def format_utc_range(start: datetime, end: datetime) -> str:
    return f"{format_utc(start)} to {format_utc(end)}"


# =========================================================================== #
# Time-delta helpers
# =========================================================================== #
def seconds_between(a: datetime, b: datetime) -> float:
    """Signed seconds from a to b (positive when b is later). Both must be aware."""
    return (_require_aware(b, "b") - _require_aware(a, "a")).total_seconds()


def minutes_between(a: datetime, b: datetime) -> float:
    return seconds_between(a, b) / 60.0


def humanize_delta(delta: Union[timedelta, float, int]) -> str:
    """90061 -> '1d 1h 01m 01s'. Negative values get a leading '-'."""
    secs = int(delta.total_seconds() if isinstance(delta, timedelta) else delta)
    sign = "-" if secs < 0 else ""
    secs = abs(secs)
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if d or h:
        parts.append(f"{h}h")
    if d or h or m:
        parts.append(f"{m:02d}m" if (d or h) else f"{m}m")
    parts.append(f"{s:02d}s" if (d or h or m) else f"{s}s")
    return sign + " ".join(parts)


def add_minutes(dt: datetime, minutes: float) -> datetime:
    """Notification-deadline helper: detection time + SLA minutes (stays aware)."""
    return _require_aware(dt) + timedelta(minutes=minutes)


def within_window(ts: datetime, start: datetime, end: datetime,
                  tolerance: timedelta = timedelta(0), inclusive: bool = True) -> bool:
    """Is `ts` inside [start, end] (optionally widened by `tolerance` on both sides)?"""
    _require_aware(ts), _require_aware(start), _require_aware(end)
    lo, hi = start - tolerance, end + tolerance
    return (lo <= ts <= hi) if inclusive else (lo < ts < hi)


def windows_overlap(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> bool:
    """Closed-interval overlap test (touching endpoints count as overlap)."""
    for d in (a_start, a_end, b_start, b_end):
        _require_aware(d)
    return a_start <= b_end and b_start <= a_end


# =========================================================================== #
# Free-form window parsing (used for the change calendar)
# =========================================================================== #
_W_DT = re.compile(
    r"(?<!\d)(?P<y>\d{4})[-/](?P<mo>\d{2})[-/](?P<d>\d{2})[T\s]+(?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?(?![\d:])"
)
_W_DATE = re.compile(r"(?<!\d)(?P<y>\d{4})[-/](?P<mo>\d{2})[-/](?P<d>\d{2})(?!\d)")
_W_TIME = re.compile(r"(?<![\d:])(?P<h>\d{1,2}):(?P<mi>\d{2})(?::(?P<s>\d{2}))?(?![\d:])")
_W_ZONE = re.compile(r"(?<![A-Za-z])(UTC|GMT|PKT)(?![A-Za-z])", re.I)


def _mk_local(y, mo, d, h, mi, s, tz: tzinfo) -> datetime:
    """Build an aware datetime; '24:00' means midnight of the next day."""
    h, mi = int(h), int(mi)
    bump = timedelta(0)
    if h == 24 and mi == 0:
        h, bump = 0, timedelta(days=1)
    try:
        return datetime(int(y), int(mo), int(d), h, mi, int(s or 0), tzinfo=tz) + bump
    except ValueError as exc:
        raise TimeParseError(f"Invalid window component: {exc}") from exc


def parse_time_window(text: str, *, default_date: Optional[date] = None,
                      default_tz: tzinfo = PKT_TZ) -> Tuple[datetime, datetime]:
    """
    Parse a human-written window into (start_utc, end_utc). Accepts, among others:

        '2026-11-04 14:00 - 16:00'            '2026-11-04 14:00 to 2026-11-04 16:30 PKT'
        '14:00-16:00'  (needs default_date)    '2026-11-04 22:00 - 02:00'  (overnight -> next day)
        '2026-11-04'                           (whole day)     '2026-11-04 to 2026-11-05'

    An explicit UTC/GMT/PKT word in the text overrides `default_tz` (the calendar is kept in
    PKT, so that is the default). Offsets like '+05:00' inside window text are NOT parsed here,
    because '14:00-16:00' is indistinguishable from an offset.
    """
    zm = _W_ZONE.search(text)
    tz: tzinfo = tz_from_text(zm.group(1)) if zm else default_tz

    dts = list(_W_DT.finditer(text))
    if len(dts) >= 2:
        s = _mk_local(*(dts[0][k] for k in ("y", "mo", "d", "h", "mi", "s")), tz)
        e = _mk_local(*(dts[1][k] for k in ("y", "mo", "d", "h", "mi", "s")), tz)
        if e < s:
            raise TimeParseError(f"Window end precedes start in {text!r}")
        return s.astimezone(UTC_TZ), e.astimezone(UTC_TZ)

    if len(dts) == 1:
        d0 = dts[0]
        s = _mk_local(*(d0[k] for k in ("y", "mo", "d", "h", "mi", "s")), tz)
        t2 = _W_TIME.search(text, d0.end())
        if not t2:
            raise TimeParseError(f"Window has a start but no end time: {text!r}")
        e = _mk_local(d0["y"], d0["mo"], d0["d"], t2["h"], t2["mi"], t2["s"], tz)
        if e < s:                       # overnight window
            e += timedelta(days=1)
        return s.astimezone(UTC_TZ), e.astimezone(UTC_TZ)

    # No full date-times: mask nothing (there are none) and look for dates + loose times.
    dates = list(_W_DATE.finditer(text))
    times = list(_W_TIME.finditer(text))
    if len(times) >= 2:
        if dates:
            y, mo, d = (dates[0][k] for k in ("y", "mo", "d"))
        elif default_date is not None:
            y, mo, d = default_date.year, default_date.month, default_date.day
        else:
            raise TimeParseError(f"Window {text!r} has times but no date and no default_date")
        s = _mk_local(y, mo, d, times[0]["h"], times[0]["mi"], times[0]["s"], tz)
        e = _mk_local(y, mo, d, times[1]["h"], times[1]["mi"], times[1]["s"], tz)
        if e < s:
            e += timedelta(days=1)
        return s.astimezone(UTC_TZ), e.astimezone(UTC_TZ)

    if not times and dates:             # whole-day window(s)
        first, last = dates[0], dates[-1]
        s = _mk_local(first["y"], first["mo"], first["d"], 0, 0, 0, tz)
        e = _mk_local(last["y"], last["mo"], last["d"], 23, 59, 59, tz)
        if e < s:
            raise TimeParseError(f"Window end precedes start in {text!r}")
        return s.astimezone(UTC_TZ), e.astimezone(UTC_TZ)

    raise TimeParseError(f"Cannot interpret time window {text!r}")


def parse_datetime_loose(text: str, *, default_date: Optional[date] = None,
                         default_tz: tzinfo = PKT_TZ) -> datetime:
    """
    One instant from a calendar cell: a full date-time, or a bare 'HH:MM' combined with
    `default_date`. Zone words (UTC/GMT/PKT) override `default_tz`. Returns UTC.
    """
    zm = _W_ZONE.search(text)
    tz: tzinfo = tz_from_text(zm.group(1)) if zm else default_tz
    m = _W_DT.search(text)
    if m:
        return _mk_local(*(m[k] for k in ("y", "mo", "d", "h", "mi", "s")), tz).astimezone(UTC_TZ)
    t = _W_TIME.search(text)
    if t:
        dm = _W_DATE.search(text)
        if dm:
            y, mo, d = dm["y"], dm["mo"], dm["d"]
        elif default_date is not None:
            y, mo, d = default_date.year, default_date.month, default_date.day
        else:
            raise TimeParseError(f"Time {text!r} has no date and no default_date")
        return _mk_local(y, mo, d, t["h"], t["mi"], t["s"], tz).astimezone(UTC_TZ)
    raise TimeParseError(f"No date/time in {text!r}")


# =========================================================================== #
# File 15: internal firewall (PKT, logged at session CLOSE, duration in seconds)
# =========================================================================== #
_DURATION_LABELED = re.compile(
    r"\b(?:duration|dur|elapsed|session[_ ]?time)(?:[_ ]?(?:s|sec|secs|seconds))?\s*[=:]\s*(\d+)\b",
    re.I,
)
_DURATION_UNIT = re.compile(r"(?<![\w.:])(\d+)\s?(?:s|sec|secs|seconds)\b", re.I)


def parse_duration_seconds(line: str, pattern: Optional[Pattern[str]] = None) -> int:
    """
    Find the session duration (seconds) in a file-15 line.
      1. `pattern` if supplied (first capture group = seconds) - use this if the real format differs
      2. a labelled field:  duration=1832 | dur: 1832 | duration_s=1832 | elapsed=1832
      3. exactly ONE bare number with a seconds unit ('1832s', '1832 sec')
    Anything else raises: a wrong duration would silently shift the session start.
    """
    if pattern is not None:
        m = pattern.search(line)
        if not m:
            raise TimeParseError(f"Custom duration pattern did not match: {line[:100]!r}")
        return int(m.group(1))
    m = _DURATION_LABELED.search(line)
    if m:
        return int(m.group(1))
    unit_hits = _DURATION_UNIT.findall(line)
    if len(unit_hits) == 1:
        return int(unit_hits[0])
    raise TimeParseError(
        f"Cannot determine session duration ({len(unit_hits)} candidates) in {line[:100]!r}; "
        "pass duration_s= or duration_pattern="
    )


@dataclass(frozen=True)
class SessionWindow:
    start_utc: datetime
    end_utc: datetime              # == close time
    duration_s: int
    close_text: str                # original close timestamp text (PKT)
    spans_logging_gap: bool        # session overlapped the internal FW reboot window

    @property
    def start_text(self) -> str:
        return format_utc(self.start_utc)

    @property
    def end_text(self) -> str:
        return format_utc(self.end_utc)


def firewall_internal_session(line: str, *, duration_s: Optional[int] = None,
                              duration_pattern: Optional[Pattern[str]] = None) -> SessionWindow:
    """
    File-15 line -> session window in UTC.
        close (PKT, naive) -> UTC, then start = close - duration.
    Example: close 2026-11-04 13:10:00 PKT, duration 600 s
             -> end 08:10:00Z, start 08:00:00Z.
    """
    close = parse_timestamp(line, LogTimeMode.PKT_NAIVE)
    secs = duration_s if duration_s is not None else parse_duration_seconds(line, duration_pattern)
    if secs < 0:
        raise TimeParseError(f"Negative duration {secs}")
    start = close.utc - timedelta(seconds=secs)
    return SessionWindow(start, close.utc, secs, close.text,
                         overlaps_internal_fw_gap(start, close.utc))


# =========================================================================== #
# Known coverage gaps
# =========================================================================== #
def internal_fw_gap_for(day_pkt: date) -> Tuple[datetime, datetime]:
    """The internal-firewall reboot window on a given PKT calendar day, as UTC instants."""
    a, b = config.FW_INTERNAL_REBOOT_PKT
    s = datetime.combine(day_pkt, a, tzinfo=PKT_TZ).astimezone(UTC_TZ)
    e = datetime.combine(day_pkt, b, tzinfo=PKT_TZ).astimezone(UTC_TZ)
    return s, e


def overlaps_internal_fw_gap(start: datetime, end: Optional[datetime] = None) -> bool:
    """
    True if [start, end] touches 11:32:00-12:28:59 PKT on any PKT day it covers.
    Nothing was logged by the internal firewall in that window, so silence there proves nothing.
    """
    end = end or start
    d0, d1 = utc_to_pkt(start).date(), utc_to_pkt(end).date()
    day = d0
    while day <= d1:
        gs, ge = internal_fw_gap_for(day)
        if windows_overlap(start, end, gs, ge):
            return True
        day += timedelta(days=1)
    return False


def dc_log_covers(dt: datetime) -> bool:
    """
    File 12 only covers 03:00-19:00 UTC (time-of-day, any date). Outside that, an empty
    DC log is a coverage gap, NOT evidence that nothing happened.
    """
    t = _require_aware(dt).astimezone(UTC_TZ).time()
    lo, hi = config.DC_LOG_COVERAGE_UTC
    return lo <= t <= hi


# =========================================================================== #
# Whole-log normalization
# =========================================================================== #
@dataclass(frozen=True)
class LogEvent:
    source_file: str
    line_no: int                    # 1-indexed inside the code fence (citation-ready)
    raw_line: str
    utc: Optional[datetime]         # event time (file 15: session CLOSE time)
    start_utc: Optional[datetime]   # == utc except file 15 (close - duration)
    end_utc: Optional[datetime]
    zone_basis: str = ""            # explicit | assumed_utc | assumed_pkt
    in_logging_gap: bool = False    # DC outside 03-19Z, or internal FW reboot window
    error: Optional[str] = None     # set when a timestamp was present but unusable

    @property
    def citation(self) -> str:
        return f"{self.source_file}:{self.line_no}"

    @property
    def utc_text(self) -> str:
        return format_utc(self.utc) if self.utc else ""


def normalize_line(source_file: str, line_no: int, line: str) -> Optional[LogEvent]:
    """
    One raw log line -> LogEvent, or None if the line has no timestamp (blank/header/comment).
    A line that HAS a timestamp we cannot trust yields an event with `error` set, so problems
    are visible rather than dropped.
    """
    spec = config.FILE_BY_NAME[source_file]
    mode = spec.time_mode
    if not line.strip():
        return None
    try:
        if source_file == INTERNAL_FW_FILE:
            parse_timestamp(line, mode)               # raises NoTimestampError if none
            try:
                sw = firewall_internal_session(line)
            except NoTimestampError:
                raise
            except TimeParseError as exc:
                close = parse_timestamp(line, mode)
                return LogEvent(source_file, line_no, line, close.utc, None, close.utc,
                                close.zone_basis, overlaps_internal_fw_gap(close.utc),
                                error=f"start time unknown: {exc}")
            return LogEvent(source_file, line_no, line, sw.end_utc, sw.start_utc, sw.end_utc,
                            "assumed_pkt", sw.spans_logging_gap)
        ts = parse_timestamp(line, mode)
        gap = (not dc_log_covers(ts.utc)) if spec.filename == "12_windows_dc_auth_log.md" else False
        return LogEvent(source_file, line_no, line, ts.utc, ts.utc, ts.utc, ts.zone_basis, gap)
    except NoTimestampError:
        return None
    except TimeParseError as exc:
        return LogEvent(source_file, line_no, line, None, None, None, error=str(exc))


def iter_events(loader, ref) -> Iterator[LogEvent]:
    """Normalize every timestamped line of a log file (`loader` is a data_loader.DataLoader)."""
    spec = loader.resolve(ref)
    for n, line in loader.iter_log_lines(spec.filename):
        ev = normalize_line(spec.filename, n, line)
        if ev is not None:
            yield ev


def event_at(loader, ref, line_no: int) -> LogEvent:
    """Normalize one specific cited line; raises if the line has no timestamp."""
    spec = loader.resolve(ref)
    line = loader.get_log_line(spec.filename, line_no)
    ev = normalize_line(spec.filename, line_no, line)
    if ev is None:
        raise NoTimestampError(f"{spec.filename}:{line_no} has no timestamp")
    return ev
