"""
backend/change_matcher.py
=========================
Deterministic check: "is this suspicious activity actually an approved change?"

Rule from the brief: approved actions are NOT incidents. An activity is harmless only when
ALL of these hold against one row of 05_change_calendar.md:

    1. TARGET     the activity's target (IP / subnet / hostname / asset tag) is inside the
                  change's scope           (every target must be covered, not just one)
    2. PERFORMER  the activity's actor (username, email or source IP, e.g. scanner 10.10.9.50)
                  is the person/system the change names
    3. TIME       the activity falls inside the approved window (calendar is PKT -> UTC)
    4. STATUS     the change is not cancelled / rejected / pending / withdrawn

`match()` returns the matching `ChangeMatch` (carrying the Change ID) or None.
Partial matches are the dangerous case (right host + right time, wrong person), so
`near_misses()` exposes them with per-criterion reasons instead of hiding them.

The calendar's column layout is discovered from its headers, and hostnames/IPs/tags/users are
cross-resolved through 02_asset_inventory.md and 18_user_directory.md, so "A-1004" in the
calendar still matches traffic to that asset's IP.

Stdlib only. Every helper is a pure function so it can be unit tested directly.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, tzinfo
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple, Union

from . import config
from .config import PKT_TZ, UTC_TZ
from .data_loader import DataLoader, TableRow, get_loader
from .time_normalizer import (
    TimeParseError, humanize_delta, parse_datetime_loose, parse_time_window,
    format_utc, windows_overlap,
)

log = logging.getLogger(__name__)

CALENDAR_FILE = "05_change_calendar.md"
ASSET_FILE = "02_asset_inventory.md"
USER_FILE = "18_user_directory.md"

_NEGATIVE_STATUS = re.compile(
    r"\b(cancel+ed|cancelled|rejected|denied|declined|withdrawn|pending|postponed|rolled[\s-]?back|draft)\b",
    re.I,
)

# --------------------------------------------------------------------------- #
# Token extraction / normalization
# --------------------------------------------------------------------------- #
_CIDR_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})(?!\d)")
_IP_RANGE_FULL_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})\s*(?:-|–|—|to)\s*(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_IP_RANGE_SHORT_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})\s*(?:-|–|—)\s*(\d{1,3})(?![\d.])")
_WILDCARD_RE = re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3})\.\*")
_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TAG_RE = re.compile(r"\bA-\d{3,5}\b", re.I)
# Hostname-ish: needs a hyphen, dot or digit so plain words ("firewall", "the") are not hosts.
_HOST_RE = re.compile(r"(?<![\w.\-])([A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)+|[A-Za-z]{2,}\d+[A-Za-z0-9\-]*)(?![\w\-])")
_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]*")
_STOPWORDS = frozenset({"and", "the", "team", "ops", "for", "via", "from", "with", "by", "of", "all", "any", "n/a", "na"})


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def norm_id(s: str) -> str:
    """
    Canonical identifier: lowercase, trimmed, markdown noise and trailing dot removed.
    Deliberately keeps dots: 'ali.khan' is a username, not a hostname with a domain.
    """
    return (s or "").strip().strip("`*_").strip().rstrip(".").lower()


def short_host(n: str) -> str:
    """'srv-web01.orbit.local' -> 'srv-web01'. IPs, CIDRs and e-mails are returned unchanged."""
    if not n or is_ip(n) or "/" in n or "@" in n or "." not in n:
        return n
    return n.split(".")[0]


def _local_part(email: str) -> str:
    return email.split("@", 1)[0].lower()


def _split_values(cell: str) -> List[str]:
    """Split a multi-value cell on , ; / newline <br> ' and ' '|'."""
    return [p.strip() for p in re.split(r"<br\s*/?>|[;,\n|]|\s+and\s+|\s+&\s+", cell or "") if p.strip()]


# --------------------------------------------------------------------------- #
# Identity resolvers (asset inventory / user directory)
# --------------------------------------------------------------------------- #
class _AliasIndex:
    """identifier -> frozenset of every identifier of the same entity (host, IP, tag / user, email, name)."""

    def __init__(self) -> None:
        self._by_id: Dict[str, FrozenSet[str]] = {}

    def add_entity(self, ids: Iterable[str]) -> None:
        group = frozenset(i for i in (norm_id(x) for x in ids) if i)
        for i in group:
            self._by_id[i] = self._by_id.get(i, frozenset()) | group

    def aliases(self, token: str) -> FrozenSet[str]:
        n = norm_id(token)
        return self._by_id.get(n, frozenset()) | ({n} if n else frozenset())

    def aliases_exact(self, token: str) -> FrozenSet[str]:
        """Alias lookup with no hostname-label fallback (safe for usernames)."""
        return _AliasIndex.aliases(self, token)

    def __contains__(self, token: str) -> bool:
        return norm_id(token) in self._by_id

    def keys(self) -> Iterable[str]:
        return self._by_id.keys()


class AssetResolver(_AliasIndex):
    """Built from 02_asset_inventory.md: hostname <-> IP <-> asset tag. FQDN == short hostname."""

    def add_entity(self, ids: Iterable[str]) -> None:
        ids = [norm_id(i) for i in ids if i]
        super().add_entity(ids + [short_host(i) for i in ids])

    def aliases(self, token: str) -> FrozenSet[str]:
        n = norm_id(token)
        sh = short_host(n)
        out = self._by_id.get(n, frozenset()) | self._by_id.get(sh, frozenset())
        return out | {x for x in (n, sh) if x}

    @classmethod
    def from_rows(cls, rows: Iterable[TableRow]) -> "AssetResolver":
        r = cls()
        for row in rows:
            ids = [row.key]
            ids += [row.get(c) for c in ("hostname", "host name", "host", "name", "fqdn")]
            ip_cell = " ".join(row.get(c) for c in ("ip", "ip address", "ipv4", "address", "ip addresses"))
            ids += _IP_RE.findall(ip_cell)
            r.add_entity([i for i in ids if i])
        return r

    @classmethod
    def empty(cls) -> "AssetResolver":
        return cls()


class UserResolver(_AliasIndex):
    """Built from 18_user_directory.md: username <-> e-mail <-> e-mail local part <-> full name."""

    def __init__(self) -> None:
        super().__init__()
        self.names: Dict[str, FrozenSet[str]] = {}   # lowercase full name -> aliases

    @classmethod
    def from_rows(cls, rows: Iterable[TableRow]) -> "UserResolver":
        r = cls()
        for row in rows:
            email = row.get("email") or row.get("e-mail") or row.get("mail")
            name = row.get("full name") or row.get("name") or row.get("display name")
            ids = [row.key, email, _local_part(email) if email else "", name]
            r.add_entity([i for i in ids if i])
            if name:
                r.names[re.sub(r"\s+", " ", name.strip().lower())] = r.aliases(row.key)
        return r

    @classmethod
    def empty(cls) -> "UserResolver":
        return cls()


# --------------------------------------------------------------------------- #
# Target scope
# --------------------------------------------------------------------------- #
@dataclass
class Scope:
    networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = field(default_factory=list)
    ranges: List[Tuple[int, int]] = field(default_factory=list)         # inclusive IPv4 int ranges
    names: Set[str] = field(default_factory=set)                          # normalized ids, alias-expanded

    @property
    def empty(self) -> bool:
        return not (self.networks or self.ranges or self.names)


def _ip_ok(s: str) -> bool:
    return is_ip(s)


def build_scope(text: str, assets: Optional[AssetResolver] = None) -> Scope:
    """
    Turn a calendar 'system/target' cell into a Scope. Understands CIDR (10.10.2.0/24),
    wildcards (10.10.2.*), ranges (10.10.2.1-50, 10.10.2.1 - 10.10.2.50), single IPs,
    asset tags (A-1004) and hostnames. Wildcard words like "all" are NOT expanded: scope must
    be explicit or it does not count.
    """
    assets = assets or AssetResolver.empty()
    sc = Scope()
    work = text or ""

    def consume(rx: re.Pattern, handler) -> None:
        nonlocal work
        for m in rx.finditer(work):
            handler(m)
        work = rx.sub(" ", work)

    def h_cidr(m):
        try:
            sc.networks.append(ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False))
        except ValueError:
            log.warning("Bad CIDR in change scope: %s", m.group(0))

    def h_wild(m):
        sc.networks.append(ipaddress.ip_network(f"{m.group(1)}.0/24", strict=False))

    def h_range_full(m):
        if _ip_ok(m.group(1)) and _ip_ok(m.group(2)):
            a, b = int(ipaddress.ip_address(m.group(1))), int(ipaddress.ip_address(m.group(2)))
            sc.ranges.append((min(a, b), max(a, b)))

    def h_range_short(m):
        base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        if _ip_ok(base + str(lo)) and hi <= 255:
            sc.ranges.append((int(ipaddress.ip_address(base + str(lo))), int(ipaddress.ip_address(base + str(hi)))))

    consume(_CIDR_RE, h_cidr)
    consume(_WILDCARD_RE, h_wild)
    consume(_IP_RANGE_FULL_RE, h_range_full)
    consume(_IP_RANGE_SHORT_RE, h_range_short)

    for ip in _IP_RE.findall(work):
        if _ip_ok(ip):
            sc.names |= assets.aliases(ip)
    work_no_ip = _IP_RE.sub(" ", work)
    for tag in _TAG_RE.findall(work_no_ip):
        sc.names |= assets.aliases(tag)
    for host in _HOST_RE.findall(_EMAIL_RE.sub(" ", work_no_ip)):
        sc.names |= assets.aliases(host)
    return sc


def _ip_in_scope(ip_str: str, sc: Scope) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if any(ip in n for n in sc.networks if n.version == ip.version):
        return True
    return ip.version == 4 and any(lo <= int(ip) <= hi for lo, hi in sc.ranges)


def scope_covers(sc: Scope, target: str, assets: Optional[AssetResolver] = None) -> bool:
    """Is a single activity target (IP, CIDR, hostname or asset tag) fully inside `sc`?"""
    assets = assets or AssetResolver.empty()
    t = (target or "").strip()
    if not t or sc.empty:
        return False

    if "/" in t:  # target is itself a subnet: must be wholly inside a scope network/range
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            return False
        if any(net.version == n.version and net.subnet_of(n) for n in sc.networks):
            return True
        if net.version == 4:
            lo, hi = int(net.network_address), int(net.broadcast_address)
            return any(a <= lo and hi <= b for a, b in sc.ranges)
        return False

    for alias in assets.aliases(t):
        if alias in sc.names or _ip_in_scope(alias, sc):
            return True
    return False


def uncovered_targets(sc: Scope, targets: Sequence[str], assets: Optional[AssetResolver] = None) -> List[str]:
    return [t for t in targets if not scope_covers(sc, t, assets)]


# --------------------------------------------------------------------------- #
# Performer matching
# --------------------------------------------------------------------------- #
def performer_tokens(text: str, users: Optional[UserResolver] = None,
                     assets: Optional[AssetResolver] = None) -> Set[str]:
    """Every identifier that a 'performed by' cell could be referring to (alias-expanded)."""
    users = users or UserResolver.empty()
    assets = assets or AssetResolver.empty()
    toks: Set[str] = set()
    low = re.sub(r"\s+", " ", (text or "").lower())

    for em in _EMAIL_RE.findall(text or ""):
        toks |= {em.lower(), _local_part(em)}
        toks |= users.aliases(em)
    for ip in _IP_RE.findall(text or ""):
        if _ip_ok(ip):
            toks |= assets.aliases_exact(ip)
    # Whole values ("Ali Khan", "jdoe (IT Ops)" -> "jdoe"): plain words inside a multi-word
    # name are NOT individual identities, otherwise actor "ali" would match "Ali Khan".
    for part in _split_values(text or ""):
        bare = re.sub(r"\s+", " ", re.sub(r"\(.*?\)", " ", part)).strip().lower()
        if bare and bare not in _STOPWORDS:
            toks.add(norm_id(bare))
            if bare in users:
                toks |= users.aliases(bare)
            if bare in assets:
                toks |= assets.aliases_exact(bare)
    # Identifier-shaped words (svc-backup, scan01, j.doe) or words known to the directories.
    for w in _WORD_RE.findall(text or ""):
        w = w.strip(".-_").lower()
        if len(w) < 3 or w in _STOPWORDS:
            continue
        known = w in users or w in assets
        if known or re.search(r"[-_.\d]", w):
            toks.add(norm_id(w))
            if w in users:
                toks |= users.aliases(w)
            if w in assets:
                toks |= assets.aliases_exact(w)
    for name, aliases in users.names.items():       # multi-word names ("Ali Khan")
        if " " in name and re.search(rf"(?<!\w){re.escape(name)}(?!\w)", low):
            toks |= aliases
    return toks


def actor_aliases(actor: str, users: Optional[UserResolver] = None,
                  assets: Optional[AssetResolver] = None) -> Set[str]:
    users = users or UserResolver.empty()
    assets = assets or AssetResolver.empty()
    a = (actor or "").strip()
    out: Set[str] = set()
    if not a:
        return out
    out |= {norm_id(a)}
    out |= users.aliases(a) | assets.aliases_exact(a)
    if "@" in a:
        out.add(_local_part(a))
    return out


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Activity:
    """The suspected activity under review. All datetimes must be timezone-aware."""
    targets: Tuple[str, ...]
    actors: Tuple[str, ...]
    start_utc: datetime
    end_utc: datetime
    description: str = ""

    @staticmethod
    def create(targets: Union[str, Iterable[str], None], actors: Union[str, Iterable[str], None],
               start: datetime, end: Optional[datetime] = None, description: str = "") -> "Activity":
        def tup(v) -> Tuple[str, ...]:
            if v is None:
                return ()
            if isinstance(v, str):
                return (v,) if v.strip() else ()
            return tuple(x for x in v if x and str(x).strip())

        end = end or start
        for d, nm in ((start, "start"), (end, "end")):
            if d.tzinfo is None or d.utcoffset() is None:
                raise ValueError(f"Activity {nm} must be timezone-aware")
        if end < start:
            raise ValueError("Activity end precedes start")
        return Activity(tup(targets), tup(actors), start.astimezone(UTC_TZ), end.astimezone(UTC_TZ), description)


@dataclass(frozen=True)
class ChangeRecord:
    change_id: str
    title: str
    target_text: str
    performer_text: str
    start_utc: Optional[datetime]
    end_utc: Optional[datetime]
    status_text: str
    status_ok: bool
    warnings: Tuple[str, ...] = ()
    row: Optional[TableRow] = field(default=None, compare=False, repr=False)

    @property
    def citation(self) -> str:
        return f"{CALENDAR_FILE}:{self.change_id}"


@dataclass(frozen=True)
class Criterion:
    ok: bool
    detail: str


@dataclass(frozen=True)
class ChangeMatch:
    record: ChangeRecord
    target: Criterion
    performer: Criterion
    time: Criterion
    status: Criterion

    @property
    def change_id(self) -> str:
        return self.record.change_id

    @property
    def full_match(self) -> bool:
        return self.target.ok and self.performer.ok and self.time.ok and self.status.ok

    @property
    def harmless(self) -> bool:
        """Approved change => close as harmless, citing the Change ID."""
        return self.full_match

    @property
    def score(self) -> int:
        return sum(c.ok for c in (self.target, self.performer, self.time, self.status))

    @property
    def citation(self) -> str:
        return self.record.citation

    def failed(self) -> List[str]:
        return [n for n, c in (("target", self.target), ("performer", self.performer),
                               ("time", self.time), ("status", self.status)) if not c.ok]

    def summary(self) -> str:
        if self.full_match:
            return (f"Matches approved change {self.change_id} (target, performer, window all "
                    f"consistent) - harmless [{self.citation}]")
        return (f"Does NOT match {self.change_id}; failed: {', '.join(self.failed())} - "
                + "; ".join(f"{n}: {c.detail}" for n, c in
                            (("target", self.target), ("performer", self.performer),
                             ("time", self.time), ("status", self.status)) if not c.ok))


# --------------------------------------------------------------------------- #
# Calendar parsing
# --------------------------------------------------------------------------- #
def _tokens(h: str) -> Set[str]:
    return set(re.sub(r"[^a-z0-9]+", " ", h.casefold()).split())


def _find_col(headers: Sequence[str], needles: Sequence[str], exclude: Sequence[str] = ()) -> Optional[str]:
    """First header matching a needle (needles are tried in priority order; single words match whole tokens)."""
    for needle in needles:
        for h in headers:
            if h in exclude:
                continue
            hn = re.sub(r"[^a-z0-9]+", " ", h.casefold()).strip()
            if (" " in needle and needle in hn) or (" " not in needle and needle in _tokens(h)):
                return h
    return None


def _header_tz(header: Optional[str]) -> tzinfo:
    return UTC_TZ if header and "utc" in _tokens(header) else PKT_TZ


def parse_change_row(row: TableRow, headers: Sequence[str], key_header: str) -> ChangeRecord:
    """One calendar row -> ChangeRecord. Never raises; unparseable windows become warnings."""
    warns: List[str] = []
    ex = (key_header,)
    c_title = _find_col(headers, ("title", "description", "summary", "activity", "purpose", "change"), ex)
    c_target = _find_col(headers, ("system", "target", "affected", "asset", "host", "scope", "subnet", "ip"), ex)
    c_perf = _find_col(headers, ("performed by", "performer", "executed", "executor", "implementer",
                                 "engineer", "operator", "requested by", "requester", "scanner",
                                 "account", "user", "who", "owner"), ex)
    c_start = _find_col(headers, ("start", "begin", "from"), ex)
    c_end = _find_col(headers, ("end", "finish", "until", "to"), ex)
    c_win = _find_col(headers, ("window", "schedule", "when", "time", "maintenance"), ex)
    c_date = _find_col(headers, ("date", "day"), ex)
    c_status = _find_col(headers, ("status", "state", "approval", "approved"), ex)

    start = end = None
    default_date: Optional[date] = None
    if c_date and row.data.get(c_date):
        try:
            dm = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})", row.data[c_date])
            if dm:
                default_date = date(int(dm[1]), int(dm[2]), int(dm[3]))
        except ValueError:
            warns.append(f"bad date cell {row.data[c_date]!r}")

    try:
        if c_start and c_end and c_start != c_end:
            s_txt, e_txt = row.data.get(c_start, ""), row.data.get(c_end, "")
            start = parse_datetime_loose(s_txt, default_date=default_date, default_tz=_header_tz(c_start))
            end = parse_datetime_loose(e_txt, default_date=default_date, default_tz=_header_tz(c_end))
            if end < start:                          # bare times across midnight
                end += timedelta(days=1)
        elif c_win:
            start, end = parse_time_window(row.data.get(c_win, ""), default_date=default_date,
                                           default_tz=_header_tz(c_win))
        elif c_date:
            start, end = parse_time_window(row.data.get(c_date, ""), default_date=default_date)
        else:
            blob = " ".join(v for k, v in row.data.items() if k != key_header)
            start, end = parse_time_window(blob, default_date=default_date)
            warns.append("no window column found; parsed window from the whole row")
    except TimeParseError as exc:
        warns.append(f"window unparseable: {exc}")
        start = end = None

    status_text = row.data.get(c_status, "") if c_status else ""
    status_ok = not _NEGATIVE_STATUS.search(status_text)
    return ChangeRecord(
        change_id=row.key,
        title=row.data.get(c_title, "") if c_title else "",
        target_text=row.data.get(c_target, "") if c_target else "",
        performer_text=row.data.get(c_perf, "") if c_perf else "",
        start_utc=start, end_utc=end, status_text=status_text, status_ok=status_ok,
        warnings=tuple(warns), row=row,
    )


def parse_change_calendar(loader: DataLoader) -> List[ChangeRecord]:
    """Parse every row of every table in 05_change_calendar.md."""
    records: List[ChangeRecord] = []
    for table in loader.get_tables(CALENDAR_FILE):
        for row in table.rows:
            if not row.key:
                continue
            records.append(parse_change_row(row, table.headers, table.key_column))
    for r in records:
        for w in r.warnings:
            log.warning("%s: %s", r.change_id, w)
    return records


# --------------------------------------------------------------------------- #
# Matcher
# --------------------------------------------------------------------------- #
class ChangeMatcher:
    """
    Usage:
        matcher = ChangeMatcher.from_loader(get_loader())
        act = Activity.create(targets=["10.10.2.15"], actors=["10.10.9.50"], start=dt1, end=dt2)
        hit = matcher.match(act)            # ChangeMatch | None
        if hit: hit.change_id, hit.harmless, hit.citation
        matcher.near_misses(act)            # right place/time but wrong person, etc.
    """

    def __init__(self, records: Sequence[ChangeRecord], assets: Optional[AssetResolver] = None,
                 users: Optional[UserResolver] = None,
                 scanner_ips: Optional[Iterable[str]] = None, tolerance_s: int = 0,
                 require_all_targets: bool = True):
        self.records = list(records)
        self.assets = assets or AssetResolver.empty()
        self.users = users or UserResolver.empty()
        self.scanner_ips = frozenset(scanner_ips if scanner_ips is not None else config.APPROVED_SCANNER_IPS)
        self.tolerance = timedelta(seconds=tolerance_s)
        self.require_all_targets = require_all_targets

    @classmethod
    def from_loader(cls, loader: Optional[DataLoader] = None, **kw) -> "ChangeMatcher":
        loader = loader or get_loader()
        return cls(
            parse_change_calendar(loader),
            AssetResolver.from_rows(loader.get_all_rows(ASSET_FILE)) if _has(loader, ASSET_FILE) else None,
            UserResolver.from_rows(loader.get_all_rows(USER_FILE)) if _has(loader, USER_FILE) else None,
            **kw,
        )

    # ---- individual criteria (each returns a Criterion; all unit-testable) ----
    def check_target(self, act: Activity, rec: ChangeRecord) -> Criterion:
        if not act.targets:
            return Criterion(False, "activity has no identified target")
        sc = build_scope(rec.target_text, self.assets)
        if sc.empty:
            return Criterion(False, f"change lists no recognizable target ({rec.target_text!r})")
        missing = uncovered_targets(sc, act.targets, self.assets)
        covered = [t for t in act.targets if t not in missing]
        if self.require_all_targets:
            if missing:
                return Criterion(False, f"not in change scope: {', '.join(missing)}")
            return Criterion(True, f"all targets within scope ({rec.target_text})")
        if covered:
            return Criterion(True, f"{', '.join(covered)} within scope" + (f"; outside: {', '.join(missing)}" if missing else ""))
        return Criterion(False, f"not in change scope: {', '.join(missing)}")

    def check_performer(self, act: Activity, rec: ChangeRecord) -> Criterion:
        if not act.actors:
            return Criterion(False, "activity has no identified actor")
        if not rec.performer_text.strip():
            return Criterion(False, "change names no performer")
        ptoks = performer_tokens(rec.performer_text, self.users, self.assets)
        for a in act.actors:
            if actor_aliases(a, self.users, self.assets) & ptoks:
                return Criterion(True, f"actor {a} is the named performer ({rec.performer_text})")
        # Hint: calendar says "scanner" without an IP, activity comes from the approved scanner.
        if re.search(r"scan", rec.performer_text, re.I):
            hit = [a for a in act.actors if a in self.scanner_ips]
            if hit:
                return Criterion(True, f"actor {hit[0]} is the approved scanner ({rec.performer_text})")
        return Criterion(False, f"actor {', '.join(act.actors)} is not the named performer ({rec.performer_text})")

    def check_time(self, act: Activity, rec: ChangeRecord) -> Criterion:
        if rec.start_utc is None or rec.end_utc is None:
            return Criterion(False, "change window could not be parsed")
        lo, hi = rec.start_utc - self.tolerance, rec.end_utc + self.tolerance
        win = f"{format_utc(rec.start_utc)} to {format_utc(rec.end_utc)}"
        if act.start_utc >= lo and act.end_utc <= hi:
            return Criterion(True, f"inside approved window {win}")
        if windows_overlap(act.start_utc, act.end_utc, lo, hi):
            over_before = max(timedelta(0), lo - act.start_utc)
            over_after = max(timedelta(0), act.end_utc - hi)
            return Criterion(False, f"overlaps window {win} but extends outside it "
                                    f"(before: {humanize_delta(over_before)}, after: {humanize_delta(over_after)})")
        gap = (lo - act.end_utc) if act.end_utc < lo else (act.start_utc - hi)
        side = "before" if act.end_utc < lo else "after"
        return Criterion(False, f"outside window {win} ({humanize_delta(gap)} {side})")

    def check_status(self, rec: ChangeRecord) -> Criterion:
        if rec.status_ok:
            return Criterion(True, rec.status_text or "no negative status")
        return Criterion(False, f"change status is '{rec.status_text}'")

    # ---- public API ----
    def evaluate(self, act: Activity, rec: ChangeRecord) -> ChangeMatch:
        return ChangeMatch(rec, self.check_target(act, rec), self.check_performer(act, rec),
                           self.check_time(act, rec), self.check_status(rec))

    def evaluate_all(self, act: Activity) -> List[ChangeMatch]:
        return [self.evaluate(act, r) for r in self.records]

    def match(self, act: Activity) -> Optional[ChangeMatch]:
        """The approved change that fully explains `act`, else None. Tightest window wins ties."""
        full = [m for m in self.evaluate_all(act) if m.full_match]
        if not full:
            return None
        full.sort(key=lambda m: ((m.record.end_utc - m.record.start_utc), m.change_id))
        return full[0]

    def match_change_id(self, act: Activity) -> Optional[str]:
        m = self.match(act)
        return m.change_id if m else None

    def near_misses(self, act: Activity, min_score: int = 2) -> List[ChangeMatch]:
        """Partial matches (>= min_score criteria met): these must NOT be closed as harmless."""
        out = [m for m in self.evaluate_all(act) if not m.full_match and m.score >= min_score]
        out.sort(key=lambda m: (-m.score, m.change_id))
        return out


def _has(loader: DataLoader, filename: str) -> bool:
    try:
        loader.load(filename)
        return True
    except Exception:  # missing/unreadable file -> resolver simply stays empty
        log.warning("%s unavailable; identity resolution degraded", filename)
        return False


def match_change(targets, actors, start: datetime, end: Optional[datetime] = None,
                 matcher: Optional[ChangeMatcher] = None) -> Optional[str]:
    """
    One-call convenience: returns the Change ID if the activity is an approved change, else None.
    `start`/`end` must be timezone-aware (use time_normalizer to produce UTC).
    """
    matcher = matcher or ChangeMatcher.from_loader()
    return matcher.match_change_id(Activity.create(targets, actors, start, end))
