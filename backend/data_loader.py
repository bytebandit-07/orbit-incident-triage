"""
backend/data_loader.py
======================
Loads and parses the 20 markdown files in `problem_c_data/`.

What it guarantees
------------------
* **Exact citations.** For log files, line 1 is the first line INSIDE the markdown
  code fence. `get_log_line(file, n)` returns that raw line, untouched.
  We never use `str.splitlines()` (it also splits on \\x0b, \\x0c, \\u2028 ... which
  would silently shift every later line number); only \\n / \\r\\n are separators.
* **Structured tables.** Every markdown pipe-table (outside code fences) is parsed
  into rows indexed by primary key (Asset Tag, Change ID, Alert ID, Username, ...).
* **Runbook steps.** Steps are indexed by number so "runbook:Step 3" can be verified.
* **LLM-ready text.** `build_context_pack()` renders files with line numbers
  burned into log lines, so the model copies citations instead of counting.
* **Citation verification.** `verify_citation()` / `validate_report_citations()` let the
  engine reject hallucinated citations *before* the report is returned.
* **Robustness.** Missing files, bad encodings, BOMs, CRLF, unclosed fences,
  ragged tables and duplicate keys are handled and reported, never silently ignored.

Stdlib only.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from . import config
from .config import FileSpec, Severity

log = logging.getLogger(__name__)


# =========================================================================== #
# Exceptions
# =========================================================================== #
class DataLoadError(Exception):
    """Base class for every error raised by this module."""


class DataFileNotFound(DataLoadError, FileNotFoundError):
    """A required data file is missing from the data directory."""


class UnknownFileError(DataLoadError, KeyError):
    """The requested name is not one of the 20 registered files."""

    def __str__(self) -> str:  # KeyError would otherwise repr() the message
        return str(self.args[0]) if self.args else ""


class LogLineError(DataLoadError, IndexError):
    """Line number out of range, or the file has no code block."""


class RowNotFound(DataLoadError, KeyError):
    """No table row with that primary key."""

    def __str__(self) -> str:
        return str(self.args[0]) if self.args else ""


class StepNotFound(DataLoadError, KeyError):
    """Runbook has no such step."""

    def __str__(self) -> str:
        return str(self.args[0]) if self.args else ""


# =========================================================================== #
# Small text helpers
# =========================================================================== #
_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
_SEP_CELL_RE = re.compile(r"^\s*:?-{1,}:?\s*$")
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")


def _split_lines(text: str) -> List[str]:
    """
    Split on \\n / \\r\\n / lone \\r ONLY. Unlike str.splitlines() this never splits on
    vertical-tab, form-feed, NEL, U+2028/2029, so line numbers stay exact.
    """
    return re.split(r"\r\n|\n|\r", text)


def _norm(s: str) -> str:
    """Normalize a header / key for loose matching: 'Asset  Tag' -> 'asset tag'."""
    return re.sub(r"[^a-z0-9]+", " ", (s or "").casefold()).strip()


def _clean_cell(s: str) -> str:
    """Strip markdown emphasis/code ticks so '**`A-1001`**' becomes 'A-1001'."""
    s = (s or "").strip()
    s = re.sub(r"^(\*\*|__|`)+|(\*\*|__|`)+$", "", s).strip()
    return s


def _read_text(path: Path) -> str:
    """
    Read a file as UTF-8 (BOM-tolerant). If the bytes are not valid UTF-8 we fall back
    to cp1252 and finally to utf-8 with replacement, logging a warning each time, so a
    stray byte in one log never crashes the whole run.
    """
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise DataFileNotFound(f"Data file not found: {path}") from exc
    except PermissionError as exc:
        raise DataLoadError(f"No permission to read {path}") from exc
    except OSError as exc:
        raise DataLoadError(f"Could not read {path}: {exc}") from exc

    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        log.warning("%s is not valid UTF-8; retrying as cp1252", path.name)
    try:
        return raw.decode("cp1252")
    except UnicodeDecodeError:
        log.warning("%s is not valid cp1252 either; decoding with replacement", path.name)
        return raw.decode("utf-8", errors="replace")


# =========================================================================== #
# Parsed structures
# =========================================================================== #
@dataclass(frozen=True, eq=False)
class TableRow:
    """One table row. `key` is the primary-key cell (cleaned of markdown noise)."""

    key: str
    data: Dict[str, str]          # original header text -> cell text
    source_file: str
    table_index: int              # which table in the file (0-based)
    row_number: int               # 1-based data-row position inside that table
    file_line: int                # 1-based line in the .md file (informational ONLY, never cite)

    def get(self, column: str, default: str = "") -> str:
        """Case/punctuation-insensitive column lookup: row.get('asset tag')."""
        target = _norm(column)
        for k, v in self.data.items():
            if _norm(k) == target:
                return v
        return default


@dataclass(eq=False)
class Table:
    title: str                    # nearest preceding heading ('' if none)
    headers: Tuple[str, ...]
    key_column: str               # header chosen as primary key
    rows: List[TableRow] = field(default_factory=list)
    index: Dict[str, TableRow] = field(default_factory=dict)   # casefolded key -> row
    duplicate_keys: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunbookStep:
    number: int
    title: str                    # first line of the step
    text: str                     # full step text (title + body)
    file_line: int                # informational only


@dataclass(eq=False)
class ParsedDocument:
    spec: FileSpec
    path: Path
    raw_text: str
    file_lines: Tuple[str, ...]                       # every line of the .md file
    code_blocks: Tuple[Tuple[str, ...], ...]          # each fenced block's inner lines
    fence_spans: Tuple[Tuple[int, int], ...]          # (open_idx, close_idx) into file_lines
    tables: Tuple[Table, ...]
    steps: Dict[int, RunbookStep]
    steps_source: str                                 # 'step-headings' | 'step-table' | 'numbered-list' | ''
    warnings: Tuple[str, ...] = ()

    @property
    def filename(self) -> str:
        return self.spec.filename

    @property
    def log_lines(self) -> Tuple[str, ...]:
        """Lines of the FIRST fenced block - this is what 'file.md:N' citations count."""
        return self.code_blocks[0] if self.code_blocks else ()


@dataclass(frozen=True)
class CitationCheck:
    citation: str
    valid: bool
    kind: str          # log_line | table_row | runbook_step | id_in_text | unknown
    reason: str = ""


@dataclass
class LoadReport:
    loaded: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)
    warnings: Dict[str, Tuple[str, ...]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.missing and not self.errors


# =========================================================================== #
# Parsing routines (pure functions - easy to unit test)
# =========================================================================== #
def _find_fences(lines: Sequence[str]) -> Tuple[List[Tuple[int, int]], List[str]]:
    """
    Locate fenced code blocks. A block opens with >=3 backticks or tildes and closes with
    the same character repeated at least as many times (CommonMark). An unclosed fence
    runs to EOF (and we warn). Returns (spans, warnings); spans are indexes into `lines`.
    """
    spans: List[Tuple[int, int]] = []
    warnings: List[str] = []
    i, n = 0, len(lines)
    while i < n:
        m = _FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        marker = m.group(1)
        # An opening backtick fence must not contain further backticks in its info string.
        if marker[0] == "`" and "`" in m.group(2):
            i += 1
            continue
        j = i + 1
        closed = False
        while j < n:
            cm = _FENCE_RE.match(lines[j])
            if cm and cm.group(1)[0] == marker[0] and len(cm.group(1)) >= len(marker) \
                    and not cm.group(2).strip():
                closed = True
                break
            j += 1
        if not closed:
            warnings.append(f"Unclosed code fence opened at file line {i + 1}; reading to EOF")
            j = n  # treat EOF as the close
        spans.append((i, j))
        i = j + 1
    return spans, warnings


def _split_row(line: str) -> List[str]:
    """Split a pipe-table row on unescaped '|' and drop the outer empty cells."""
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    return [c.replace("\\|", "|").strip() for c in re.split(r"(?<!\\)\|", s)]


def _is_separator(line: str) -> bool:
    if "|" not in line and "-" not in line:
        return False
    cells = _split_row(line)
    return bool(cells) and all(_SEP_CELL_RE.match(c) for c in cells if c != "") \
        and any(c != "" for c in cells)


def _pick_key_column(headers: Sequence[str], candidates: Sequence[str]) -> int:
    """Index of the primary-key column: first matching candidate name, else column 0."""
    normed = [_norm(h) for h in headers]
    for cand in candidates:
        c = _norm(cand)
        if c in normed:
            return normed.index(c)
    return 0


def _parse_tables(lines: Sequence[str], fence_spans: Sequence[Tuple[int, int]],
                  spec: FileSpec) -> List[Table]:
    """Parse every pipe table that is NOT inside a code fence."""
    in_fence = set()
    for a, b in fence_spans:
        in_fence.update(range(a, min(b, len(lines) - 1) + 1))

    tables: List[Table] = []
    current_heading = ""
    i, n = 0, len(lines)
    while i < n:
        if i in in_fence:
            i += 1
            continue
        hm = _HEADING_RE.match(lines[i])
        if hm:
            current_heading = hm.group(2).strip()
            i += 1
            continue

        # A table = header row (contains '|') followed immediately by a separator row.
        if "|" in lines[i] and i + 1 < n and (i + 1) not in in_fence and "|" in lines[i + 1] \
                and _is_separator(lines[i + 1]):
            headers = [_clean_cell(h) for h in _split_row(lines[i])]
            key_idx = _pick_key_column(headers, spec.primary_key_candidates)
            table = Table(title=current_heading, headers=tuple(headers),
                          key_column=headers[key_idx] if headers else "")
            tindex = len(tables)

            j = i + 2
            row_no = 0
            while j < n and j not in in_fence and lines[j].strip() and "|" in lines[j]:
                cells = _split_row(lines[j])
                # Ragged rows: pad short ones; fold surplus cells into the last column.
                if len(cells) < len(headers):
                    cells += [""] * (len(headers) - len(cells))
                elif len(cells) > len(headers) and headers:
                    cells = cells[: len(headers) - 1] + [" | ".join(cells[len(headers) - 1:])]
                row_no += 1
                data = dict(zip(headers, cells))
                key = _clean_cell(cells[key_idx]) if cells else ""
                row = TableRow(key=key, data=data, source_file=spec.filename,
                               table_index=tindex, row_number=row_no, file_line=j + 1)
                table.rows.append(row)
                if key:
                    ck = key.casefold()
                    if ck in table.index:
                        table.duplicate_keys.append(key)   # first occurrence wins
                    else:
                        table.index[ck] = row
                j += 1
            tables.append(table)
            i = j
            continue
        i += 1
    return tables


_STEP_LINE_RE = re.compile(
    r"^\s{0,3}(?P<hashes>#{1,6}\s*)?(?P<bold>\*\*|__)?\s*(?:Step|STEP)\s*[-#:]?\s*(?P<num>\d+)\b"
)
_NUMBERED_RE = re.compile(r"^\s{0,3}(?P<num>\d+)[.)]\s+(?P<rest>.*)$")


def _parse_steps(lines: Sequence[str], fence_spans: Sequence[Tuple[int, int]],
                 tables: Sequence[Table]) -> Tuple[Dict[int, RunbookStep], str]:
    """
    Extract runbook steps. Tried in order (first that yields anything wins):
      1. 'Step N' headings / bold lines / plain lines
      2. a table with a 'Step' column
      3. top-level numbered list ('1. ...')
    """
    in_fence = set()
    for a, b in fence_spans:
        in_fence.update(range(a, min(b, len(lines) - 1) + 1))

    def collect(starts: List[Tuple[int, int]]) -> Dict[int, RunbookStep]:
        out: Dict[int, RunbookStep] = {}
        for idx, (line_idx, num) in enumerate(starts):
            end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
            # Stop at the next heading of any level so trailing sections don't leak in.
            for k in range(line_idx + 1, end):
                if k not in in_fence and _HEADING_RE.match(lines[k]) \
                        and not _STEP_LINE_RE.match(lines[k]):
                    end = k
                    break
            body = "\n".join(lines[line_idx:end]).strip()
            if num not in out:  # first definition wins
                out[num] = RunbookStep(num, lines[line_idx].strip(), body, line_idx + 1)
        return out

    # 1) explicit "Step N"
    starts = [(i, int(m.group("num"))) for i, l in enumerate(lines)
              if i not in in_fence and (m := _STEP_LINE_RE.match(l))]
    if starts:
        return collect(starts), "step-headings"

    # 2) table with a Step column
    steps: Dict[int, RunbookStep] = {}
    for t in tables:
        step_col = next((h for h in t.headers if _norm(h) in ("step", "step no", "step number", "no", "#")), None)
        if not step_col:
            continue
        for r in t.rows:
            dm = re.search(r"\d+", r.data.get(step_col, ""))
            if dm and int(dm.group()) not in steps:
                num = int(dm.group())
                text = " | ".join(f"{k}: {v}" for k, v in r.data.items())
                steps[num] = RunbookStep(num, r.data.get(step_col, ""), text, r.file_line)
    if steps:
        return steps, "step-table"

    # 3) numbered list
    starts = [(i, int(m.group("num"))) for i, l in enumerate(lines)
              if i not in in_fence and (m := _NUMBERED_RE.match(l))]
    if starts:
        return collect(starts), "numbered-list"
    return {}, ""


def parse_document(spec: FileSpec, path: Path) -> ParsedDocument:
    """Parse one file completely (raw text, fences, tables, steps)."""
    text = _read_text(path)
    file_lines = _split_lines(text)
    warnings: List[str] = []

    spans, fence_warnings = _find_fences(file_lines)
    warnings.extend(fence_warnings)

    code_blocks: List[Tuple[str, ...]] = []
    for a, b in spans:
        # Inner lines only: line 1 of a citation == file_lines[a + 1]. Keep blank lines
        # (they count!) and keep raw content exactly as written.
        code_blocks.append(tuple(file_lines[a + 1: b]))

    if spec.expects_code_block and not code_blocks:
        warnings.append("Log file has no fenced code block; log-line citations are impossible")
    if len(code_blocks) > 1 and spec.expects_code_block:
        warnings.append(
            f"{len(code_blocks)} code blocks found; citations count lines in the FIRST block only"
        )

    tables = _parse_tables(file_lines, spans, spec)
    for t in tables:
        if t.duplicate_keys:
            warnings.append(f"Duplicate keys in table '{t.title or t.key_column}': {t.duplicate_keys}")

    steps: Dict[int, RunbookStep] = {}
    steps_source = ""
    if spec.category == "runbook":
        steps, steps_source = _parse_steps(file_lines, spans, tables)
        if not steps:
            warnings.append("No runbook steps detected")

    for w in warnings:
        log.warning("%s: %s", spec.filename, w)

    return ParsedDocument(
        spec=spec, path=path, raw_text=text, file_lines=tuple(file_lines),
        code_blocks=tuple(code_blocks), fence_spans=tuple(spans), tables=tuple(tables),
        steps=steps, steps_source=steps_source, warnings=tuple(warnings),
    )


# =========================================================================== #
# DataLoader
# =========================================================================== #
_CITATION_RE = re.compile(
    r"(?P<file>\b\d{2}_[A-Za-z0-9_]+\.md)\s*:\s*"
    r"(?P<ref>(?:[Ss]tep[\s_-]*\d+)|(?:\d+\s*-\s*\d+)|(?:[A-Za-z0-9][A-Za-z0-9_.\-@]*))"
)
_STEP_REF_RE = re.compile(r"^[Ss]tep[\s_-]*(\d+)$")
_RANGE_RE = re.compile(r"^(\d+)\s*-\s*(\d+)$")

FileRef = Union[str, int]


class DataLoader:
    """
    Thread-safe, cache-backed access to the 20 data files.

        dl = DataLoader()
        dl.get_log_line("11_vpn_auth_log.md", 7)     # exact raw line 7 of the code block
        dl.get_row("02_asset_inventory.md", "A-1007").data
        dl.get_runbook_step("06_runbook_phishing.md", 3).text
        context = dl.build_context_pack()            # numbered text for the LLM
    """

    def __init__(self, data_dir: Optional[Union[str, Path]] = None, strict: bool = False):
        self.data_dir = Path(data_dir).expanduser().resolve() if data_dir else config.DATA_DIR
        self.strict = strict
        self._cache: Dict[str, ParsedDocument] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ #
    # File resolution + loading
    # ------------------------------------------------------------------ #
    def resolve(self, ref: FileRef) -> FileSpec:
        """
        Accepts: exact filename ('11_vpn_auth_log.md'), short key ('vpn_auth_log'),
        file number (11 or '11'), or a unique filename prefix/stem ('11_vpn_auth_log').
        """
        if isinstance(ref, int):
            spec = config.FILE_BY_NUMBER.get(ref)
            if spec:
                return spec
        else:
            name = Path(str(ref).strip()).name       # tolerate 'problem_c_data/11_...md'
            if name in config.FILE_BY_NAME:
                return config.FILE_BY_NAME[name]
            if name in config.FILE_BY_KEY:
                return config.FILE_BY_KEY[name]
            if name.isdigit() and int(name) in config.FILE_BY_NUMBER:
                return config.FILE_BY_NUMBER[int(name)]
            stem = name[:-3] if name.endswith(".md") else name
            matches = [s for s in config.FILE_SPECS if s.filename[:-3] == stem]
            if len(matches) == 1:
                return matches[0]
        raise UnknownFileError(f"Unknown data file reference: {ref!r}")

    def load(self, ref: FileRef) -> ParsedDocument:
        """Parse a file once; later calls hit the cache."""
        spec = self.resolve(ref)
        with self._lock:
            doc = self._cache.get(spec.filename)
            if doc is None:
                doc = parse_document(spec, self.data_dir / spec.filename)
                self._cache[spec.filename] = doc
            return doc

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    def preload_all(self) -> LoadReport:
        """
        Load every file, never raising (unless strict=True) so the UI can show exactly
        which files are missing instead of dying on the first one.
        """
        report = LoadReport()
        for spec in config.FILE_SPECS:
            try:
                doc = self.load(spec.filename)
                report.loaded.append(spec.filename)
                if doc.warnings:
                    report.warnings[spec.filename] = doc.warnings
            except DataFileNotFound:
                report.missing.append(spec.filename)
                if self.strict:
                    raise
            except DataLoadError as exc:
                report.errors[spec.filename] = str(exc)
                if self.strict:
                    raise
        return report

    # ------------------------------------------------------------------ #
    # Raw text (for LLM context packing)
    # ------------------------------------------------------------------ #
    def get_raw_text(self, ref: FileRef) -> str:
        return self.load(ref).raw_text

    def render_numbered(self, ref: FileRef, block_index: int = 0,
                        start: Optional[int] = None, end: Optional[int] = None) -> str:
        """
        Render a file for the LLM: prose and tables verbatim; lines of the citation block
        prefixed with their 1-indexed number, e.g. `  12| 2026-11-04T08:15:00Z ...`.
        Prose outside the fence is kept because it often states the timezone/format.
        `start`/`end` (1-indexed, inclusive) restrict the numbered block to a window.
        """
        doc = self.load(ref)
        if not doc.fence_spans:
            return doc.raw_text
        out: List[str] = []
        pos = 0
        for b_idx, (a, b) in enumerate(doc.fence_spans):
            out.extend(doc.file_lines[pos:a])               # prose before fence
            out.append(doc.file_lines[a])                   # opening fence line
            inner = doc.file_lines[a + 1:b]
            if b_idx == block_index:
                width = len(str(len(inner)))
                lo = max(1, start or 1)
                hi = min(len(inner), end or len(inner))
                if lo > 1:
                    out.append(f"... (lines 1-{lo - 1} omitted)")
                for n in range(lo, hi + 1):
                    out.append(f"{n:>{width}}| {inner[n - 1]}")
                if hi < len(inner):
                    out.append(f"... (lines {hi + 1}-{len(inner)} omitted)")
            else:
                out.extend(inner)
            if b < len(doc.file_lines):
                out.append(doc.file_lines[b])               # closing fence line
            pos = b + 1
        out.extend(doc.file_lines[pos:])
        return "\n".join(out)

    def build_context_pack(self, refs: Optional[Iterable[FileRef]] = None,
                           include_line_numbers: bool = True) -> str:
        """
        Concatenate files into one prompt-ready string with clear delimiters and a
        citation legend. Missing files are noted inline (so the model cites file 20
        rather than inventing data) instead of aborting the whole pack.
        """
        specs = [self.resolve(r) for r in refs] if refs is not None else list(config.FILE_SPECS)
        parts: List[str] = [
            "### CITATION LEGEND",
            "- Log files: cite `filename.md:N` where N is the number printed left of the `|`; "
            "line 1 is the first line INSIDE the code fence.",
            "- Tables: cite `filename.md:ROW_ID` (asset tag, change ID, alert ID, username, ...).",
            "- Runbooks: cite the step number.",
            "",
        ]
        for spec in specs:
            parts.append(f"===== FILE: {spec.filename} | {spec.category} | time: {spec.time_mode.value} =====")
            try:
                parts.append(self.render_numbered(spec.filename) if include_line_numbers
                             else self.get_raw_text(spec.filename))
            except DataFileNotFound:
                parts.append(f"[MISSING FILE: {spec.filename} - treat as 'Not enough evidence in the logs']")
            parts.append(f"===== END FILE: {spec.filename} =====\n")
        return "\n".join(parts)

    # ------------------------------------------------------------------ #
    # Log access (1-indexed, relative to the code fence)
    # ------------------------------------------------------------------ #
    def get_log_lines(self, ref: FileRef) -> Tuple[str, ...]:
        doc = self.load(ref)
        if not doc.code_blocks:
            raise LogLineError(f"{doc.filename} has no fenced code block")
        return doc.log_lines

    def get_log_line_count(self, ref: FileRef) -> int:
        return len(self.get_log_lines(ref))

    def get_log_line(self, ref: FileRef, line_no: int) -> str:
        """Exact raw text of line `line_no` (1-indexed, first line inside the fence = 1)."""
        lines = self.get_log_lines(ref)
        if isinstance(line_no, bool) or not isinstance(line_no, int):
            raise LogLineError(f"line_no must be an int, got {line_no!r}")
        if not 1 <= line_no <= len(lines):
            raise LogLineError(
                f"{self.resolve(ref).filename} has {len(lines)} log lines; line {line_no} is out of range"
            )
        return lines[line_no - 1]

    def iter_log_lines(self, ref: FileRef) -> Iterable[Tuple[int, str]]:
        """Yield (1-indexed line number, raw line). Blank lines are included - they count."""
        for i, line in enumerate(self.get_log_lines(ref), start=1):
            yield i, line

    def find_log_lines(self, ref: FileRef, needle: str, ignore_case: bool = True) -> List[Tuple[int, str]]:
        """Substring search returning (line_no, raw_line) pairs - handy for evidence gathering."""
        n = needle.casefold() if ignore_case else needle
        return [(i, l) for i, l in self.iter_log_lines(ref)
                if n in (l.casefold() if ignore_case else l)]

    def cite_log(self, ref: FileRef, line_no: int) -> str:
        """Canonical citation string for a log line (validates the line exists)."""
        self.get_log_line(ref, line_no)
        return f"{self.resolve(ref).filename}:{line_no}"

    # ------------------------------------------------------------------ #
    # Table access
    # ------------------------------------------------------------------ #
    def get_tables(self, ref: FileRef) -> Tuple[Table, ...]:
        return self.load(ref).tables

    def get_rows(self, ref: FileRef, table_index: int = 0) -> List[TableRow]:
        tables = self.get_tables(ref)
        if not tables:
            return []
        return list(tables[table_index].rows)

    def get_all_rows(self, ref: FileRef) -> List[TableRow]:
        """Rows from every table in the file (some files hold several tables)."""
        return [r for t in self.get_tables(ref) for r in t.rows]

    def get_table_index(self, ref: FileRef) -> Dict[str, Dict[str, str]]:
        """{primary_key: {column: value}} merged across all tables (first key wins)."""
        merged: Dict[str, Dict[str, str]] = {}
        for t in self.get_tables(ref):
            for r in t.rows:
                if r.key and r.key not in merged:
                    merged[r.key] = dict(r.data)
        return merged

    def find_row(self, ref: FileRef, row_id: str) -> Optional[TableRow]:
        """Case-insensitive primary-key lookup across all tables. None if absent."""
        key = _clean_cell(str(row_id)).casefold()
        for t in self.get_tables(ref):
            hit = t.index.get(key)
            if hit:
                return hit
        return None

    def get_row(self, ref: FileRef, row_id: str) -> TableRow:
        row = self.find_row(ref, row_id)
        if row is None:
            raise RowNotFound(f"No row '{row_id}' in {self.resolve(ref).filename}")
        return row

    def matrix_lookup(self, row_key: str, column: str,
                      ref: FileRef = "03_severity_matrix.md") -> Optional[Severity]:
        """
        Deterministic severity matrix lookup: matrix_lookup('Phishing', 'Critical') -> P1.
        Row = incident type, column = asset criticality. Returns None if either is unknown or
        the cell holds no P1..P4 token. (Exact incident-type strings come from the file.)
        """
        row = self.find_row(ref, row_key)
        if row is None:
            return None
        return Severity.from_text(row.get(column))

    # ------------------------------------------------------------------ #
    # Runbook access
    # ------------------------------------------------------------------ #
    def get_runbook_steps(self, ref: FileRef) -> Dict[int, RunbookStep]:
        return dict(self.load(ref).steps)

    def get_runbook_step(self, ref: FileRef, step: Union[int, str]) -> RunbookStep:
        m = _STEP_REF_RE.match(str(step).strip())
        num = int(m.group(1)) if m else int(re.sub(r"\D", "", str(step)) or -1)
        steps = self.load(ref).steps
        if num not in steps:
            raise StepNotFound(f"{self.resolve(ref).filename} has no Step {step} (have {sorted(steps)})")
        return steps[num]

    # ------------------------------------------------------------------ #
    # Citation verification (guards against hallucinated evidence)
    # ------------------------------------------------------------------ #
    def verify_citation(self, citation: str) -> CitationCheck:
        """
        Verify 'file.md:REF' where REF is a log line number, 'N-M' range, 'Step N',
        or a table row ID. Never raises; returns a CitationCheck.
        """
        c = citation.strip().strip("`")
        fm, _, ref = c.partition(":")
        ref = ref.strip()
        try:
            spec = self.resolve(fm.strip())
        except UnknownFileError:
            return CitationCheck(c, False, "unknown", f"unknown file '{fm}'")
        if not ref:
            return CitationCheck(c, False, "unknown", "empty reference")

        try:
            doc = self.load(spec.filename)
        except DataLoadError as exc:
            return CitationCheck(c, False, "unknown", str(exc))

        # Log line or range
        if ref.isdigit() or _RANGE_RE.match(ref):
            if not doc.code_blocks:
                return CitationCheck(c, False, "log_line", "file has no code block to count lines in")
            total = len(doc.log_lines)
            lo, hi = (int(ref), int(ref)) if ref.isdigit() else map(int, _RANGE_RE.match(ref).groups())
            if lo < 1 or hi < lo or hi > total:
                return CitationCheck(c, False, "log_line", f"valid lines are 1-{total}")
            return CitationCheck(c, True, "log_line")

        # Runbook step
        sm = _STEP_REF_RE.match(ref)
        if sm:
            ok = int(sm.group(1)) in doc.steps
            return CitationCheck(c, ok, "runbook_step", "" if ok else f"steps available: {sorted(doc.steps)}")

        # Table row ID
        if self.find_row(spec.filename, ref) is not None:
            return CitationCheck(c, True, "table_row")

        # Fallback: ID appears verbatim in the file text (e.g. alerts kept in a code block)
        if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(ref)}(?![A-Za-z0-9_-])", doc.raw_text):
            return CitationCheck(c, True, "id_in_text", "found in text but not as a parsed table key")
        return CitationCheck(c, False, "table_row", f"no row/ID '{ref}' in {spec.filename}")

    def validate_report_citations(self, report_text: str) -> List[CitationCheck]:
        """Find every `NN_name.md:REF` in a report and verify each. Order preserved, de-duplicated."""
        seen: set = set()
        results: List[CitationCheck] = []
        for m in _CITATION_RE.finditer(report_text):
            ref = m.group("ref").rstrip(".,;:)")
            cite = f"{m.group('file')}:{ref}"
            if cite not in seen:
                seen.add(cite)
                results.append(self.verify_citation(cite))
        return results


# =========================================================================== #
# Module-level convenience (shared cache for the whole app)
# =========================================================================== #
@lru_cache(maxsize=1)
def get_loader() -> DataLoader:
    """Process-wide singleton so FastAPI requests share one parsed cache."""
    return DataLoader()


def get_log_line(filename: str, line_no: int) -> str:
    """Convenience wrapper matching the spec: exact raw line, 1-indexed inside the fence."""
    return get_loader().get_log_line(filename, line_no)
