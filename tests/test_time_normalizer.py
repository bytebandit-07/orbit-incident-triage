import re
from datetime import date, datetime, timedelta, timezone

import pytest

from backend import config
from backend.config import LogTimeMode, PKT_TZ, UTC_TZ
from backend.data_loader import DataLoader
from backend import time_normalizer as tn

U = lambda *a: datetime(*a, tzinfo=UTC_TZ)


# ---------------------------------------------------------------- per-source parsing
def test_utc_z():
    p = tn.parse_timestamp("2026-11-04T08:15:00Z user=a", LogTimeMode.UTC_Z)
    assert p.utc == U(2026, 11, 4, 8, 15) and p.zone_basis == "explicit"


def test_utc_mode_without_zone_assumes_utc():
    p = tn.parse_timestamp("2026-11-04 08:15:00 x", LogTimeMode.UTC_Z)
    assert p.utc == U(2026, 11, 4, 8, 15) and p.zone_basis == "assumed_utc"


def test_pkt_naive_shifts_five_hours_back():
    p = tn.parse_timestamp("2026-11-04 13:15:00 ACCEPT", LogTimeMode.PKT_NAIVE)
    assert p.utc == U(2026, 11, 4, 8, 15) and p.zone_basis == "assumed_pkt"


def test_pkt_naive_rolls_back_a_day_after_midnight():
    p = tn.parse_timestamp("2026-11-04 01:30:00", LogTimeMode.PKT_NAIVE)
    assert p.utc == U(2026, 11, 3, 20, 30)


def test_explicit_zone_beats_file_default():
    p = tn.parse_timestamp("2026-11-04T08:15:00Z", LogTimeMode.PKT_NAIVE)
    assert p.utc == U(2026, 11, 4, 8, 15)


@pytest.mark.parametrize("line,expected", [
    ('1.2.3.4 - - [04/Nov/2026:13:15:00 +0500] "GET /"', U(2026, 11, 4, 8, 15)),
    ("2026-11-04T13:15:00+05:00 GET /", U(2026, 11, 4, 8, 15)),
    ("2026-11-04T13:45:00+05:30 GET /", U(2026, 11, 4, 8, 15)),
    ("2026-11-03T22:15:00-10:00 GET /", U(2026, 11, 4, 8, 15)),
    ("2026-11-04 13:15:00 +0500 lease", U(2026, 11, 4, 8, 15)),
])
def test_offset_in_line(line, expected):
    assert tn.parse_timestamp(line, LogTimeMode.OFFSET_IN_LINE).utc == expected


def test_offset_mode_refuses_to_guess():
    with pytest.raises(tn.TimeParseError) as e:
        tn.parse_timestamp("2026-11-04 13:15:00 GET /", LogTimeMode.OFFSET_IN_LINE)
    assert not isinstance(e.value, tn.NoTimestampError)


def test_no_timestamp_is_soft_error():
    with pytest.raises(tn.NoTimestampError):
        tn.parse_timestamp("# header line", LogTimeMode.UTC_Z)


def test_invalid_date_is_hard_error():
    with pytest.raises(tn.TimeParseError):
        tn.parse_timestamp("2026-13-45T08:15:00Z", LogTimeMode.UTC_Z)


def test_second_timestamp_in_line():
    p = tn.parse_timestamp("2026-11-04T08:00:00Z lease until 2026-11-04T20:00:00Z", LogTimeMode.UTC_Z, index=1)
    assert p.utc == U(2026, 11, 4, 20, 0)


def test_fractional_seconds_and_pkt_word():
    assert tn.parse_timestamp("2026-11-04 13:15:00.250 PKT", None).utc == U(2026, 11, 4, 8, 15, 0, 250000)


def test_parse_for_file_uses_registry():
    assert tn.parse_for_file("16_email_gateway_log.md", "2026-11-04 13:15:00").utc == U(2026, 11, 4, 8, 15)
    assert tn.parse_for_file("11_vpn_auth_log.md", "2026-11-04 13:15:00").utc == U(2026, 11, 4, 13, 15)


# ---------------------------------------------------------------- conversion / formatting
def test_naive_never_guessed():
    with pytest.raises(ValueError):
        tn.to_utc(datetime(2026, 11, 4, 13, 0))
    with pytest.raises(ValueError):
        tn.format_utc(datetime(2026, 11, 4, 13, 0))


def test_pkt_to_utc_and_back():
    assert tn.pkt_to_utc(datetime(2026, 11, 4, 13, 0)) == U(2026, 11, 4, 8, 0)
    assert tn.utc_to_pkt(U(2026, 11, 4, 8, 0)).hour == 13


def test_format_utc_from_pkt_aware():
    assert tn.format_utc(datetime(2026, 11, 4, 13, 0, tzinfo=PKT_TZ)) == "2026-11-04T08:00:00Z"
    assert tn.format_pkt(U(2026, 11, 4, 8, 0)) == "2026-11-04 13:00:00 PKT"


# ---------------------------------------------------------------- deltas
def test_deltas_and_windows():
    a, b = U(2026, 11, 4, 8, 0), U(2026, 11, 4, 8, 15, 30)
    assert tn.seconds_between(a, b) == 930 and tn.minutes_between(b, a) == -15.5
    assert tn.humanize_delta(930) == "15m 30s" and tn.humanize_delta(90061) == "1d 1h 01m 01s"
    assert tn.humanize_delta(-5) == "-5s"
    assert tn.within_window(a, a, b) and not tn.within_window(a, a, b, inclusive=False)
    assert tn.within_window(a - timedelta(seconds=5), a, b, tolerance=timedelta(seconds=5))
    assert tn.windows_overlap(a, b, b, b + timedelta(hours=1))          # touching counts
    assert not tn.windows_overlap(a, a + timedelta(seconds=1), b, b)
    assert tn.add_minutes(a, 15) == U(2026, 11, 4, 8, 15)


# ---------------------------------------------------------------- windows
@pytest.mark.parametrize("text,kw,expected", [
    ("2026-11-04 14:00 - 16:00", {}, (U(2026, 11, 4, 9), U(2026, 11, 4, 11))),
    ("2026-11-04 14:00 to 2026-11-04 16:30 PKT", {}, (U(2026, 11, 4, 9), U(2026, 11, 4, 11, 30))),
    ("2026-11-04 14:00-16:00", {}, (U(2026, 11, 4, 9), U(2026, 11, 4, 11))),
    ("14:00-16:00", {"default_date": date(2026, 11, 4)}, (U(2026, 11, 4, 9), U(2026, 11, 4, 11))),
    ("2026-11-04 22:00 - 02:00", {}, (U(2026, 11, 4, 17), U(2026, 11, 4, 21))),        # overnight
    ("2026-11-04 14:00 - 16:00 UTC", {}, (U(2026, 11, 4, 14), U(2026, 11, 4, 16))),    # zone word wins
    ("2026-11-04", {}, (U(2026, 11, 3, 19), U(2026, 11, 4, 18, 59, 59))),               # whole PKT day
    ("2026-11-04 00:00 - 24:00", {}, (U(2026, 11, 3, 19), U(2026, 11, 4, 19))),
])
def test_parse_time_window(text, kw, expected):
    assert tn.parse_time_window(text, **kw) == expected


def test_window_errors():
    with pytest.raises(tn.TimeParseError):
        tn.parse_time_window("14:00-16:00")                      # no date
    with pytest.raises(tn.TimeParseError):
        tn.parse_time_window("2026-11-04 16:00 to 2026-11-04 14:00")
    with pytest.raises(tn.TimeParseError):
        tn.parse_time_window("sometime tomorrow")


def test_parse_datetime_loose():
    assert tn.parse_datetime_loose("2026-11-04 14:00") == U(2026, 11, 4, 9)
    assert tn.parse_datetime_loose("14:00", default_date=date(2026, 11, 4)) == U(2026, 11, 4, 9)
    assert tn.parse_datetime_loose("14:00 UTC", default_date=date(2026, 11, 4)) == U(2026, 11, 4, 14)


# ---------------------------------------------------------------- file 15: close - duration
def test_internal_fw_start_is_close_minus_duration():
    sw = tn.firewall_internal_session("2026-11-04 13:10:00 ALLOW 10.0.0.5 -> 10.0.0.9 duration=600")
    assert sw.end_utc == U(2026, 11, 4, 8, 10) and sw.start_utc == U(2026, 11, 4, 8, 0)
    assert sw.duration_s == 600 and not sw.spans_logging_gap


def test_internal_fw_session_crossing_midnight():
    sw = tn.firewall_internal_session("2026-11-04 00:05:00 ALLOW dur=900")
    assert sw.start_utc == U(2026, 11, 3, 18, 50) and sw.end_utc == U(2026, 11, 3, 19, 5)


@pytest.mark.parametrize("line,secs", [
    ("x duration=1832 y", 1832), ("x dur: 12 y", 12), ("x duration_s=7", 7),
    ("x elapsed=99", 99), ("x 1832s y", 1832), ("x 45 sec y", 45),
])
def test_duration_formats(line, secs):
    assert tn.parse_duration_seconds(line) == secs


def test_duration_ambiguous_or_missing_raises():
    with pytest.raises(tn.TimeParseError):
        tn.parse_duration_seconds("a 10s b 20s")
    with pytest.raises(tn.TimeParseError):
        tn.parse_duration_seconds("no duration here, port 443")


def test_duration_custom_pattern_and_explicit_arg():
    pat = re.compile(r"\bdur\((\d+)\)")
    assert tn.parse_duration_seconds("x dur(321)", pat) == 321
    sw = tn.firewall_internal_session("2026-11-04 13:10:00 weird", duration_s=60)
    assert sw.start_utc == U(2026, 11, 4, 8, 9)


# ---------------------------------------------------------------- coverage gaps
def test_internal_fw_gap_window():
    # 11:32:00-12:28:59 PKT on 2026-11-04 == 06:32:00-07:28:59Z
    gs, ge = tn.internal_fw_gap_for(date(2026, 11, 4))
    assert gs == U(2026, 11, 4, 6, 32) and ge == U(2026, 11, 4, 7, 28, 59)
    assert tn.overlaps_internal_fw_gap(U(2026, 11, 4, 7, 0))
    assert not tn.overlaps_internal_fw_gap(U(2026, 11, 4, 7, 29))
    assert not tn.overlaps_internal_fw_gap(U(2026, 11, 4, 6, 31, 59))
    assert tn.overlaps_internal_fw_gap(U(2026, 11, 4, 6, 0), U(2026, 11, 4, 8, 0))   # spans it


def test_session_spanning_gap_flagged():
    sw = tn.firewall_internal_session("2026-11-04 13:00:00 ALLOW duration=7200")  # started 11:00 PKT
    assert sw.spans_logging_gap


def test_dc_coverage_edges():
    assert not tn.dc_log_covers(U(2026, 11, 4, 2, 59, 59))
    assert tn.dc_log_covers(U(2026, 11, 4, 3, 0, 0)) and tn.dc_log_covers(U(2026, 11, 4, 19, 0, 0))
    assert not tn.dc_log_covers(U(2026, 11, 4, 19, 0, 1))
    assert tn.dc_log_covers(datetime(2026, 11, 4, 8, 0, tzinfo=PKT_TZ))   # 03:00Z


# ---------------------------------------------------------------- whole-file normalization
@pytest.fixture()
def loader(tmp_path):
    def w(name, body):
        (tmp_path / name).write_text(f"# t\n\n```\n{body}\n```\n", encoding="utf-8")
    w("11_vpn_auth_log.md", "# comment\n2026-11-04T08:15:00Z login ok")
    w("12_windows_dc_auth_log.md", "2026-11-04T02:00:00Z 4624\n2026-11-04T05:00:00Z 4624")
    w("13_web_server_log.md", "1.2.3.4 [04/Nov/2026:13:15:00 +0500] GET /\nbad 2026-11-04 13:15:00 no offset")
    w("15_firewall_internal_log.md",
      "2026-11-04 13:10:00 ALLOW duration=600\n2026-11-04 12:00:00 ALLOW duration=30\n2026-11-04 13:30:00 ALLOW nodur")
    return DataLoader(tmp_path)


def test_iter_events_vpn_skips_header(loader):
    evs = list(tn.iter_events(loader, "11"))
    assert [(e.line_no, e.utc_text) for e in evs] == [(2, "2026-11-04T08:15:00Z")]
    assert evs[0].citation == "11_vpn_auth_log.md:2"


def test_iter_events_dc_marks_coverage_gap(loader):
    evs = list(tn.iter_events(loader, "12_windows_dc_auth_log.md"))
    assert [e.in_logging_gap for e in evs] == [True, False]


def test_iter_events_offset_log_flags_naive_line(loader):
    evs = list(tn.iter_events(loader, 13))
    assert evs[0].utc == U(2026, 11, 4, 8, 15) and evs[0].error is None
    assert evs[1].utc is None and "no UTC offset" in evs[1].error


def test_iter_events_internal_fw(loader):
    e1, e2, e3 = tn.iter_events(loader, 15)
    assert e1.start_utc == U(2026, 11, 4, 8, 0) and e1.end_utc == U(2026, 11, 4, 8, 10)
    assert e2.in_logging_gap and not e1.in_logging_gap
    assert e3.start_utc is None and e3.end_utc == U(2026, 11, 4, 8, 30) and "start time unknown" in e3.error


def test_event_at(loader):
    assert tn.event_at(loader, 11, 2).utc == U(2026, 11, 4, 8, 15)
    with pytest.raises(tn.NoTimestampError):
        tn.event_at(loader, 11, 1)
