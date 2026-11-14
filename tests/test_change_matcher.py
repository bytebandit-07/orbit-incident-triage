from datetime import datetime, timedelta

import pytest

from backend.config import UTC_TZ
from backend.data_loader import DataLoader
from backend import change_matcher as cm

U = lambda *a: datetime(*a, tzinfo=UTC_TZ)

ASSETS = """# Assets
| Asset Tag | Hostname | IP Address | Criticality | Owner |
|---|---|---|---|---|
| A-1001 | SRV-WEB01 | 10.10.1.10 | High | IT |
| A-1004 | SRV-DB01 | 10.10.3.4 | Critical | IT |
| A-2001 | SCAN01 | 10.10.9.50 | Low | Security |
"""
USERS = """# Users
| Username | Full Name | Email | Department |
|---|---|---|---|
| ali.khan | Ali Khan | ali.khan@orbit.example | IT |
| sara.ahmed | Sara Ahmed | sara.ahmed@orbit.example | IT |
"""
CAL = """# Changes
| Change ID | Description | System / Target | Performed By | Start (PKT) | End (PKT) | Status |
|---|---|---|---|---|---|---|
| CHG-2026-1104-01 | Vulnerability scan | 10.10.2.0/24 | Vulnerability scanner 10.10.9.50 | 2026-11-04 14:00 | 2026-11-04 16:00 | Approved |
| CHG-2026-1104-02 | Web patching | SRV-WEB01 | Ali Khan | 2026-11-04 22:00 | 2026-11-05 02:00 | Approved |
| CHG-2026-1104-03 | DB firewall rule | A-1004 | sara.ahmed | 2026-11-04 10:00 | 2026-11-04 11:00 | Cancelled |
| CHG-2026-1104-04 | Backup run | 10.10.3.10-20, 10.10.3.40 | svc-backup | 2026-11-04 03:00 | 2026-11-04 04:00 | Approved |
| CHG-2026-1104-05 | Security scan | 10.10.7.* | Security scanner | 2026-11-04 17:00 | 2026-11-04 18:00 | Approved |
"""


@pytest.fixture()
def matcher(tmp_path):
    for n, b in (("02_asset_inventory.md", ASSETS), ("18_user_directory.md", USERS),
                 ("05_change_calendar.md", CAL)):
        (tmp_path / n).write_text(b, encoding="utf-8")
    return cm.ChangeMatcher.from_loader(DataLoader(tmp_path))


def act(targets, actors, start, end=None):
    return cm.Activity.create(targets, actors, start, end)


# ---------------------------------------------------------------- calendar parsing
def test_calendar_windows_converted_pkt_to_utc(matcher):
    r = {x.change_id: x for x in matcher.records}
    assert len(r) == 5
    c1 = r["CHG-2026-1104-01"]
    assert (c1.start_utc, c1.end_utc) == (U(2026, 11, 4, 9), U(2026, 11, 4, 11))
    c2 = r["CHG-2026-1104-02"]
    assert (c2.start_utc, c2.end_utc) == (U(2026, 11, 4, 17), U(2026, 11, 4, 21))
    assert not r["CHG-2026-1104-03"].status_ok and r["CHG-2026-1104-01"].status_ok


def test_window_and_date_column_layout(tmp_path):
    (tmp_path / "05_change_calendar.md").write_text("""# C
| Change ID | Title | Affected Systems | Executed By | Date | Window (PKT) | Approval |
|---|---|---|---|---|---|---|
| CHG-X-01 | Scan | 10.1.1.0/24 | 10.10.9.50 | 2026-11-04 | 14:00 - 16:00 | Approved |
| CHG-X-02 | Odd | 10.1.2.0/24 | 10.10.9.50 | 2026-11-04 | garbage | Approved |
""", encoding="utf-8")
    m = cm.ChangeMatcher.from_loader(DataLoader(tmp_path))
    r = {x.change_id: x for x in m.records}
    assert (r["CHG-X-01"].start_utc, r["CHG-X-01"].end_utc) == (U(2026, 11, 4, 9), U(2026, 11, 4, 11))
    assert r["CHG-X-02"].start_utc is None and r["CHG-X-02"].warnings
    # unparseable window can never produce a match
    assert m.match(act("10.1.2.5", "10.10.9.50", U(2026, 11, 4, 9))) is None


# ---------------------------------------------------------------- full matches
def test_scanner_in_window_is_harmless(matcher):
    hit = matcher.match(act("10.10.2.15", "10.10.9.50", U(2026, 11, 4, 9, 0), U(2026, 11, 4, 10, 30)))
    assert hit and hit.change_id == "CHG-2026-1104-01" and hit.harmless
    assert hit.citation == "05_change_calendar.md:CHG-2026-1104-01"
    assert "harmless" in hit.summary()


def test_window_edges_inclusive(matcher):
    assert matcher.match_change_id(act("10.10.2.1", "10.10.9.50", U(2026, 11, 4, 9), U(2026, 11, 4, 11)))
    assert not matcher.match_change_id(act("10.10.2.1", "10.10.9.50", U(2026, 11, 4, 8, 59, 59)))
    assert not matcher.match_change_id(act("10.10.2.1", "10.10.9.50", U(2026, 11, 4, 11, 0, 1)))


def test_tolerance(tmp_path, matcher):
    m = cm.ChangeMatcher(matcher.records, matcher.assets, matcher.users, tolerance_s=60)
    assert m.match_change_id(act("10.10.2.1", "10.10.9.50", U(2026, 11, 4, 11, 0, 30)))


def test_hostname_fqdn_ip_and_user_resolution(matcher):
    start = U(2026, 11, 4, 17, 30)
    for target in ("SRV-WEB01", "srv-web01.orbit.local", "10.10.1.10", "A-1001"):
        for actor in ("ali.khan", "Ali Khan", "ali.khan@orbit.example", "ALI.KHAN"):
            assert matcher.match_change_id(act(target, actor, start)) == "CHG-2026-1104-02", (target, actor)


def test_overnight_window_after_midnight_pkt(matcher):
    # 01:30 PKT on Nov 5 = 20:30Z Nov 4
    assert matcher.match_change_id(act("srv-web01", "ali.khan", U(2026, 11, 4, 20, 30))) == "CHG-2026-1104-02"
    assert matcher.match_change_id(act("srv-web01", "ali.khan", U(2026, 11, 4, 21, 1))) is None


def test_ip_range_and_single_ip_scope(matcher):
    ok = lambda ip: matcher.match_change_id(act(ip, "svc-backup", U(2026, 11, 3, 22, 30)))
    assert ok("10.10.3.15") and ok("10.10.3.40") and ok("10.10.3.10") and ok("10.10.3.20")
    assert not ok("10.10.3.21") and not ok("10.10.3.9")


def test_wildcard_scope_and_scanner_hint(matcher):
    # CHG-05 names "Security scanner" with no IP -> approved scanner IP from config is accepted
    a = act("10.10.7.200", "10.10.9.50", U(2026, 11, 4, 12, 30))
    assert matcher.match_change_id(a) == "CHG-2026-1104-05"
    no_hint = cm.ChangeMatcher(matcher.records, matcher.assets, matcher.users, scanner_ips=())
    assert no_hint.match(a) is None


def test_subnet_activity_target(matcher):
    t = U(2026, 11, 4, 9, 30)
    assert matcher.match_change_id(act("10.10.2.0/25", "10.10.9.50", t))
    assert not matcher.match_change_id(act("10.10.0.0/16", "10.10.9.50", t))
    assert not matcher.match_change_id(act("10.10.2.0/23", "10.10.9.50", t))


# ---------------------------------------------------------------- must NOT match
def test_every_target_must_be_covered(matcher):
    a = act(["10.10.2.15", "10.10.4.1"], "10.10.9.50", U(2026, 11, 4, 9, 30))
    assert matcher.match(a) is None
    lenient = cm.ChangeMatcher(matcher.records, matcher.assets, matcher.users, require_all_targets=False)
    assert lenient.match(a)


def test_wrong_performer_is_a_near_miss(matcher):
    a = act("10.10.2.15", "10.10.5.5", U(2026, 11, 4, 9, 30))
    assert matcher.match(a) is None
    nm = matcher.near_misses(a)
    assert nm[0].change_id == "CHG-2026-1104-01" and nm[0].failed() == ["performer"]
    assert "not the named performer" in nm[0].performer.detail


def test_activity_running_past_window_is_not_harmless(matcher):
    a = act("10.10.2.15", "10.10.9.50", U(2026, 11, 4, 10, 30), U(2026, 11, 4, 11, 45))
    assert matcher.match(a) is None
    nm = matcher.near_misses(a)[0]
    assert nm.failed() == ["time"] and "extends outside" in nm.time.detail and "45m" in nm.time.detail


def test_activity_outside_window_reports_distance(matcher):
    c = matcher.check_time(act("10.10.2.15", "10.10.9.50", U(2026, 11, 4, 13)), matcher.records[0])
    assert not c.ok and "2h 00m 00s after" in c.detail


def test_cancelled_change_never_matches(matcher):
    a = act("10.10.3.4", "sara.ahmed", U(2026, 11, 4, 5, 30))
    assert matcher.match(a) is None
    nm = matcher.near_misses(a)
    assert nm[0].change_id == "CHG-2026-1104-03" and nm[0].failed() == ["status"]


def test_missing_actor_or_target(matcher):
    assert matcher.match(act("10.10.2.15", None, U(2026, 11, 4, 9, 30))) is None
    assert matcher.match(act(None, "10.10.9.50", U(2026, 11, 4, 9, 30))) is None


def test_username_substring_does_not_match(matcher):
    # 'ali' must not be treated as ali.khan, and 'khan' must not either
    for actor in ("ali", "khan", "ali.khan2"):
        assert matcher.match_change_id(act("srv-web01", actor, U(2026, 11, 4, 17, 30))) is None


def test_no_match_returns_none(matcher):
    assert cm.match_change("10.99.99.99", "evil", U(2026, 11, 4, 9), matcher=matcher) is None
    assert cm.match_change("10.10.2.9", "10.10.9.50", U(2026, 11, 4, 9, 30), matcher=matcher) == "CHG-2026-1104-01"


# ---------------------------------------------------------------- helpers / validation
def test_activity_requires_aware_datetimes():
    with pytest.raises(ValueError):
        cm.Activity.create("a", "b", datetime(2026, 11, 4, 9))
    with pytest.raises(ValueError):
        cm.Activity.create("a", "b", U(2026, 11, 4, 9), U(2026, 11, 4, 8))


def test_build_scope_variants():
    sc = cm.build_scope("10.0.0.0/24; 10.0.1.5-9, 10.0.2.1 - 10.0.2.3, 10.0.3.*, A-1001, SRV-X1")
    assert len(sc.networks) == 2 and len(sc.ranges) == 2
    assert {"a-1001", "srv-x1"} <= sc.names
    assert cm.scope_covers(sc, "10.0.1.7") and not cm.scope_covers(sc, "10.0.1.10")
    assert cm.scope_covers(sc, "10.0.3.99") and cm.scope_covers(sc, "SRV-X1")
    assert not cm.scope_covers(cm.build_scope("all servers"), "10.0.0.1")     # no wildcard words


def test_norm_id_keeps_usernames_whole():
    assert cm.norm_id(" Ali.Khan. ") == "ali.khan" and cm.norm_id("**`A-1001`**") == "a-1001"
    assert cm.norm_id("10.0.0.1") == "10.0.0.1" and cm.norm_id("A@b.com") == "a@b.com"


def test_short_host_only_for_fqdns():
    assert cm.short_host("srv-web01.orbit.local") == "srv-web01"
    for keep in ("10.0.0.1", "a@b.com", "10.0.0.0/24", "srv-web01"):
        assert cm.short_host(keep) == keep
