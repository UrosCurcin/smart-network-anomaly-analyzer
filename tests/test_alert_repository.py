"""Tests for SQLite alert persistence."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import threading

import numpy as np
import pytest

from sn_analyzer.ingestion.stream_demux import Endpoint, StreamKey
from sn_analyzer.storage.alert_repository import (
    AlertRepository,
    AlertRepositoryError,
    SqliteAlertSink,
)


@pytest.fixture
def repository():
    """An in-memory repository closed after each test."""
    with AlertRepository(":memory:") as repo:
        yield repo


def test_alert_round_trips_with_full_fidelity(repository, alert_factory) -> None:
    """Everything a dashboard needs comes back exactly as it was stored."""
    original = alert_factory(alert_id="a-1", score=0.912345678901234, packet_ids=(4, 5, 9))

    repository.add_alert(original)
    loaded = repository.get_alert("a-1")

    assert loaded is not None
    assert loaded.alert_id == original.alert_id
    assert loaded.created_at == original.created_at
    assert loaded.severity == original.severity
    assert loaded.suspicious_ips == original.suspicious_ips
    assert loaded.evidence_pcap_path == original.evidence_pcap_path
    assert loaded.result.anomaly_score == original.result.anomaly_score
    assert loaded.result.model_scores == original.result.model_scores
    assert loaded.result.contributing_features == original.result.contributing_features
    left, right = loaded.result.observation, original.result.observation
    assert left.stream_key == right.stream_key
    assert left.timestamp == right.timestamp
    assert left.feature_names == right.feature_names
    assert left.packet_ids == right.packet_ids
    assert np.array_equal(left.values, right.values)
    assert not left.values.flags.writeable


def test_ipv6_flows_and_portless_flows_round_trip(repository, alert_factory) -> None:
    """IPv6 addresses, missing ports and a missing evidence path are preserved."""
    v6 = StreamKey("UDP", Endpoint("2001:db8::2", 5353), Endpoint("2001:db8::1", 5353))
    arp = StreamKey("ARP", Endpoint("192.168.1.10"), Endpoint("192.168.1.20"))
    repository.add_alert(alert_factory(alert_id="v6", stream_key=v6))
    repository.add_alert(alert_factory(alert_id="arp", stream_key=arp, evidence_path=None))

    assert repository.get_alert("v6").result.observation.stream_key == v6
    stored_arp = repository.get_alert("arp")
    assert stored_arp.result.observation.stream_key == arp
    assert stored_arp.result.observation.stream_key.endpoint_a.port is None
    assert stored_arp.evidence_pcap_path is None


def test_unknown_and_blank_ids(repository) -> None:
    """A missing alert is None; a blank id is a caller error."""
    assert repository.get_alert("nope") is None
    with pytest.raises(ValueError):
        repository.get_alert("  ")


def test_duplicate_alert_id_is_rejected(repository, alert_factory) -> None:
    """Alert ids are unique; a second insert fails without altering the first."""
    repository.add_alert(alert_factory(alert_id="dup", score=0.9))

    with pytest.raises(AlertRepositoryError, match="duplicate"):
        repository.add_alert(alert_factory(alert_id="dup", score=0.99))

    assert repository.get_alert("dup").result.anomaly_score == 0.9


def test_only_alerts_can_be_stored(repository) -> None:
    """Wrong types fail fast."""
    with pytest.raises(TypeError):
        repository.add_alert("not an alert")  # type: ignore[arg-type]


def test_listing_is_newest_first_and_paginates(repository, alert_factory) -> None:
    """Ordering is chronological even when some timestamps have no microseconds."""
    for index, offset in enumerate((0.0, 0.5, 1.0, 1.5, 2.0)):
        repository.add_alert(alert_factory(alert_id=f"a{index}", offset_seconds=offset))

    newest = [alert.alert_id for alert in repository.list_alerts()]
    oldest = [alert.alert_id for alert in repository.list_alerts(newest_first=False)]
    page = [alert.alert_id for alert in repository.list_alerts(limit=2, offset=1)]

    assert newest == ["a4", "a3", "a2", "a1", "a0"]
    assert oldest == ["a0", "a1", "a2", "a3", "a4"]
    assert page == ["a3", "a2"]


def test_filters_by_severity_ip_and_time(repository, alert_factory, base_time) -> None:
    """Filters combine with AND and use half-open time ranges."""
    other = StreamKey("TCP", Endpoint("172.16.0.9", 1), Endpoint("2001:db8::7", 2))
    repository.add_alert(alert_factory(alert_id="low", severity="low", offset_seconds=0))
    repository.add_alert(alert_factory(alert_id="high", severity="high", offset_seconds=10))
    repository.add_alert(
        alert_factory(alert_id="v6", severity="high", offset_seconds=20, stream_key=other)
    )

    ids = lambda **kw: sorted(a.alert_id for a in repository.list_alerts(**kw))  # noqa: E731

    assert ids(severity="high") == ["high", "v6"]
    assert ids(ip="10.0.0.2") == ["high", "low"]  # matches the second endpoint
    assert ids(ip="172.16.0.9") == ["v6"]  # matches the first endpoint
    assert ids(ip="2001:0db8:0000:0000:0000:0000:0000:0007") == ["v6"]  # uncompressed form
    assert ids(since=base_time + timedelta(seconds=10)) == ["high", "v6"]  # inclusive
    assert ids(until=base_time + timedelta(seconds=10)) == ["low"]  # exclusive
    assert ids(severity="high", ip="10.0.0.1") == ["high"]
    assert repository.count_alerts(severity="high") == 2
    assert repository.count_alerts() == 3
    assert repository.count_alerts(ip="10.0.0.1", severity="low") == 1


def test_new_alerts_start_unacknowledged(repository, alert_factory) -> None:
    """The default matches a freshly created, never-reviewed alert."""
    repository.add_alert(alert_factory(alert_id="a1"))

    assert repository.get_alert("a1").acknowledged is False


def test_set_acknowledged_updates_and_reports_whether_the_alert_existed(
    repository, alert_factory
) -> None:
    """Marking observed (and clearing that mark) both round-trip; a missing id is False."""
    repository.add_alert(alert_factory(alert_id="a1"))

    assert repository.set_acknowledged("a1", True) is True
    assert repository.get_alert("a1").acknowledged is True

    assert repository.set_acknowledged("a1", False) is True
    assert repository.get_alert("a1").acknowledged is False

    assert repository.set_acknowledged("does-not-exist", True) is False


def test_set_acknowledged_rejects_a_blank_id(repository) -> None:
    with pytest.raises(ValueError):
        repository.set_acknowledged("  ", True)


def test_filters_by_acknowledged(repository, alert_factory) -> None:
    """Alerts already reviewed can be told apart from ones still pending."""
    repository.add_alert(alert_factory(alert_id="seen", acknowledged=True))
    repository.add_alert(alert_factory(alert_id="unseen", acknowledged=False))

    assert [a.alert_id for a in repository.list_alerts(acknowledged=True)] == ["seen"]
    assert [a.alert_id for a in repository.list_alerts(acknowledged=False)] == ["unseen"]
    assert repository.count_alerts(acknowledged=True) == 1
    assert repository.count_alerts(acknowledged=False) == 1
    assert repository.count_alerts() == 2


def test_delete_alert_removes_it_and_reports_whether_it_existed(
    repository, alert_factory
) -> None:
    """A delete is idempotent to observe: the second call just reports nothing changed."""
    repository.add_alert(alert_factory(alert_id="a1"))
    repository.add_alert(alert_factory(alert_id="a2"))

    assert repository.delete_alert("a1") is True
    assert repository.get_alert("a1") is None
    assert repository.get_alert("a2") is not None
    assert repository.delete_alert("a1") is False


def test_delete_alert_rejects_a_blank_id(repository) -> None:
    with pytest.raises(ValueError):
        repository.delete_alert(" ")


def test_clear_alerts_empties_the_table_and_returns_evidence_paths(
    repository, alert_factory
) -> None:
    """Every row is gone, and every referenced evidence path comes back for cleanup."""
    repository.add_alert(alert_factory(alert_id="a1", evidence_path="/evidence/a1.pcap"))
    repository.add_alert(alert_factory(alert_id="a2", evidence_path=None))
    repository.add_alert(alert_factory(alert_id="a3", evidence_path="/evidence/a3.pcap"))

    deleted, evidence_paths = repository.clear_alerts()

    assert deleted == 3
    assert sorted(evidence_paths) == ["/evidence/a1.pcap", "/evidence/a3.pcap"]
    assert repository.count_alerts() == 0
    assert repository.list_alerts() == []


def test_clear_alerts_on_an_empty_table_is_a_no_op(repository) -> None:
    assert repository.clear_alerts() == (0, [])


def test_count_by_severity_includes_zero_counts(repository, alert_factory) -> None:
    """Dashboards can rely on all four severities being present."""
    repository.add_alert(alert_factory(severity="critical"))
    repository.add_alert(alert_factory(severity="critical"))
    repository.add_alert(alert_factory(severity="low"))

    assert repository.count_by_severity() == {
        "low": 1, "medium": 0, "high": 0, "critical": 2,
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"limit": 0},
        {"limit": 1001},
        {"offset": -1},
        {"severity": "urgent"},
        {"ip": "not-an-ip"},
        {"ip": "10.0.0.1' OR '1'='1"},
        {"since": datetime(2026, 1, 1)},  # naive
    ],
)
def test_invalid_query_arguments_are_rejected(repository, kwargs) -> None:
    """Bad input is refused before it reaches SQL."""
    with pytest.raises(ValueError):
        repository.list_alerts(**kwargs)


def test_data_survives_reopening_and_records_schema_version(
    tmp_path: Path, alert_factory
) -> None:
    """A file database persists, creates missing folders, and is versioned."""
    path = tmp_path / "nested" / "dir" / "alerts.db"

    with AlertRepository(path) as first:
        first.add_alert(alert_factory(alert_id="keep"))
        location = first.location
    with AlertRepository(path) as second:
        assert second.get_alert("keep") is not None

    assert Path(location) == path.resolve()
    with sqlite3.connect(path) as raw:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == 2
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_database_from_a_newer_version_is_refused(tmp_path: Path) -> None:
    """Never write to a schema this program does not understand."""
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as raw:
        raw.execute("PRAGMA user_version = 99")

    with pytest.raises(AlertRepositoryError, match="newer"):
        AlertRepository(path)


def test_corrupt_rows_raise_a_clear_error(tmp_path: Path, alert_factory) -> None:
    """A damaged row is reported by id instead of returning bad data."""
    path = tmp_path / "alerts.db"
    with AlertRepository(path) as repo:
        repo.add_alert(alert_factory(alert_id="broken"))
    with sqlite3.connect(path) as raw:
        raw.execute("UPDATE alerts SET feature_values = '[]' WHERE alert_id = 'broken'")

    with AlertRepository(path) as repo, pytest.raises(AlertRepositoryError, match="broken"):
        repo.get_alert("broken")


def test_closed_repository_fails_clearly_and_close_is_idempotent(alert_factory) -> None:
    """Using a closed repository is an error, not a crash."""
    repo = AlertRepository(":memory:")
    repo.close()
    repo.close()

    with pytest.raises(AlertRepositoryError, match="closed"):
        repo.add_alert(alert_factory())
    with pytest.raises(AlertRepositoryError, match="closed"):
        repo.count_alerts()


def test_concurrent_writers_and_a_reader_do_not_conflict(
    tmp_path: Path, alert_factory
) -> None:
    """The analysis thread and an API thread can share one repository."""
    repo = AlertRepository(tmp_path / "alerts.db")
    errors: list[BaseException] = []
    stop_reading = threading.Event()

    def write(worker: int) -> None:
        try:
            for index in range(25):
                repo.add_alert(alert_factory(alert_id=f"w{worker}-{index}"))
        except BaseException as exc:  # noqa: BLE001 - reported by the assertion below
            errors.append(exc)

    def read() -> None:
        try:
            while not stop_reading.is_set():
                repo.list_alerts(limit=10)
                repo.count_by_severity()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    reader = threading.Thread(target=read)
    writers = [threading.Thread(target=write, args=(n,)) for n in range(4)]
    reader.start()
    for thread in writers:
        thread.start()
    for thread in writers:
        thread.join(timeout=30)
    stop_reading.set()
    reader.join(timeout=30)

    try:
        assert errors == []
        assert repo.count_alerts() == 100
    finally:
        repo.close()


def test_sqlite_sink_stores_published_alerts(repository, alert_factory) -> None:
    """The sink is a thin adapter from AlertSink to the repository."""
    SqliteAlertSink(repository).publish(alert_factory(alert_id="via-sink"))

    assert repository.get_alert("via-sink") is not None


def test_sink_requires_a_repository() -> None:
    """Wrong construction fails immediately."""
    with pytest.raises(TypeError):
        SqliteAlertSink(object())  # type: ignore[arg-type]
