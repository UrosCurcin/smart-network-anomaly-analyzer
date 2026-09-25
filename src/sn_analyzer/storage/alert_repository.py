"""SQLite persistence for alert history."""

from __future__ import annotations

from contextlib import AbstractContextManager
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any

import numpy as np

from ..alerting.alert_manager import Alert
from ..alerting.sinks import AlertSink
from ..features.schemas import FeatureVector
from ..inference.engine import InferenceResult
from ..ingestion.stream_demux import Endpoint, StreamKey

_SEVERITIES = ("low", "medium", "high", "critical")
_MAX_PAGE_SIZE = 1000

# Schema migrations, applied in order.  ``PRAGMA user_version`` records how many
# have run, so the database upgrades itself.  Never edit a released entry:
# append a new one instead.
_MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE alerts (
        alert_id              TEXT PRIMARY KEY,
        created_at            TEXT NOT NULL,
        severity              TEXT NOT NULL
            CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        anomaly_score         REAL NOT NULL,
        window_end            TEXT NOT NULL,
        protocol              TEXT NOT NULL,
        endpoint_a_address    TEXT NOT NULL,
        endpoint_a_port       INTEGER,
        endpoint_b_address    TEXT NOT NULL,
        endpoint_b_port       INTEGER,
        suspicious_ips        TEXT NOT NULL,
        evidence_pcap_path    TEXT,
        model_scores          TEXT NOT NULL,
        contributing_features TEXT NOT NULL,
        feature_names         TEXT NOT NULL,
        feature_values        TEXT NOT NULL,
        packet_ids            TEXT NOT NULL
    );
    CREATE INDEX idx_alerts_created_at ON alerts (created_at);
    CREATE INDEX idx_alerts_severity ON alerts (severity, created_at);
    CREATE INDEX idx_alerts_endpoint_a ON alerts (endpoint_a_address);
    CREATE INDEX idx_alerts_endpoint_b ON alerts (endpoint_b_address);
    """,
    """
    ALTER TABLE alerts ADD COLUMN acknowledged INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX idx_alerts_acknowledged ON alerts (acknowledged, created_at);
    """,
)


class AlertRepositoryError(RuntimeError):
    """Raised when alerts cannot be stored, read, or the database is unusable."""


class AlertRepository(AbstractContextManager["AlertRepository"]):
    """Thread-safe store of :class:`Alert` history in one SQLite database.

    A single connection is shared behind a lock, which suits an analysis thread
    writing while an API thread reads.  Write-ahead logging lets other
    processes (for example a dashboard) read the same file concurrently.
    Timestamps are stored as fixed-width UTC ISO-8601 text, which sorts
    chronologically.  Use ``":memory:"`` as the path for a throwaway database.
    """

    def __init__(self, path: str | Path) -> None:
        """Open (creating and migrating if necessary) the database at ``path``."""
        self._lock = RLock()
        self._connection: sqlite3.Connection | None = None

        if str(path) == ":memory:":
            location = ":memory:"
        else:
            database_path = Path(path).expanduser().resolve()
            try:
                database_path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise AlertRepositoryError(
                    f"cannot create database directory: {database_path.parent}"
                ) from exc
            location = str(database_path)
        self._location = location

        try:
            connection = sqlite3.connect(location, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            self._connection = connection
            connection.execute("PRAGMA busy_timeout = 5000")
            if location != ":memory:":
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = NORMAL")
            self._migrate()
        except AlertRepositoryError:
            self.close()
            raise
        except sqlite3.Error as exc:
            self.close()
            raise AlertRepositoryError(f"unable to open alert database: {location}") from exc

    @property
    def location(self) -> str:
        """Return the resolved database file path, or ``":memory:"``."""
        return self._location

    def close(self) -> None:
        """Close the database; safe to call more than once."""
        with self._lock:
            connection, self._connection = self._connection, None
        if connection is not None:
            connection.close()

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Close the database when leaving a ``with`` block."""
        self.close()

    def add_alert(self, alert: Alert) -> None:
        """Persist one alert.

        Raises:
            AlertRepositoryError: If the alert id already exists or the write fails.
        """
        if not isinstance(alert, Alert):
            raise TypeError("alert must be an Alert")
        row = self._alert_to_row(alert)
        columns = ", ".join(row)
        placeholders = ", ".join(f":{name}" for name in row)
        try:
            with self._lock:
                connection = self._require_open()
                with connection:
                    connection.execute(
                        f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", row
                    )
        except sqlite3.IntegrityError as exc:
            raise AlertRepositoryError(
                f"alert {alert.alert_id!r} could not be stored (duplicate id?)"
            ) from exc
        except sqlite3.Error as exc:
            raise AlertRepositoryError(f"failed to store alert {alert.alert_id!r}") from exc

    def get_alert(self, alert_id: str) -> Alert | None:
        """Return the alert with ``alert_id``, or ``None`` when it does not exist."""
        if not alert_id or not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")
        rows = self._query("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        return self._row_to_alert(rows[0]) if rows else None

    def list_alerts(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        acknowledged: bool | None = None,
        newest_first: bool = True,
    ) -> list[Alert]:
        """Return a page of alerts, newest first by default.

        Args:
            limit: Page size, from 1 to 1000.
            offset: Number of matching alerts to skip.
            severity: Only alerts of this severity.
            ip: Only alerts whose flow involves this IP address.
            since: Only alerts created at or after this timezone-aware time.
            until: Only alerts created strictly before this timezone-aware time.
            acknowledged: Only alerts marked observed (``True``) or not (``False``).
            newest_first: Sort direction of ``created_at``.
        """
        if not 1 <= limit <= _MAX_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {_MAX_PAGE_SIZE}")
        if offset < 0:
            raise ValueError("offset must not be negative")
        where, parameters = self._where(severity, ip, since, until, acknowledged)
        direction = "DESC" if newest_first else "ASC"
        rows = self._query(
            f"SELECT * FROM alerts{where} "
            f"ORDER BY created_at {direction}, alert_id {direction} LIMIT ? OFFSET ?",
            (*parameters, limit, offset),
        )
        return [self._row_to_alert(row) for row in rows]

    def count_alerts(
        self,
        *,
        severity: str | None = None,
        ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        acknowledged: bool | None = None,
    ) -> int:
        """Return how many alerts match the same filters as :meth:`list_alerts`."""
        where, parameters = self._where(severity, ip, since, until, acknowledged)
        rows = self._query(f"SELECT COUNT(*) AS total FROM alerts{where}", parameters)
        return int(rows[0]["total"])

    def count_by_severity(
        self,
        *,
        ip: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> dict[str, int]:
        """Return alert counts for every severity, including those with zero."""
        where, parameters = self._where(None, ip, since, until)
        rows = self._query(
            f"SELECT severity, COUNT(*) AS total FROM alerts{where} GROUP BY severity",
            parameters,
        )
        counts = {severity: 0 for severity in _SEVERITIES}
        counts.update({row["severity"]: int(row["total"]) for row in rows})
        return counts

    def set_acknowledged(self, alert_id: str, acknowledged: bool = True) -> bool:
        """Mark one alert as observed, or clear that mark.

        Returns:
            Whether an alert with ``alert_id`` existed to update.
        """
        if not alert_id or not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")
        try:
            with self._lock:
                connection = self._require_open()
                with connection:
                    cursor = connection.execute(
                        "UPDATE alerts SET acknowledged = ? WHERE alert_id = ?",
                        (1 if acknowledged else 0, alert_id),
                    )
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            raise AlertRepositoryError(f"failed to update alert {alert_id!r}") from exc

    def delete_alert(self, alert_id: str) -> bool:
        """Delete one alert.

        Callers that need to remove its evidence PCAP too should read the
        alert with :meth:`get_alert` first, since this only touches the
        database, not the filesystem.

        Returns:
            Whether an alert with ``alert_id`` existed to delete.
        """
        if not alert_id or not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")
        try:
            with self._lock:
                connection = self._require_open()
                with connection:
                    cursor = connection.execute(
                        "DELETE FROM alerts WHERE alert_id = ?", (alert_id,)
                    )
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            raise AlertRepositoryError(f"failed to delete alert {alert_id!r}") from exc

    def clear_alerts(self) -> tuple[int, list[str]]:
        """Delete every stored alert.

        The database is the source of truth for which evidence files were
        ever referenced, not the filesystem, so this hands back every
        referenced path in the same transaction that removes the rows. The
        repository only knows about the database; callers are responsible
        for removing those files themselves.

        Returns:
            A tuple of ``(alerts_deleted, evidence_pcap_paths)``.
        """
        try:
            with self._lock:
                connection = self._require_open()
                with connection:
                    rows = connection.execute(
                        "SELECT evidence_pcap_path FROM alerts "
                        "WHERE evidence_pcap_path IS NOT NULL"
                    ).fetchall()
                    cursor = connection.execute("DELETE FROM alerts")
                return cursor.rowcount, [row["evidence_pcap_path"] for row in rows]
        except sqlite3.Error as exc:
            raise AlertRepositoryError("failed to clear alerts") from exc

    def _migrate(self) -> None:
        """Bring the schema up to date, refusing databases from newer versions."""
        with self._lock:
            connection = self._require_open()
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > len(_MIGRATIONS):
                raise AlertRepositoryError(
                    f"database schema version {version} is newer than this program "
                    f"supports ({len(_MIGRATIONS)}); upgrade the analyzer"
                )
            for target in range(version + 1, len(_MIGRATIONS) + 1):
                try:
                    connection.executescript(
                        f"BEGIN;\n{_MIGRATIONS[target - 1]}\n"
                        f"PRAGMA user_version = {target};\nCOMMIT;"
                    )
                except sqlite3.Error as exc:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise AlertRepositoryError(
                        f"failed to migrate alert database to version {target}"
                    ) from exc

    def _require_open(self) -> sqlite3.Connection:
        """Return the live connection or fail clearly after :meth:`close`."""
        if self._connection is None:
            raise AlertRepositoryError("the alert repository is closed")
        return self._connection

    def _query(self, sql: str, parameters: tuple[Any, ...]) -> list[sqlite3.Row]:
        """Run a read-only statement and return all rows."""
        try:
            with self._lock:
                return self._require_open().execute(sql, parameters).fetchall()
        except sqlite3.Error as exc:
            raise AlertRepositoryError("failed to read alerts") from exc

    @staticmethod
    def _where(
        severity: str | None,
        ip: str | None,
        since: datetime | None,
        until: datetime | None,
        acknowledged: bool | None = None,
    ) -> tuple[str, tuple[Any, ...]]:
        """Build a parameterized WHERE clause; values are never interpolated."""
        clauses: list[str] = []
        parameters: list[Any] = []
        if severity is not None:
            if severity not in _SEVERITIES:
                raise ValueError(f"severity must be one of {', '.join(_SEVERITIES)}")
            clauses.append("severity = ?")
            parameters.append(severity)
        if ip is not None:
            try:
                address = ip_address(ip).compressed
            except ValueError as exc:
                raise ValueError(f"invalid IP address: {ip!r}") from exc
            clauses.append("(endpoint_a_address = ? OR endpoint_b_address = ?)")
            parameters.extend((address, address))
        if since is not None:
            clauses.append("created_at >= ?")
            parameters.append(_to_db_time(since))
        if until is not None:
            clauses.append("created_at < ?")
            parameters.append(_to_db_time(until))
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            parameters.append(1 if acknowledged else 0)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, tuple(parameters)

    @staticmethod
    def _alert_to_row(alert: Alert) -> dict[str, Any]:
        """Flatten an alert into column values; detail fields are stored as JSON."""
        result = alert.result
        observation = result.observation
        key = observation.stream_key
        return {
            "alert_id": alert.alert_id,
            "created_at": _to_db_time(alert.created_at),
            "severity": alert.severity,
            "anomaly_score": result.anomaly_score,
            "window_end": _to_db_time(observation.timestamp),
            "protocol": key.protocol,
            "endpoint_a_address": key.endpoint_a.address,
            "endpoint_a_port": key.endpoint_a.port,
            "endpoint_b_address": key.endpoint_b.address,
            "endpoint_b_port": key.endpoint_b.port,
            "suspicious_ips": json.dumps(list(alert.suspicious_ips)),
            "evidence_pcap_path": alert.evidence_pcap_path,
            "acknowledged": int(alert.acknowledged),
            "model_scores": json.dumps(result.model_scores),
            "contributing_features": json.dumps(result.contributing_features),
            "feature_names": json.dumps(list(observation.feature_names)),
            "feature_values": json.dumps([float(value) for value in observation.values]),
            "packet_ids": json.dumps(list(observation.packet_ids)),
        }

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        """Rebuild a validated :class:`Alert` from a stored row."""
        try:
            stream_key = StreamKey(
                row["protocol"],
                Endpoint(row["endpoint_a_address"], row["endpoint_a_port"]),
                Endpoint(row["endpoint_b_address"], row["endpoint_b_port"]),
            )
            observation = FeatureVector(
                stream_key=stream_key,
                timestamp=datetime.fromisoformat(row["window_end"]),
                values=np.array(json.loads(row["feature_values"]), dtype=float),
                feature_names=tuple(json.loads(row["feature_names"])),
                packet_ids=tuple(json.loads(row["packet_ids"])),
            )
            result = InferenceResult(
                observation=observation,
                anomaly_score=row["anomaly_score"],
                is_anomalous=True,
                model_scores=json.loads(row["model_scores"]),
                contributing_features=json.loads(row["contributing_features"]),
            )
            return Alert(
                alert_id=row["alert_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                severity=row["severity"],
                result=result,
                suspicious_ips=tuple(json.loads(row["suspicious_ips"])),
                evidence_pcap_path=row["evidence_pcap_path"],
                acknowledged=bool(row["acknowledged"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            # JSONDecodeError and the domain validators all derive from ValueError.
            raise AlertRepositoryError(
                f"stored alert {row['alert_id']!r} is corrupt or incompatible"
            ) from exc


class SqliteAlertSink(AlertSink):
    """Alert sink that records every alert in an :class:`AlertRepository`.

    The repository stays owned by the caller, who is responsible for closing it.
    """

    def __init__(self, repository: AlertRepository) -> None:
        """Bind the sink to an open repository."""
        if not isinstance(repository, AlertRepository):
            raise TypeError("repository must be an AlertRepository")
        self._repository = repository

    def publish(self, alert: Alert) -> None:
        """Store the alert."""
        self._repository.add_alert(alert)


def _to_db_time(value: datetime) -> str:
    """Format a timezone-aware time as fixed-width UTC text that sorts correctly."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
