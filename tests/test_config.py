"""Tests for layered configuration and its command-line integration."""

from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path

import pytest

from sn_analyzer import cli
from sn_analyzer.config import (
    CONFIG_FILE_ENV_VAR,
    AppSettings,
    ConfigError,
    load_settings,
)
from sn_analyzer.ingestion.base import PacketSource

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Remove SN_ variables from the developer's shell and use a clean cwd."""
    for name in list(os.environ):
        if name.startswith("SN_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_match_the_previous_command_line_defaults() -> None:
    """Adding configuration must not change behavior for existing users."""
    settings = load_settings()

    assert settings.model.save_path is None
    assert settings.analysis.threshold == 0.80
    assert settings.analysis.window_packets == 50
    assert settings.analysis.window_seconds == 30.0
    assert settings.analysis.bootstrap_windows == 100
    assert settings.analysis.max_active_flows == 10_000
    assert settings.analysis.tick_seconds == 1.0
    assert settings.storage.evidence_dir == Path("artifacts/evidence")
    assert settings.capture.interface is None
    assert settings.capture.promiscuous is False
    assert settings.capture.pcap_dir == Path("logs")
    assert settings.model.path is None
    assert settings.model.model_dir == Path("models")
    assert settings.logging.level == "INFO"


def test_derived_durations() -> None:
    """Second-based fields are exposed as timedeltas for the pipeline."""
    analysis = load_settings().analysis

    assert analysis.window_duration == timedelta(seconds=30)
    assert analysis.stream_idle_timeout == timedelta(minutes=5)
    assert analysis.alert_cooldown == timedelta(minutes=5)
    assert analysis.tick_interval == timedelta(seconds=1)


def test_shipped_default_yaml_matches_builtin_defaults() -> None:
    """configs/default.yaml documents the defaults, so it must never drift."""
    sample = REPOSITORY_ROOT / "configs" / "default.yaml"

    assert load_settings(sample) == AppSettings()


def test_yaml_values_override_defaults_field_by_field(tmp_path: Path) -> None:
    """A file that sets one field keeps the defaults of the rest of its section."""
    path = _write(tmp_path / "c.yaml", "analysis:\n  threshold: 0.7\n")

    settings = load_settings(path)

    assert settings.analysis.threshold == 0.7
    assert settings.analysis.window_packets == 50


def test_environment_overrides_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Environment variables outrank the YAML file but keep its other values."""
    path = _write(tmp_path / "c.yaml", "analysis:\n  threshold: 0.7\n  window_packets: 20\n")
    monkeypatch.setenv("SN_ANALYSIS__THRESHOLD", "0.9")

    settings = load_settings(path)

    assert settings.analysis.threshold == 0.9
    assert settings.analysis.window_packets == 20


def test_explicit_overrides_beat_environment_and_none_clears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Command-line style overrides win, and an explicit None unsets a path."""
    path = _write(tmp_path / "c.yaml", "storage:\n  database_path: from_file.db\n")
    monkeypatch.setenv("SN_ANALYSIS__THRESHOLD", "0.9")

    settings = load_settings(
        path,
        {"analysis": {"threshold": 0.95}, "storage": {"database_path": None}},
    )

    assert settings.analysis.threshold == 0.95
    assert settings.storage.database_path is None


def test_config_file_can_come_from_environment_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SN_CONFIG_FILE is used when no path is passed, and an argument wins over it."""
    from_env = _write(tmp_path / "env.yaml", "analysis:\n  window_packets: 11\n")
    explicit = _write(tmp_path / "arg.yaml", "analysis:\n  window_packets: 22\n")
    monkeypatch.setenv(CONFIG_FILE_ENV_VAR, str(from_env))

    assert load_settings().analysis.window_packets == 11
    assert load_settings(explicit).analysis.window_packets == 22


def test_blank_optional_values_mean_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty variable disables the database instead of meaning the cwd."""
    monkeypatch.setenv("SN_STORAGE__DATABASE_PATH", "")
    monkeypatch.setenv("SN_CAPTURE__INTERFACE", "   ")

    settings = load_settings()

    assert settings.storage.database_path is None
    assert settings.capture.interface is None


def test_log_level_is_normalized_and_validated() -> None:
    """Level names are case-insensitive, and unknown levels are rejected."""
    assert load_settings(overrides={"logging": {"level": "debug"}}).logging.level == "DEBUG"
    with pytest.raises(ConfigError):
        load_settings(overrides={"logging": {"level": "chatty"}})


def test_missing_config_file_is_an_error(tmp_path: Path) -> None:
    """An explicitly requested file that does not exist must not be ignored."""
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "missing.yaml")


def test_unknown_keys_are_rejected_in_file_and_overrides(tmp_path: Path) -> None:
    """Typos fail loudly and name the offending key."""
    path = _write(tmp_path / "c.yaml", "analysis:\n  thresold: 0.5\n")

    with pytest.raises(ConfigError, match="analysis.thresold"):
        load_settings(path)
    with pytest.raises(ConfigError, match="analysis.thresold"):
        load_settings(overrides={"analysis": {"thresold": 0.5}})
    with pytest.raises(ConfigError, match="anaylsis"):
        load_settings(_write(tmp_path / "d.yaml", "anaylsis: {}\n"))


def test_invalid_values_report_every_problem(tmp_path: Path) -> None:
    """All bad fields are listed together, with their dotted names."""
    with pytest.raises(ConfigError) as caught:
        load_settings(
            overrides={"analysis": {"threshold": 2, "window_packets": 0}}
        )

    message = str(caught.value)
    assert "analysis.threshold" in message
    assert "analysis.window_packets" in message


def test_malformed_yaml_is_a_config_error(tmp_path: Path) -> None:
    """Syntax errors surface as ConfigError with the file name."""
    path = _write(tmp_path / "bad.yaml", "analysis: {threshold: 0.5\n")

    with pytest.raises(ConfigError, match="bad.yaml"):
        load_settings(path)


def test_empty_yaml_file_uses_defaults(tmp_path: Path) -> None:
    """A blank file is valid and changes nothing."""
    assert load_settings(_write(tmp_path / "e.yaml", "")) == AppSettings()


def test_resolve_pcap_looks_up_a_bare_filename_under_pcap_dir() -> None:
    """A plain filename is found in the configured directory, not the cwd."""
    settings = load_settings(overrides={"capture": {"pcap_dir": "captures"}})

    assert settings.capture.resolve_pcap("traffic.pcap") == Path("captures/traffic.pcap")


def test_resolve_pcap_leaves_paths_with_a_directory_component_alone() -> None:
    """Anything that already names a directory is trusted as given."""
    settings = load_settings(overrides={"capture": {"pcap_dir": "captures"}})

    assert settings.capture.resolve_pcap("other/traffic.pcap") == Path("other/traffic.pcap")
    assert settings.capture.resolve_pcap("./traffic.pcap") == Path("./traffic.pcap")
    assert settings.capture.resolve_pcap("/abs/traffic.pcap") == Path("/abs/traffic.pcap")


def test_resolve_pcap_leaves_dot_and_dotdot_alone() -> None:
    """'.' and '..' are directory references, not filenames, so they pass through."""
    settings = load_settings(overrides={"capture": {"pcap_dir": "captures"}})

    assert settings.capture.resolve_pcap(".") == Path(".")
    assert settings.capture.resolve_pcap("..") == Path("..")


def test_resolve_model_looks_up_a_bare_filename_under_model_dir() -> None:
    """A plain model filename is found in the configured directory, not the cwd."""
    settings = load_settings(overrides={"model": {"model_dir": "artifacts_models"}})

    assert settings.model.resolve_model("trained.joblib") == Path("artifacts_models/trained.joblib")


def test_resolve_model_leaves_paths_with_a_directory_component_alone() -> None:
    """A path that already names a directory is trusted as given."""
    settings = load_settings(overrides={"model": {"model_dir": "artifacts_models"}})

    assert settings.model.resolve_model("other/trained.joblib") == Path("other/trained.joblib")
    assert settings.model.resolve_model("/abs/trained.joblib") == Path("/abs/trained.joblib")


def test_settings_are_immutable() -> None:
    """Configuration cannot be changed after it has been validated."""
    settings = load_settings()

    with pytest.raises(Exception):
        settings.analysis.threshold = 0.1  # type: ignore[misc]


# --- command-line integration -------------------------------------------------


def _parse(*argv: str):
    return cli.build_parser().parse_args(list(argv))


def test_untyped_options_produce_no_overrides() -> None:
    """Only options the user typed may override the file and environment."""
    assert cli._settings_overrides(_parse("--pcap", "x.pcap")) == {}


def test_typed_options_map_to_settings_sections() -> None:
    """Each flag lands in the matching settings section and field."""
    args = _parse(
        "--interface", "eth0", "--bpf", "tcp", "--promiscuous", "--model", "m.joblib",
        "--save-model", "trained.joblib",
        "--threshold", "0.9", "--window-packets", "10", "--window-seconds", "5",
        "--bootstrap-windows", "7", "--max-flows", "99", "--tick-seconds", "2",
        "--evidence-dir", "ev", "--db-path", "a.db", "--verbose",
    )

    assert cli._settings_overrides(args) == {
        "capture": {"interface": "eth0", "bpf_filter": "tcp", "promiscuous": True},
        "model": {"path": "m.joblib", "save_path": "trained.joblib"},
        "analysis": {
            "threshold": 0.9,
            "window_packets": 10,
            "window_seconds": 5.0,
            "bootstrap_windows": 7,
            "max_active_flows": 99,
            "tick_seconds": 2.0,
        },
        "storage": {"evidence_dir": "ev", "database_path": "a.db"},
        "logging": {"level": "DEBUG"},
    }


def test_save_model_option_is_independently_optional() -> None:
    """--save-model alone (no --model) still produces the right override."""
    args = _parse("--pcap", "x", "--save-model", "trained.joblib")

    assert cli._settings_overrides(args) == {"model": {"save_path": "trained.joblib"}}


def test_no_db_flag_disables_the_database() -> None:
    """--no-db clears the configured database path."""
    settings = load_settings(overrides=cli._settings_overrides(_parse("--no-db", "--pcap", "x")))

    assert settings.storage.database_path is None


def test_full_precedence_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """defaults < file < environment < command line, resolved per field."""
    path = _write(
        tmp_path / "c.yaml",
        "analysis:\n  threshold: 0.6\n  window_packets: 20\n  window_seconds: 10\n",
    )
    monkeypatch.setenv("SN_ANALYSIS__WINDOW_PACKETS", "30")
    monkeypatch.setenv("SN_ANALYSIS__WINDOW_SECONDS", "15")
    args = _parse("--config", str(path), "--pcap", "x", "--window-seconds", "99")

    settings = load_settings(args.config, cli._settings_overrides(args))

    assert settings.analysis.threshold == 0.6  # file
    assert settings.analysis.window_packets == 30  # environment beats file
    assert settings.analysis.window_seconds == 99.0  # command line beats environment
    assert settings.analysis.bootstrap_windows == 100  # default


def test_conflicting_cli_options_are_rejected() -> None:
    """Mutually exclusive options fail at parse time."""
    with pytest.raises(SystemExit):
        _parse("--pcap", "a", "--interface", "b")
    with pytest.raises(SystemExit):
        _parse("--db-path", "a.db", "--no-db")


@pytest.mark.parametrize(
    "argv",
    [
        [],  # no packet source anywhere
        ["--pcap", "x.pcap", "--bpf", "tcp"],  # live-only option with a file
        ["--pcap", "x.pcap", "--config", "missing.yaml"],  # unreadable config
        ["--pcap", "x.pcap", "--threshold", "5"],  # invalid value
    ],
)
def test_main_rejects_bad_invocations_with_exit_code_2(argv: list[str]) -> None:
    """User errors exit with argparse's status 2 before any work starts."""
    with pytest.raises(SystemExit) as caught:
        cli.main(argv)

    assert caught.value.code == 2


class _EmptySource(PacketSource):
    """Packet source with no packets, standing in for a PCAP reader."""

    def packets(self):
        self._mark_running()
        return iter(())

    def stop(self) -> None:
        self._mark_stopping()
        self._mark_stopped()


def test_main_opens_the_configured_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A normal run creates the SQLite file named by --db-path."""
    monkeypatch.setattr(cli, "PcapFileSource", lambda path: _EmptySource())
    database = tmp_path / "nested" / "alerts.db"

    code = cli.main(
        ["--pcap", "x.pcap", "--db-path", str(database), "--evidence-dir", str(tmp_path / "ev")]
    )

    assert code == 0
    assert database.is_file()


def test_main_with_no_db_creates_no_database_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--no-db runs without touching the database at all."""
    monkeypatch.setattr(cli, "PcapFileSource", lambda path: _EmptySource())

    code = cli.main(["--pcap", "x.pcap", "--no-db", "--evidence-dir", str(tmp_path / "ev")])

    assert code == 0
    assert not (tmp_path / "data").exists()
