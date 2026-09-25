"""Typed, layered runtime configuration for the network analyzer.

Settings are resolved from four layers, each overriding the one before it:

1. Built-in defaults (the values declared on the models below).
2. An optional YAML file (``--config`` or the ``SN_CONFIG_FILE`` variable).
3. Environment variables named ``SN_<SECTION>__<FIELD>``, for example
   ``SN_ANALYSIS__THRESHOLD=0.9``.
4. Explicit overrides, such as command-line flags.

Unknown keys are rejected at every layer so a typo in a file or variable name
fails loudly instead of being silently ignored.  Relative paths are resolved
against the process working directory, not the location of the config file.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

CONFIG_FILE_ENV_VAR = "SN_CONFIG_FILE"
"""Environment variable naming a YAML config file when ``--config`` is absent."""


class ConfigError(ValueError):
    """Raised when configuration cannot be found, parsed, or validated."""


def _blank_to_none(value: Any) -> Any:
    """Treat empty or whitespace-only strings as an unset optional value."""
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return value


def _resolve_bare_name(value: str, directory: Path) -> Path:
    """Resolve a bare filename under ``directory``; leave anything else alone.

    A "bare filename" is the whole string, with no directory separator, and
    not ``"."`` or ``".."``. Anything else -- an absolute path, or a relative
    one that already names a directory, like ``captures/x.pcap`` -- is
    returned exactly as given, so a caller that already knows where a file
    lives is never redirected.
    """
    candidate = Path(value)
    if value == candidate.name and candidate.name not in {"", ".", ".."}:
        return directory / candidate.name
    return candidate


class _Section(BaseModel):
    """Base for one immutable configuration section that rejects unknown keys."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class CaptureSettings(_Section):
    """Where packets come from when capturing live traffic."""

    interface: str | None = None
    bpf_filter: str | None = None
    promiscuous: bool = False
    pcap_dir: Path = Path("logs")
    """Directory a bare PCAP filename (no directory component) resolves against.

    Callers that already know exactly where a file lives -- an absolute path,
    or a relative one with a directory in it, like ``captures/x.pcap`` -- are
    never redirected; only a plain filename like ``traffic.pcap`` is resolved
    here. See :meth:`resolve_pcap`.
    """

    @field_validator("interface", "bpf_filter", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        return _blank_to_none(value)

    def resolve_pcap(self, pcap: str) -> Path:
        """Resolve a ``--pcap``/``StartCaptureRequest.pcap`` argument to a real path.

        A bare filename is looked up under :attr:`pcap_dir`, since capture
        files are conventionally kept in one place and a caller (the
        dashboard, in particular) shouldn't have to know or send the full
        path just to replay one of them. See :func:`_resolve_bare_name`.
        """
        return _resolve_bare_name(pcap, self.pcap_dir)


class AnalysisSettings(_Section):
    """Windowing, scoring, and resource limits of the analysis pipeline."""

    threshold: float = Field(default=0.80, ge=0.0, le=1.0)
    window_packets: int = Field(default=50, gt=0)
    window_seconds: float = Field(default=30.0, gt=0)
    bootstrap_windows: int = Field(default=100, gt=0)
    stream_idle_seconds: float = Field(default=300.0, gt=0)
    alert_cooldown_seconds: float = Field(default=300.0, gt=0)
    max_active_flows: int = Field(default=10_000, gt=0)
    tick_seconds: float = Field(default=1.0, gt=0)

    @property
    def window_duration(self) -> timedelta:
        """Return the flow-window length as a timedelta."""
        return timedelta(seconds=self.window_seconds)

    @property
    def stream_idle_timeout(self) -> timedelta:
        """Return the inactivity after which a flow is dropped."""
        return timedelta(seconds=self.stream_idle_seconds)

    @property
    def alert_cooldown(self) -> timedelta:
        """Return the per-flow interval in which duplicate alerts are suppressed."""
        return timedelta(seconds=self.alert_cooldown_seconds)

    @property
    def tick_interval(self) -> timedelta:
        """Return the live-capture housekeeping interval."""
        return timedelta(seconds=self.tick_seconds)


class ModelSettings(_Section):
    """Anomaly-model artifacts."""

    path: Path | None = None
    """Trusted, previously saved model to load instead of training a baseline."""

    save_path: Path | None = None
    """Where to save the model once baseline training completes.

    Ignored when ``path`` is set, because then no baseline training happens.
    """

    model_dir: Path = Path("models")
    """Directory a bare model filename (for either ``path`` or ``save_path``)
    resolves against. See :meth:`resolve_model`.
    """

    @field_validator("path", "save_path", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        return _blank_to_none(value)

    def resolve_model(self, value: str) -> Path:
        """Resolve a model filename or path to load or save under :attr:`model_dir`.

        A bare filename like ``trained.joblib`` is looked up (or written)
        there, so the dashboard's "save the model" and "load a saved model"
        controls don't need to know the full artifact path. See
        :func:`_resolve_bare_name`.
        """
        return _resolve_bare_name(value, self.model_dir)


class StorageSettings(_Section):
    """Where alerts and evidence are persisted."""

    database_path: Path | None = Path("data/alerts.db")
    """SQLite alert history; ``null`` (or empty) disables alert persistence."""
    evidence_dir: Path = Path("artifacts/evidence")

    @field_validator("database_path", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        return _blank_to_none(value)


class LoggingSettings(_Section):
    """Process logging."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("level", mode="before")
    @classmethod
    def _normalize_level(cls, value: Any) -> Any:
        return value.strip().upper() if isinstance(value, str) else value


class AppSettings(BaseSettings):
    """Complete, immutable analyzer configuration.

    Prefer :func:`load_settings`, which adds the YAML layer and converts
    validation failures into :class:`ConfigError`.
    """

    model_config = SettingsConfigDict(
        env_prefix="SN_",
        env_nested_delimiter="__",
        frozen=True,
        extra="forbid",
    )

    capture: CaptureSettings = CaptureSettings()
    analysis: AnalysisSettings = AnalysisSettings()
    model: ModelSettings = ModelSettings()
    storage: StorageSettings = StorageSettings()
    logging: LoggingSettings = LoggingSettings()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order sources from highest to lowest priority.

        ``.env`` and secret-directory sources are deliberately omitted so the
        only inputs are explicit overrides, the environment, and one YAML file.
        """
        return (
            init_settings,
            env_settings,
            YamlConfigSettingsSource(settings_cls),
        )


def load_settings(
    config_file: str | Path | None = None,
    overrides: Mapping[str, Mapping[str, Any]] | None = None,
) -> AppSettings:
    """Resolve settings from defaults, a YAML file, the environment, and overrides.

    Args:
        config_file: YAML file to read.  When ``None``, the path in the
            ``SN_CONFIG_FILE`` environment variable is used if it is set.
        overrides: Highest-priority values shaped like the settings, for
            example ``{"analysis": {"threshold": 0.9}}``.  They are merged
            field by field, so unspecified fields keep their lower-layer value.
            An explicit ``None`` clears an optional field.

    Raises:
        ConfigError: If the file is missing or malformed, or any value is
            unknown or invalid.
    """
    path = _resolve_config_path(config_file)
    settings_cls: type[AppSettings] = AppSettings
    if path is not None:
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        # Bind this file by subclassing, because the YAML source reads its path
        # from the settings class configuration.
        settings_cls = type(
            "FileBoundAppSettings",
            (AppSettings,),
            {
                "model_config": SettingsConfigDict(
                    yaml_file=str(path), yaml_file_encoding="utf-8"
                )
            },
        )

    try:
        loaded = settings_cls(**(dict(overrides) if overrides else {}))
        if type(loaded) is AppSettings:
            return loaded
        # Hand callers a plain AppSettings rather than the internal file-bound
        # subclass, so equality, repr and isinstance checks behave as expected.
        # The sections are already validated, so nothing is re-parsed.
        return AppSettings.model_construct(
            **{name: getattr(loaded, name) for name in AppSettings.model_fields}
        )
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc, path)) from exc
    except ImportError as exc:
        raise ConfigError(
            "PyYAML is required to read YAML config files; install the "
            "project's configuration dependency."
        ) from exc
    except Exception as exc:
        if path is not None:
            raise ConfigError(f"unable to read config file {path}: {exc}") from exc
        raise


def _resolve_config_path(config_file: str | Path | None) -> Path | None:
    """Pick the explicit path, else the environment variable, else ``None``."""
    candidate: str | Path | None = config_file
    if candidate is None:
        candidate = os.environ.get(CONFIG_FILE_ENV_VAR)
    if candidate is None or not str(candidate).strip():
        return None
    return Path(candidate).expanduser()


def _format_validation_error(exc: ValidationError, path: Path | None) -> str:
    """Render pydantic errors as one readable ``section.field: message`` line each."""
    source = f" in {path}" if path is not None else ""
    lines = [
        f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
        for error in exc.errors()
    ]
    return f"invalid configuration{source}:\n  " + "\n  ".join(lines)
