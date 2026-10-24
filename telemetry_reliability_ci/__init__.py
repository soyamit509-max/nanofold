from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class TelemetryConfig:
    """Configuration used to synthesize a reproducible telemetry dataset."""

    n_samples: int = 300
    n_sensors: int = 4
    sample_interval_s: int = 60
    nominal_mean: float = 50.0
    nominal_std: float = 2.5
    drift_rate: float = 0.02
    anomaly_fraction: float = 0.08
    start_time: pd.Timestamp = field(default_factory=lambda: pd.Timestamp("2026-01-01 00:00:00"))
    seed: int = 42

    def __post_init__(self) -> None:
        if self.n_samples <= 0:
            raise ValueError("n_samples must be positive.")
        if self.n_sensors <= 0:
            raise ValueError("n_sensors must be positive.")
        if self.sample_interval_s <= 0:
            raise ValueError("sample_interval_s must be positive.")
        if not 0.0 <= self.anomaly_fraction <= 1.0:
            raise ValueError("anomaly_fraction must be between 0 and 1.")


def generate_telemetry(
    config: TelemetryConfig | None = None,
    *,
    seed: int | None = None,
) -> pd.DataFrame:
    """Generate synthetic time-indexed telemetry with a ground-truth anomaly label column.

    The generated data is intentionally simple and offline-only. It is meant for reproducible
    developer workflows and research experiments, not for flight qualification.
    """

    if config is None:
        config = TelemetryConfig(seed=seed if seed is not None else 42)
    if seed is not None:
        config = TelemetryConfig(**{**config.__dict__, "seed": seed})

    rng = np.random.default_rng(config.seed)
    timestamps = pd.date_range(config.start_time, periods=config.n_samples, freq=f"{config.sample_interval_s}s")

    signal_matrix = np.zeros((config.n_samples, config.n_sensors), dtype=float)
    for sensor_index in range(config.n_sensors):
        waveform = config.nominal_mean + np.sin(np.linspace(0, 4 * np.pi, config.n_samples) + sensor_index) * 2.5
        drift_component = np.linspace(0.0, config.drift_rate * config.n_samples, config.n_samples)
        noise = rng.normal(0.0, config.nominal_std, size=config.n_samples)
        signal_matrix[:, sensor_index] = waveform + drift_component + noise + sensor_index * 0.5

    columns = [f"sensor_{index + 1}" for index in range(config.n_sensors)]
    df = pd.DataFrame(signal_matrix, columns=columns, index=timestamps)
    df.index.name = "timestamp"

    anomaly_count = max(1, int(round(config.n_samples * config.anomaly_fraction))) if config.n_samples else 0
    anomaly_indices = rng.choice(config.n_samples, size=min(anomaly_count, config.n_samples), replace=False)
    truth = np.zeros(config.n_samples, dtype=bool)
    truth[anomaly_indices] = True

    for idx in anomaly_indices:
        affected_sensor = int(rng.integers(0, config.n_sensors))
        df.iloc[idx, affected_sensor] += float(rng.uniform(10.0, 25.0))

    df.insert(0, "ground_truth", truth)
    return df.reset_index().rename(columns={"index": "timestamp"})


def sensor_columns(df: pd.DataFrame, columns: Iterable[str] | None = None) -> list[str]:
    """Return the sensor columns from a telemetry DataFrame."""

    if df.empty:
        raise ValueError("Telemetry data is empty.")

    available = [column for column in df.columns if column not in {"timestamp", "ground_truth"}]
    if columns is None:
        if not available:
            raise ValueError("No sensor columns found in the provided telemetry frame.")
        return available

    selected = list(columns)
    missing = [column for column in selected if column not in df.columns]
    if missing:
        raise ValueError(f"Missing sensor columns: {missing}")
    return selected
