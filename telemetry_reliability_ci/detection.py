from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd

from .simulation import sensor_columns


def inject_missing_readings(
    df: pd.DataFrame,
    missing_rate: float = 0.05,
    *,
    seed: int = 42,
    columns: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Set a fraction of values to NaN in the selected sensor columns."""

    if df.empty:
        raise ValueError("Telemetry data is empty.")
    selected = sensor_columns(df, columns)
    if not 0.0 <= missing_rate <= 1.0:
        raise ValueError("missing_rate must be between 0 and 1.")

    copy_df = df.copy()
    rng = np.random.default_rng(seed)
    for column in selected:
        total_points = len(copy_df)
        n_missing = max(0, int(round(total_points * missing_rate)))
        if n_missing == 0:
            continue
        indices = rng.choice(total_points, size=n_missing, replace=False)
        copy_df.loc[indices, column] = np.nan
    return copy_df


def inject_sensor_drift(
    df: pd.DataFrame,
    drift_amount: float = 5.0,
    *,
    seed: int = 42,
    columns: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Add a gradual drift term to the selected sensor channels."""

    if df.empty:
        raise ValueError("Telemetry data is empty.")
    selected = sensor_columns(df, columns)
    if drift_amount < 0:
        raise ValueError("drift_amount must be non-negative.")

    copy_df = df.copy()
    rng = np.random.default_rng(seed)
    for sensor_index, column in enumerate(selected):
        offset = np.linspace(0.0, drift_amount, len(copy_df))
        phase = rng.uniform(0.0, 1.0)
        copy_df[column] = copy_df[column] + offset + sensor_index * phase
    return copy_df


def inject_stuck_values(
    df: pd.DataFrame,
    stuck_rate: float = 0.10,
    *,
    stuck_value: float = 0.0,
    seed: int = 42,
    columns: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Force a fraction of readings in each selected sensor to a constant value."""

    if df.empty:
        raise ValueError("Telemetry data is empty.")
    selected = sensor_columns(df, columns)
    if not 0.0 <= stuck_rate <= 1.0:
        raise ValueError("stuck_rate must be between 0 and 1.")

    copy_df = df.copy()
    rng = np.random.default_rng(seed)
    for column in selected:
        total_points = len(copy_df)
        n_stuck = max(0, int(round(total_points * stuck_rate)))
        if n_stuck == 0:
            continue
        chosen_idx = rng.choice(total_points, size=n_stuck, replace=False)
        copy_df.loc[chosen_idx, column] = stuck_value
    return copy_df


def inject_noise_spikes(
    df: pd.DataFrame,
    spike_rate: float = 0.03,
    *,
    spike_amplitude: float = 10.0,
    seed: int = 42,
    columns: Iterable[str] | None = None,
) -> pd.DataFrame:
    """Insert short, high-amplitude spikes into the selected sensor columns."""

    if df.empty:
        raise ValueError("Telemetry data is empty.")
    selected = sensor_columns(df, columns)
    if not 0.0 <= spike_rate <= 1.0:
        raise ValueError("spike_rate must be between 0 and 1.")
    if spike_amplitude < 0:
        raise ValueError("spike_amplitude must be non-negative.")

    copy_df = df.copy()
    rng = np.random.default_rng(seed)
    for column in selected:
        total_points = len(copy_df)
        n_spikes = max(0, int(round(total_points * spike_rate)))
        if n_spikes == 0:
            continue
        spike_idx = rng.choice(total_points, size=n_spikes, replace=False)
        for idx in spike_idx:
            copy_df.at[idx, column] += float(rng.uniform(0.35, 1.0) * spike_amplitude)
    return copy_df


def apply_fault_scenario(
    df: pd.DataFrame,
    scenario: str,
    *,
    severity: float = 0.5,
    seed: int = 42,
) -> pd.DataFrame:
    """Apply a synthetic quality fault to a telemetry frame."""

    if df.empty:
        raise ValueError("Telemetry data is empty.")
    if not 0.0 <= severity <= 1.0:
        raise ValueError("severity must be between 0 and 1.")

    scenario = scenario.lower()
    if scenario == "clean":
        return df.copy()
    if scenario == "missing":
        return inject_missing_readings(df, missing_rate=max(0.02, severity * 0.25), seed=seed)
    if scenario == "drift":
        return inject_sensor_drift(df, drift_amount=1.0 + severity * 8.0, seed=seed)
    if scenario == "stuck":
        return inject_stuck_values(df, stuck_rate=max(0.02, severity * 0.2), stuck_value=0.0, seed=seed)
    if scenario == "spike":
        return inject_noise_spikes(df, spike_rate=max(0.01, severity * 0.12), spike_amplitude=5.0 + severity * 15.0, seed=seed)
    raise ValueError(f"Unsupported fault scenario: {scenario}")
