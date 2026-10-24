from __future__ import annotations

import numpy as np
import pandas as pd

from .simulation import sensor_columns


def baseline_anomaly_detector(
    df: pd.DataFrame,
    *,
    sensor_columns_input: list[str] | None = None,
    threshold: float = 3.0,
) -> pd.Series:
    """Compute a simple, explainable baseline using robust z-scores across all sensors.

    This is intentionally lightweight and interpretable. It should not be interpreted as a flight-
    validated model; it is a developer baseline for offline synthetic benchmarking only.
    """

    if df.empty:
        return pd.Series([], dtype=bool)

    selected = sensor_columns(df, sensor_columns_input)
    values = df[selected].astype(float).to_numpy(copy=True)
    if values.size == 0:
        return pd.Series([], index=df.index, dtype=bool)

    valid_mask = ~np.isnan(values)
    medians = np.nanmedian(values, axis=0)
    medians = np.where(np.isnan(medians), 0.0, medians)

    mad = np.median(np.abs(values - medians), axis=0)
    mad = np.where(np.isnan(mad), 1.0, mad)
    scale = np.where(mad == 0.0, 1.0, 1.4826 * mad)

    z_scores = np.zeros_like(values, dtype=float)
    for col_index in range(values.shape[1]):
        z_scores[:, col_index] = np.abs((values[:, col_index] - medians[col_index]) / (scale[col_index] + 1e-6))

    row_max = np.nanmax(np.where(valid_mask, z_scores, np.nan), axis=1)
    row_max = np.nan_to_num(row_max, nan=0.0)
    predictions = pd.Series(row_max > threshold, index=df.index, name="prediction")
    return predictions
