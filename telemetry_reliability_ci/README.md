from __future__ import annotations

import numpy as np
import pandas as pd

from telemetry_reliability_ci.evaluation import compute_binary_metrics
from telemetry_reliability_ci.fault_injection import (
    inject_missing_readings,
    inject_noise_spikes,
    inject_sensor_drift,
    inject_stuck_values,
)
from telemetry_reliability_ci.reporting import generate_report
from telemetry_reliability_ci.simulation import TelemetryConfig, generate_telemetry


def test_reproducible_generation() -> None:
    first = generate_telemetry(TelemetryConfig(n_samples=120, n_sensors=3, seed=11))
    second = generate_telemetry(TelemetryConfig(n_samples=120, n_sensors=3, seed=11))
    pd.testing.assert_frame_equal(first, second)


def test_each_fault_injection_function() -> None:
    df = generate_telemetry(TelemetryConfig(n_samples=80, n_sensors=2, seed=5))

    missing = inject_missing_readings(df, missing_rate=0.15, seed=7)
    assert missing["sensor_1"].isna().sum() > 0

    drifted = inject_sensor_drift(df, drift_amount=4.0, seed=9)
    assert np.abs(drifted["sensor_1"].mean() - df["sensor_1"].mean()) > 0.5

    stuck = inject_stuck_values(df, stuck_rate=0.12, stuck_value=0.0, seed=10)
    assert (stuck["sensor_2"] == 0.0).sum() > 0

    spiked = inject_noise_spikes(df, spike_rate=0.08, spike_amplitude=12.0, seed=11)
    assert (spiked["sensor_1"] > 100).sum() >= 0


def test_metric_calculations() -> None:
    metrics = compute_binary_metrics([True, False, True, False], [True, True, False, False])
    assert metrics["true_positive_count"] == 1
    assert metrics["false_positive_count"] == 1
    assert metrics["false_negative_count"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5


def test_empty_and_no_positive_label_inputs() -> None:
    empty = compute_binary_metrics([], [])
    assert empty["precision"] == 0.0
    assert empty["recall"] == 0.0
    assert empty["f1"] == 0.0

    no_positive = compute_binary_metrics([False, False, False], [False, False, False])
    assert no_positive["false_positive_count"] == 0
    assert no_positive["false_negative_count"] == 0


def test_csv_report_generation() -> None:
    rows = [
        {"scenario": "clean", "precision": 1.0, "recall": 0.8, "f1": 0.89},
        {"scenario": "spike", "precision": 0.7, "recall": 0.6, "f1": 0.65},
    ]
    summary, csv_path, png_path = generate_report(rows, output_dir="./tmp_report_test")
    assert csv_path.exists()
    assert png_path.exists()
    assert summary["scenario"].tolist() == ["clean", "spike"]
    assert summary["f1"].iloc[0] == 0.89
