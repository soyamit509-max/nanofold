from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from telemetry_reliability_ci.detection import baseline_anomaly_detector
from telemetry_reliability_ci.evaluation import compute_binary_metrics
from telemetry_reliability_ci.fault_injection import apply_fault_scenario
from telemetry_reliability_ci.reporting import generate_report
from telemetry_reliability_ci.simulation import TelemetryConfig, generate_telemetry


st.set_page_config(page_title="Telemetry Reliability CI", layout="wide")
st.title("Telemetry Reliability CI")
st.caption("Offline synthetic benchmark for telemetry anomaly detector robustness.")

with st.sidebar:
    st.header("Experiment Controls")
    n_samples = st.slider("Samples", min_value=100, max_value=1000, value=300, step=50)
    n_sensors = st.slider("Sensors", min_value=2, max_value=8, value=4, step=1)
    seed = st.number_input("Random seed", min_value=0, max_value=10000, value=42, step=1)
    fault_scenario = st.selectbox("Fault scenario", ["clean", "missing", "drift", "stuck", "spike"]) 
    severity = st.slider("Fault severity", min_value=0.1, max_value=1.0, value=0.5, step=0.05)
    detection_threshold = st.slider("Detection threshold", min_value=2.0, max_value=6.0, value=3.0, step=0.1)
    use_seeded_run = st.button("Run evaluation")


if use_seeded_run:
    config = TelemetryConfig(
        n_samples=n_samples,
        n_sensors=n_sensors,
        seed=seed,
    )
    clean_df = generate_telemetry(config)
    faulty_df = apply_fault_scenario(clean_df, fault_scenario, severity=severity, seed=seed)
    predictions = baseline_anomaly_detector(faulty_df, threshold=detection_threshold)
    metrics = compute_binary_metrics(clean_df["ground_truth"], predictions)

    st.subheader("Experiment Summary")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Precision", f"{metrics['precision']:.3f}")
    col2.metric("Recall", f"{metrics['recall']:.3f}")
    col3.metric("F1", f"{metrics['f1']:.3f}")
    col4.metric("False positives", metrics["false_positive_count"])

    st.subheader("Telemetry Preview")
    st.dataframe(faulty_df.head(10), use_container_width=True)

    st.subheader("Metrics Table")
    metric_df = pd.DataFrame(
        [{
            "scenario": fault_scenario,
            "seed": seed,
            "severity": severity,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "false_positive_count": metrics["false_positive_count"],
            "false_negative_count": metrics["false_negative_count"],
            "true_positive_count": metrics["true_positive_count"],
        }]
    )
    st.dataframe(metric_df, use_container_width=True)

    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    _, csv_path, fig_path = generate_report(metric_df.to_dict("records"), output_dir=output_dir, output_prefix="single_run_report")

    st.subheader("Comparison Plot")
    st.image(str(fig_path), use_column_width=True)

    with open(csv_path, "rb") as csv_file:
        st.download_button(
            label="Download CSV report",
            data=csv_file,
            file_name=csv_path.name,
            mime="text/csv",
        )
else:
    st.info("Use the sidebar controls to generate synthetic telemetry and evaluate a fault scenario.")

    placeholder = TelemetryConfig(n_samples=300, n_sensors=4, seed=42)
    preview_df = generate_telemetry(placeholder)
    st.dataframe(preview_df.head(10), use_container_width=True)
