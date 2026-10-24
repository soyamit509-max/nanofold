"""Telemetry Reliability CI package."""

__all__ = [
    "TelemetryConfig",
    "generate_telemetry",
    "apply_fault_scenario",
    "baseline_anomaly_detector",
    "compute_binary_metrics",
    "generate_report",
]

from .simulation import TelemetryConfig, generate_telemetry
from .fault_injection import apply_fault_scenario
from .detection import baseline_anomaly_detector
from .evaluation import compute_binary_metrics
from .reporting import generate_report
