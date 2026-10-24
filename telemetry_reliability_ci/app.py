from __future__ import annotations

from pathlib import Path
from typing import Iterable

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def generate_report(
    rows: Iterable[dict],
    *,
    output_dir: str | Path | None = None,
    output_prefix: str = "comparison_report",
) -> tuple[pd.DataFrame, Path, Path]:
    """Create a comparison report from experiment rows and save CSV and plot artifacts."""

    summary = pd.DataFrame(list(rows))
    if summary.empty:
        raise ValueError("Cannot generate a report from an empty result set.")

    target_dir = Path(output_dir) if output_dir is not None else Path.cwd()
    target_dir.mkdir(parents=True, exist_ok=True)

    csv_path = target_dir / f"{output_prefix}.csv"
    fig_path = target_dir / f"{output_prefix}.png"

    summary.to_csv(csv_path, index=False)

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(summary["scenario"], summary["f1"], color=["#3B82F6", "#10B981", "#F59E0B", "#F97316", "#8B5CF6"])
    ax.set_title("Baseline F1 by Fault Scenario")
    ax.set_xlabel("Scenario")
    ax.set_ylabel("F1 Score")
    ax.set_ylim(0.0, 1.05)
    ax.bar_label(bars, padding=3, fmt="%.2f")
    plt.xticks(rotation=20)
    fig.tight_layout()
    fig.savefig(fig_path, dpi=150)
    plt.close(fig)

    return summary, csv_path, fig_path
