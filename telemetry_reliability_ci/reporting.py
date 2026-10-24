from __future__ import annotations

from typing import Iterable

import numpy as np


def compute_binary_metrics(
    y_true: Iterable[bool] | np.ndarray,
    y_pred: Iterable[bool] | np.ndarray,
) -> dict[str, float | int]:
    """Compute precision, recall, F1, false positives, and false negatives.

    Edge cases are handled explicitly: empty inputs return neutral zero metrics, and scenarios with
    no positive labels still produce useful counts instead of raising exceptions.
    """

    true_values = np.asarray(list(y_true), dtype=bool)
    pred_values = np.asarray(list(y_pred), dtype=bool)

    if true_values.size != pred_values.size:
        raise ValueError("y_true and y_pred must have the same length.")
    if true_values.size == 0:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "false_positive_count": 0,
            "false_negative_count": 0,
            "true_positive_count": 0,
            "true_negative_count": 0,
        }

    tp = int(np.sum(true_values & pred_values))
    fp = int(np.sum((~true_values) & pred_values))
    fn = int(np.sum(true_values & (~pred_values)))
    tn = int(np.sum((~true_values) & (~pred_values)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "false_positive_count": int(fp),
        "false_negative_count": int(fn),
        "true_positive_count": int(tp),
        "true_negative_count": int(tn),
    }
