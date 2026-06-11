"""
Minimal libsvm loader (numpy-only, no xgboost / sklearn).

Used by the coordinator (validation set) and the reference client (local
training data) to build XGBoost DMatrix objects FROM ARRAYS rather than via
XGBoost's file-URI loader. Building from arrays is both portable and avoids
XGBoost's external-memory file iterator, which can be fragile under
constrained OpenMP thread pools.

libsvm line format:  <label> <1-based-index>:<value> <1-based-index>:<value> ...
"""

import numpy as np


def load_libsvm(path: str) -> tuple["np.ndarray", "np.ndarray"]:
    """Parse a libsvm/svmlight file into dense (X, y) float32 arrays.

    Dense is fine for the small validation sets used here; for very wide
    feature spaces a caller may prefer a sparse loader.
    """
    rows: list[dict[int, float]] = []
    labels: list[float] = []
    max_index = 0
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            labels.append(float(parts[0]))
            feats: dict[int, float] = {}
            for tok in parts[1:]:
                idx_s, val_s = tok.split(":")
                idx = int(idx_s)
                feats[idx] = float(val_s)
                if idx > max_index:
                    max_index = idx
            rows.append(feats)

    X = np.zeros((len(rows), max_index), dtype=np.float32)   # 1-based -> width=max_index
    for r, feats in enumerate(rows):
        for idx, val in feats.items():
            X[r, idx - 1] = val
    y = np.asarray(labels, dtype=np.float32)
    return X, y
