#!/usr/bin/env python3
"""
Generate a small PUBLIC/synthetic validation set (libsvm) for the coordinator's
trust + poisoning scoring.

This is NOT any participant's data — it is a synthetic benchmark the neutral
coordinator holds to sanity-check contributed models (accuracy floor + sudden
accuracy-drop). In production, replace it with a representative public/shared
benchmark agreed by the federation.

Usage:
  python examples/gen_validation.py config/validation.svm [n_rows] [n_features]
"""

import sys

import numpy as np


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "config/validation.svm"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    d = int(sys.argv[3]) if len(sys.argv) > 3 else 8

    rng = np.random.default_rng(1234)
    X = rng.normal(size=(n, d))
    w = rng.normal(size=d)
    y = ((X @ w + rng.normal(scale=0.3, size=n)) > 0).astype(int)

    with open(out, "w") as f:
        for xi, yi in zip(X, y):
            feats = " ".join(f"{j + 1}:{v:.5f}" for j, v in enumerate(xi))
            f.write(f"{int(yi)} {feats}\n")

    print(f"wrote {n} rows x {d} features -> {out}")
    print("point the coordinator at it with FL_VALIDATION_DATA=" + out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
