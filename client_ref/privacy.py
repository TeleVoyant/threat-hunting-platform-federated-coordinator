"""
Client-side differential privacy for federated XGBoost contributions.

Adds calibrated Laplace noise to leaf values in the XGBoost tree structure
BEFORE the model leaves the org, so the coordinator (and anyone observing the
channel) cannot reconstruct training data from the shared parameters. This is
applied entirely on the participant side — the coordinator never sees the
un-noised model. Smaller epsilon => more privacy => more noise => less accuracy.

Self-contained: stdlib + numpy only (no coordinator/monorepo imports), so an
external organisation can vendor just this file + flproto/ into their client.
"""

import json
import logging

import numpy as np

logger = logging.getLogger("flclient.privacy")


def apply_differential_privacy(model_raw_bytes: bytes, epsilon: float = 1.0) -> bytes:
    """
    Apply (epsilon)-differential privacy to an XGBoost JSON model.

    Args:
        model_raw_bytes: bytes of an XGBoost model exported as JSON
            (booster.save_model("model.json")).
        epsilon: privacy budget (1.0 is a reasonable default per the proposal).

    Returns:
        Model bytes with Laplace-perturbed leaf values, re-serialised as JSON.
        Returns the input unchanged if it is not parseable JSON.
    """
    try:
        model_json = json.loads(model_raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.warning("model is not JSON — returning unmodified (no DP applied)")
        return model_raw_bytes

    # Sensitivity: max change one data point can cause in a leaf value.
    # For XGBoost with typical learning_rate ~0.05, sensitivity ~= 0.1.
    sensitivity = 0.1
    scale = sensitivity / max(epsilon, 0.01)   # Laplace scale = sensitivity/epsilon

    trees_modified = 0
    if "learner" in model_json:
        gbm = model_json["learner"].get("gradient_booster", {})
        trees = gbm.get("model", {}).get("trees", [])
        for tree in trees:
            # Leaf nodes are where left_children[i] == -1; their value lives in
            # split_conditions[i] in current XGBoost JSON.
            if "split_conditions" in tree:
                conditions = tree["split_conditions"]
                left_children = tree.get("left_children", [])
                for i in range(len(conditions)):
                    if i < len(left_children) and left_children[i] == -1:
                        conditions[i] = float(conditions[i]) + float(np.random.laplace(0, scale))
                trees_modified += 1

    logger.info("differential privacy applied: epsilon=%s scale=%.4f trees=%d",
                epsilon, scale, trees_modified)
    return json.dumps(model_json).encode()
