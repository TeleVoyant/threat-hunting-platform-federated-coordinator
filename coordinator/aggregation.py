# coordinator/aggregation.py
"""
Flower-free federated bagging for XGBoost.

Participating platforms each train an XGBoost ensemble locally and upload it
as XGBoost-native JSON. This module merges those ensembles into one global
model with NO Flower / gRPC dependency: it concatenates each contributor's
trees in proportion to that contributor's weight (trust_score x num_examples),
caps the global ensemble, and renumbers tree ids so the merged model loads
cleanly.

The merge math is lifted verbatim from the project's proven Flower
`XGBoostFedBagging.aggregate_fit` strategy (proportional tree sampling, heaviest
contributor as the structural base, 500-tree cap). Extracting it lets the
standalone coordinator aggregate the contributions it has already received and
cryptographically verified, on demand, over REST -- without holding any live
gRPC client connections.

Why renumber tree ids?
  XGBoost JSON models carry an 'id' field per tree plus parallel count arrays
  (tree_info / iteration_indptr / gbtree_model_param.num_trees). Appended trees
  from different contributors start their ids at 0, creating duplicates that
  segfault at load time. `_set_trees` rewrites all of these consistently.
"""

import json
from typing import Sequence, Tuple

# Hard cap on the global ensemble. XGBoost inference cost scales linearly with
# num_trees; beyond ~500 the marginal accuracy gain drops while latency grows.
_MAX_GLOBAL_TREES = 500


def _get_trees(model_json: dict) -> list:
    """Extract the tree list from an XGBoost JSON model dict."""
    return (
        model_json
        .get("learner", {})
        .get("gradient_booster", {})
        .get("model", {})
        .get("trees", [])
    )


def _set_trees(model_json: dict, trees: list) -> None:
    """Replace the tree list in-place and update all parallel count arrays so
    the merged model is internally consistent and loadable."""
    model = (
        model_json
        .get("learner", {})
        .get("gradient_booster", {})
        .get("model", {})
    )
    n = len(trees)
    # Renumber tree ids sequentially -- appended trees from other contributors
    # start at 0, creating duplicates that crash XGBoost at load time.
    for i, tree in enumerate(trees):
        if isinstance(tree, dict):
            tree["id"] = i
    model["trees"] = trees
    model["tree_info"] = [0] * n                       # group index 0 (binary task)
    model["iteration_indptr"] = list(range(n + 1))     # sequential [0..n]
    gbtree_param = model.get("gbtree_model_param")
    if isinstance(gbtree_param, dict):
        gbtree_param["num_trees"] = str(n)


def merge_xgboost_models(
    weighted_models: Sequence[Tuple[bytes, float]],
) -> Tuple[bytes, dict]:
    """
    Merge XGBoost JSON models by trust/data-weighted tree bagging.

    Args:
        weighted_models: list of (model_json_bytes, weight). `weight` is
            normally trust_score * num_examples; only relative magnitude
            matters. Non-positive-weight or non-JSON or tree-less entries are
            skipped.

    Returns:
        (global_model_bytes, info) where info carries num_models / total_trees /
        capped for the round record + audit.

    Raises:
        ValueError if no usable model remains after filtering.
    """
    parsed: list[tuple[dict, float]] = []
    for raw, weight in weighted_models:
        try:
            model_json = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue  # contributions must be valid XGBoost JSON
        w = float(weight)
        if w > 0.0 and _get_trees(model_json):
            parsed.append((model_json, w))

    if not parsed:
        raise ValueError("No usable models to aggregate")

    total_weight = sum(w for _, w in parsed) or 1.0

    # Heaviest contributor is the structural base of the merged ensemble.
    parsed.sort(key=lambda x: x[1], reverse=True)
    merged = parsed[0][0]
    base_trees = list(_get_trees(merged))

    # Append a weighted fraction of every other contributor's trees. Trees are
    # ordered by training round (first = highest marginal gain), so we take
    # from the start of each contributor's sequence.
    for model_json, weight in parsed[1:]:
        client_trees = _get_trees(model_json)
        if not client_trees:
            continue
        frac = weight / total_weight
        n_include = max(1, int(len(client_trees) * frac))
        base_trees.extend(client_trees[:n_include])

    capped = len(base_trees) > _MAX_GLOBAL_TREES
    if capped:
        base_trees = base_trees[:_MAX_GLOBAL_TREES]

    _set_trees(merged, base_trees)
    global_bytes = json.dumps(merged).encode()
    return global_bytes, {
        "num_models":  len(parsed),
        "total_trees": len(base_trees),
        "capped":      capped,
    }
