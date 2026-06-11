# coordinator/trust.py
"""
Persisted trust + poisoning defense for FL contributions.

At aggregation time the coordinator re-evaluates every accepted contribution
against a coordinator-held PUBLIC/synthetic validation set and adjusts the
contributor's PERSISTED trust score:

  - structural validation  (must load as an XGBoost booster)
  - minimum accuracy        on the validation set
  - sudden accuracy drop    vs the org's previous round (poisoning heuristic)

Trust is clamped to [0, 1], persisted in the `orgs` table (store.update_org_trust),
and used both to BLOCK low-trust orgs (< min_trust, SR-05) and to WEIGHT
survivors in the federated-bagging merge (trust x num_examples).

Validation-data privacy: the validation set is a PUBLIC/synthetic benchmark
shipped with the coordinator -- never any participant's raw telemetry -- so
scoring contributions here does not cross any org's data boundary.

When no validation set is configured (FL_VALIDATION_DATA unset) the manager
degrades gracefully to structure-only validation (loadable-model check, no
accuracy gate).
"""

from typing import Optional

from coordinator.logging import get_logger

logger = get_logger("coordinator.trust")


class TrustManager:
    def __init__(
        self,
        store,
        validation_data=None,          # xgboost.DMatrix or None (structure-only)
        *,
        min_accuracy: float = 0.5,
        max_accuracy_drop: float = 0.15,
        min_trust: float = 0.3,
    ):
        self.store = store
        self.validation_data = validation_data
        self.min_accuracy = min_accuracy
        self.max_accuracy_drop = max_accuracy_drop
        self.min_trust = min_trust
        # Per-org last-accuracy for the sudden-drop heuristic. In-process only
        # (resets on restart); the durable trust SCORE lives in the DB.
        self._last_accuracy: dict[str, float] = {}

    def _bump(self, org_id: str, delta: float) -> float:
        org = self.store.get_org(org_id) or {}
        cur = float(org.get("trust_score", 1.0))
        new = max(0.0, min(1.0, cur + delta))
        self.store.update_org_trust(org_id, new)
        return new

    def evaluate(self, org_id: str, model_bytes: bytes, num_examples: int) -> dict:
        """
        Validate + (re)score one contribution.

        Returns dict(accepted, trust, weight, accuracy, reason). `weight` is
        trust * num_examples for accepted contributions, else 0.
        """
        org = self.store.get_org(org_id) or {}
        trust = float(org.get("trust_score", 1.0))

        # ── Block low-trust orgs outright (SR-05) ──────────────────────────
        if trust < self.min_trust:
            logger.warning("contribution blocked - low trust", org=org_id, trust=trust)
            return {"accepted": False, "trust": trust, "weight": 0.0,
                    "accuracy": None, "reason": "trust below minimum"}

        # ── Structural validation (must be a loadable XGBoost booster) ─────
        try:
            import xgboost as xgb
            booster = xgb.Booster()
            booster.load_model(bytearray(model_bytes))
        except Exception as e:
            new = self._bump(org_id, -0.2)
            logger.warning("invalid model structure", org=org_id, error=str(e))
            return {"accepted": False, "trust": new, "weight": 0.0,
                    "accuracy": None, "reason": f"invalid model structure: {e}"}

        accuracy: Optional[float] = None
        if self.validation_data is not None:
            try:
                import numpy as np
                preds = booster.predict(self.validation_data)
                labels = self.validation_data.get_label()
                accuracy = float(np.mean((preds > 0.5).astype(int) == labels))
            except Exception as e:
                new = self._bump(org_id, -0.1)
                return {"accepted": False, "trust": new, "weight": 0.0,
                        "accuracy": None, "reason": f"evaluation failed: {e}"}

            # Minimum accuracy gate.
            if accuracy < self.min_accuracy:
                new = self._bump(org_id, -0.15)
                logger.warning("below accuracy threshold", org=org_id, accuracy=accuracy)
                return {"accepted": False, "trust": new, "weight": 0.0,
                        "accuracy": accuracy,
                        "reason": f"accuracy {accuracy:.2%} below {self.min_accuracy:.2%}"}

            # Sudden-drop poisoning heuristic vs the org's previous round.
            prev = self._last_accuracy.get(org_id)
            if prev is not None and (prev - accuracy) > self.max_accuracy_drop:
                new = self._bump(org_id, -0.2)
                logger.warning("suspicious accuracy drop", org=org_id,
                               prev=prev, current=accuracy)
                return {"accepted": False, "trust": new, "weight": 0.0,
                        "accuracy": accuracy,
                        "reason": f"suspicious accuracy drop {prev - accuracy:.2%}"}
            self._last_accuracy[org_id] = accuracy

        # ── Accepted -- slowly recover trust for consistently good orgs ────
        new = self._bump(org_id, +0.02)
        weight = new * float(max(num_examples, 1))
        logger.info("contribution validated", org=org_id, accuracy=accuracy, trust=new)
        return {"accepted": True, "trust": new, "weight": weight,
                "accuracy": accuracy, "reason": "accepted"}
