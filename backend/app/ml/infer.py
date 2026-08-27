"""Load the trained artifacts and score flows.

The detector is a process-wide singleton loaded once at startup. If artifacts are
missing the service starts in an explicitly UNAVAILABLE state and every endpoint
reports that — it does not fall back to random guessing. A security tool that
invents verdicts when its model is missing is worse than one that admits it.
"""

import json
import os
import threading
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import torch

from .features import flow_to_features
from .net import Net

_LOCK = threading.Lock()


class Detector:
    def __init__(self, model_dir: str) -> None:
        self.model_dir = os.path.abspath(model_dir)
        self.net: Optional[Net] = None
        self.scaler = None
        self.labels = None
        self.metrics: Dict = {}
        self.error: Optional[str] = None
        self.load()

    # ── lifecycle ────────────────────────────────────────────────────────
    def load(self) -> None:
        try:
            model_path = os.path.join(self.model_dir, "model.pt")
            scaler_path = os.path.join(self.model_dir, "scaler.joblib")
            labels_path = os.path.join(self.model_dir, "labels.joblib")
            metrics_path = os.path.join(self.model_dir, "metrics.json")

            missing = [
                os.path.basename(p)
                for p in (model_path, scaler_path, labels_path)
                if not os.path.exists(p)
            ]
            if missing:
                raise FileNotFoundError(
                    f"missing artifact(s): {', '.join(missing)} — "
                    "run: python -m backend.app.ml.train"
                )

            net = Net()
            # weights_only=True keeps the load restricted to plain tensors.
            # The default unpickles arbitrary objects, which means a swapped
            # model.pt is remote code execution rather than a bad prediction —
            # and the model file is exactly the artifact most likely to be
            # fetched from a build cache, a release asset or a teammate.
            # It became the torch default in 2.6; passing it explicitly keeps
            # the guarantee on the older versions this still supports.
            net.load_state_dict(
                torch.load(model_path, map_location="cpu", weights_only=True)
            )
            net.eval()

            self.net = net
            self.scaler = joblib.load(scaler_path)
            self.labels = joblib.load(labels_path)
            self.metrics = (
                json.load(open(metrics_path)) if os.path.exists(metrics_path) else {}
            )
            self.error = None
        except Exception as exc:  # noqa: BLE001 - surfaced via /api/status
            self.net = None
            self.error = str(exc)

    @property
    def ready(self) -> bool:
        return self.net is not None

    @property
    def class_names(self) -> List[str]:
        if self.labels is None:
            return []
        return list(self.labels.classes_)

    # ── scoring ──────────────────────────────────────────────────────────
    def predict(self, flow: Dict) -> Tuple[str, float, Dict[str, float]]:
        """Score one flow. Returns (label, confidence, per-class probabilities)."""
        if not self.ready:
            raise RuntimeError(f"model unavailable: {self.error}")

        vec = np.array([flow_to_features(flow)], dtype=np.float32)
        scaled = self.scaler.transform(vec)

        with _LOCK, torch.no_grad():
            logits = self.net(torch.tensor(scaled, dtype=torch.float32))
            probs = torch.softmax(logits, dim=1)[0].numpy()

        idx = int(probs.argmax())
        names = self.class_names
        return (
            names[idx],
            float(probs[idx]),
            {name: float(p) for name, p in zip(names, probs)},
        )

    def predict_batch(self, flows: List[Dict]) -> List[Tuple[str, float, Dict[str, float]]]:
        if not self.ready:
            raise RuntimeError(f"model unavailable: {self.error}")
        if not flows:
            return []

        vec = np.array([flow_to_features(f) for f in flows], dtype=np.float32)
        scaled = self.scaler.transform(vec)

        with _LOCK, torch.no_grad():
            logits = self.net(torch.tensor(scaled, dtype=torch.float32))
            probs = torch.softmax(logits, dim=1).numpy()

        names = self.class_names
        out = []
        for row in probs:
            idx = int(row.argmax())
            out.append((names[idx], float(row[idx]),
                        {n: float(p) for n, p in zip(names, row)}))
        return out


_detector: Optional[Detector] = None


def get_detector(model_dir: Optional[str] = None) -> Detector:
    global _detector
    if _detector is None:
        from ..config import settings
        _detector = Detector(model_dir or settings.model_dir)
    return _detector


def reload_detector() -> Detector:
    """Re-read artifacts from disk, e.g. after retraining."""
    global _detector
    _detector = None
    return get_detector()
