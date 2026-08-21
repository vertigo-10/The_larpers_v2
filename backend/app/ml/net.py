"""Network architecture and the synthetic traffic generator.

Both are reproduced verbatim (in behaviour) from `backend/sentryv1.py`, which was
written by SpaceNerdSai. That file is left untouched on purpose: it is his, and
it runs as a standalone training demo. This module exists because a *served*
model needs things his script does not persist — namely the fitted
StandardScaler and LabelEncoder. Scoring a flow without the exact scaler used at
training time produces silently wrong predictions.

IMPORTANT HONESTY NOTE
----------------------
`make_data()` generates synthetic samples from hand-written distributions. It is
NOT CIC-IDS2017 and not captured traffic. Any accuracy measured against it
describes how well the model separates three synthetic clusters — it says
nothing about real-world performance. Every metric this package emits is tagged
`"dataset": "synthetic"` so the UI can state that plainly.
"""

from typing import Tuple

import numpy as np
import torch
import torch.nn as nn

# Order matters and must stay in sync with the LabelEncoder fitted in train.py.
CLASS_NAMES = ["dos_ddos", "normal", "scan"]  # LabelEncoder sorts alphabetically

FEATURE_NAMES = [
    "duration",
    "packets",
    "total_bytes",
    "packets_per_sec",
    "bytes_per_packet",
    "dst_port",
]
N_FEATURES = len(FEATURE_NAMES)
N_CLASSES = 3


class Net(nn.Module):
    """6 → 64 → 32 → 3 MLP. Same shape as sentryv1.py."""

    def __init__(self) -> None:
        super().__init__()
        self.m = nn.Sequential(
            nn.Linear(N_FEATURES, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, N_CLASSES),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.m(x)


def make_data(n: int = 2000, seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Synthetic flows for three behaviour classes.

    Distributions are those in sentryv1.py:
      normal   — long-lived, moderate packet counts, large payloads, port 443
      dos_ddos — very short, huge packet counts, small payloads, port 80
      scan     — near-instant, 1–5 packets, random destination port
    """
    rng = np.random.RandomState(seed)
    X, y = [], []

    for _ in range(n):
        d = rng.uniform(0.5, 60)
        p = rng.randint(10, 500)
        b = p * rng.uniform(300, 1200)
        X.append([d, p, b, p / d, b / p, 443])
        y.append("normal")

    for _ in range(n):
        d = rng.uniform(0.01, 2)
        p = rng.randint(3000, 50000)
        b = p * rng.uniform(40, 80)
        X.append([d, p, b, p / d, b / p, 80])
        y.append("dos_ddos")

    for _ in range(n):
        d = rng.uniform(0.001, 0.2)
        p = rng.randint(1, 5)
        b = p * rng.uniform(40, 80)
        X.append([d, p, b, p / d, b / p, rng.randint(1, 65535)])
        y.append("scan")

    return np.array(X, dtype=np.float32), np.array(y)
