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


# Ports that ordinary traffic and volumetric floods both land on. Sampled from
# the same pool for both classes on purpose — see the label-leak note below.
SERVICE_PORTS = [80, 443, 8080, 8443, 22, 53, 123, 3306, 5432, 25, 993, 587]
SERVICE_PORT_WEIGHTS = [
    0.34, 0.34, 0.05, 0.03, 0.05, 0.06, 0.02, 0.02, 0.02, 0.02, 0.02, 0.03,
]


def make_data(n: int = 2000, seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Synthetic flows for three behaviour classes.

    Shapes follow sentryv1.py — long-lived moderate flows for `normal`, very
    short huge-packet-count flows for `dos_ddos`, near-instant 1–5 packet flows
    for `scan`.

    LABEL LEAK, DELIBERATELY REMOVED
    --------------------------------
    This one distribution now diverges from sentryv1.py, and the divergence is
    the point. That script hardcoded the destination port per class: 443 for
    every `normal` sample and 80 for every `dos_ddos` sample. Since `dst_port`
    is feature #6, the network did not have to learn anything about traffic
    shape at all — "port 80" was a sufficient statistic for "attack".

    That is invisible on a held-out split of the same synthetic data, because
    the split inherits the same leak, which is why the reported accuracy looked
    excellent. Against real traffic it is catastrophic in the most damaging
    possible direction: every plain-HTTP request on the network gets classified
    as a DDoS, and an actual flood aimed at 443 reads as normal.

    Both classes now draw from the same realistic service-port mix, so port
    carries no class information and the model is forced onto duration, packet
    count and payload size — the features that actually generalise. `scan`
    keeps its uniform-random port because scanning genuinely does sweep
    arbitrary ports; that is real signal, not leakage.

    Expect the reported accuracy to *drop* after this change. That is the fix
    working: the previous figure was measuring the leak.
    """
    rng = np.random.RandomState(seed)
    X, y = [], []

    def port() -> int:
        return int(rng.choice(SERVICE_PORTS, p=SERVICE_PORT_WEIGHTS))

    def row(d: float, p: int, bpp: float, prt: int):
        d = max(float(d), 1e-3)
        p = max(int(p), 1)
        b = p * bpp
        return [d, p, b, p / d, b / p, prt]

    # normal — a mixture, because real benign traffic is not one shape. Most
    # flows are short interactive requests; a minority are bulk transfers whose
    # packet counts run into the thousands and overlap the flood class.
    for _ in range(n):
        if rng.rand() < 0.78:                       # interactive / web
            d = float(np.clip(rng.lognormal(0.2, 1.2), 0.02, 40))
            p = int(np.clip(rng.lognormal(3.2, 1.1), 2, 900))
            bpp = rng.uniform(120, 1400)
        else:                                        # bulk transfer / streaming
            d = float(np.clip(rng.lognormal(3.0, 0.9), 3, 400))
            p = int(np.clip(rng.lognormal(8.0, 1.0), 400, 60000))
            bpp = rng.uniform(700, 1460)
        X.append(row(d, p, bpp, port()))
        y.append("normal")

    # dos_ddos — defined by rate and payload shape, not raw volume. The rate
    # distribution deliberately reaches down into what a fast bulk transfer
    # looks like, so the boundary is genuinely ambiguous rather than a
    # threshold the model can memorise.
    for _ in range(n):
        d = float(np.clip(rng.lognormal(-0.4, 1.3), 0.01, 60))
        rate = float(np.clip(rng.lognormal(8.6, 1.4), 200, 4e6))
        # Floor of 8, not 50: a 10ms burst at the low end of the rate range
        # really is only a handful of packets, and forcing a floor high enough
        # to clear the scan class would hand the model a threshold instead of a
        # decision boundary.
        p = int(np.clip(rate * d, 8, 3_000_000))
        bpp = rng.uniform(40, 180)
        X.append(row(d, p, bpp, port()))
        y.append("dos_ddos")

    # scan — a handful of packets, near-instant, tiny payloads. Overlaps the
    # short tail of normal, which is correct: a single failed connection and a
    # single probe really do look alike at flow level.
    for _ in range(n):
        d = float(np.clip(rng.lognormal(-3.0, 1.2), 0.001, 3.0))
        p = int(np.clip(rng.lognormal(1.0, 0.8), 1, 40))
        bpp = rng.uniform(40, 220)
        prt = (int(rng.randint(1, 65536)) if rng.rand() < 0.85 else port())
        X.append(row(d, p, bpp, prt))
        y.append("scan")

    return np.array(X, dtype=np.float32), np.array(y)
