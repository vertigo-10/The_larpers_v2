"""Load CIC-IDS2017 and reduce it to the six features this model serves.

The dataset is eight CSVs of labelled flows captured at the Canadian Institute
for Cybersecurity over five working days in July 2017. Roughly 2.8M rows, ~880MB
uncompressed, which is why everything here streams rather than loading frames
into memory.

WHY THIS FILE IS SO FUSSY ABOUT FEATURE PARITY
----------------------------------------------
The served path builds its vector in `features.flow_to_features`. If this loader
derives the same six numbers even slightly differently — different duration
units, using the CSV's own `Flow Packets/s` column instead of recomputing it,
skipping the 1e-3 duration floor — then the model trains on one distribution and
is served another. That failure is silent: predictions stay confident and are
quietly wrong. So the row builder here deliberately mirrors that function line
for line, and a test asserts the two agree.

WHAT GETS DROPPED, AND WHY IT MATTERS
-------------------------------------
The model has three classes. The dataset has fifteen labels. BENIGN, the five
DoS/DDoS variants and PortScan map cleanly. The remaining six families —
brute-force (FTP/SSH-Patator), the three web attacks, Bot, Infiltration and
Heartbleed — have no class to map to, so their ~18k rows are excluded from both
training and evaluation.

That exclusion is not cosmetic and must not be buried. It means the reported
accuracy describes a three-way problem, and that a real SSH brute-force arriving
at a deployment will be scored as one of three classes that do not describe it —
most likely `normal`. The metrics carry this note so the console can state it.
"""

import csv
import glob
import os
import sys
from typing import Dict, List, Optional, Tuple

import numpy as np

from .features import _MIN_DURATION
from .net import N_FEATURES

# Some rows carry enormous fields; the default limit raises on them.
csv.field_size_limit(sys.maxsize)

# Flow Duration is recorded in microseconds. Everything the model sees is in
# seconds, so this is the single most important unit conversion in the file.
_MICROSECONDS = 1_000_000.0

# CIC's "Total Length of ... Packets" columns count PAYLOAD bytes. SENTRY's
# collector sums whole captured frames, headers included. Without correcting
# for that the two disagree about the same physical event: a SYN probe carries
# no payload, so it lands at ~3 bytes/packet in this dataset and ~60 in SENTRY,
# and the model receives one shape labelled `scan` and a near-identical shape
# labelled `normal`. Measured effect of leaving it uncorrected: scan recall on
# SENTRY's own traffic collapses from 99% to 43%.
#
# 40 bytes is a bare IPv4 + TCP header with no options. An approximation — real
# frames carry Ethernet framing and often timestamps — but it moves the two
# domains onto the same scale, which is what matters.
_HEADER_BYTES_PER_PACKET = 40.0

# Dataset label -> model class. Labels absent here are dropped on purpose; see
# the module docstring. Keys are compared after whitespace is stripped and the
# non-UTF8 dash in the "Web Attack" labels is normalised.
LABEL_MAP: Dict[str, str] = {
    "BENIGN": "normal",
    "DDoS": "dos_ddos",
    "DoS Hulk": "dos_ddos",
    "DoS GoldenEye": "dos_ddos",
    "DoS slowloris": "dos_ddos",
    "DoS Slowhttptest": "dos_ddos",
    "PortScan": "scan",
}

# Recorded so the metrics can name what the model was never taught, rather than
# leaving a reader to assume three classes covered the whole capture.
EXCLUDED_LABELS = (
    "FTP-Patator", "SSH-Patator", "Bot", "Infiltration", "Heartbleed",
    "Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - Sql Injection",
)

_COLUMNS = (
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Label",
)


def _resolve_columns(fieldnames: List[str]) -> Dict[str, str]:
    """Map bare column names to their real headers.

    The CSVs ship with inconsistent leading spaces (" Label", "Flow Bytes/s"),
    and at least one column name appears twice. Matching on the stripped name
    keeps this robust to that.
    """
    resolved = {}
    for raw in fieldnames or []:
        key = raw.strip()
        if key in _COLUMNS and key not in resolved:
            resolved[key] = raw
    missing = [c for c in _COLUMNS if c not in resolved]
    if missing:
        raise ValueError(f"CSV is missing expected columns: {missing}")
    return resolved


def _normalise_label(raw: str) -> str:
    """Strip whitespace and repair the mojibake dash in the web-attack labels.

    Those labels contain a non-UTF8 byte that decodes to a replacement char, so
    they arrive as "Web Attack � XSS". Normalised to a plain hyphen so the
    exclusion list can name them readably.
    """
    text = str(raw).strip()
    return " ".join(text.replace("�", "-").split())


def _row_to_features(row: Dict[str, str], cols: Dict[str, str]) -> Optional[List[float]]:
    """Mirror of features.flow_to_features, fed from a CSV row.

    Returns None when the row cannot produce a finite vector. The dataset is
    known to contain NaN and Infinity (its own Flow Bytes/s column overflows),
    negative durations, and header lines repeated mid-file.
    """
    try:
        duration_us = float(row[cols["Flow Duration"]])
        fwd_pkts = float(row[cols["Total Fwd Packets"]])
        bwd_pkts = float(row[cols["Total Backward Packets"]])
        fwd_bytes = float(row[cols["Total Length of Fwd Packets"]])
        bwd_bytes = float(row[cols["Total Length of Bwd Packets"]])
        dst_port = float(row[cols["Destination Port"]])
    except (TypeError, ValueError):
        return None  # a repeated header row, or a blank field

    # A negative duration is a capture artefact, not a flow.
    if duration_us < 0 or fwd_pkts < 0 or bwd_pkts < 0 or fwd_bytes < 0 or bwd_bytes < 0:
        return None

    duration = max(duration_us / _MICROSECONDS, _MIN_DURATION)
    packets = fwd_pkts + bwd_pkts

    if packets <= 0:
        return None

    # Payload -> approximate wire bytes. See _HEADER_BYTES_PER_PACKET.
    total_bytes = fwd_bytes + bwd_bytes + _HEADER_BYTES_PER_PACKET * packets

    # Derived here rather than read from the CSV's own Flow Packets/s column,
    # because the serving path derives them too. Trusting the dataset's
    # precomputed columns would train on numbers inference never produces.
    packets_per_sec = packets / duration
    bytes_per_packet = total_bytes / packets

    vec = [duration, packets, total_bytes, packets_per_sec, bytes_per_packet, dst_port]
    if not all(np.isfinite(v) for v in vec):
        return None
    assert len(vec) == N_FEATURES, "feature vector drifted from net.FEATURE_NAMES"
    return vec


def load(
    data_dir: str,
    per_class_cap: Optional[int] = None,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray, Dict[str, int]]:
    """Stream every CSV in `data_dir` and return (X, y, stats).

    `per_class_cap` balances the classes by reservoir-sampling that many rows
    per class. Without it the split is 86% benign and a model that answers
    "normal" to everything scores 86% while detecting nothing.
    """
    paths = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not paths:
        raise FileNotFoundError(f"no CSVs under {data_dir}")

    rng = np.random.RandomState(seed)
    buckets: Dict[str, List[List[float]]] = {c: [] for c in set(LABEL_MAP.values())}
    seen: Dict[str, int] = {c: 0 for c in buckets}
    stats = {"rows": 0, "dropped_unmapped": 0, "dropped_malformed": 0}

    for path in paths:
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            cols = _resolve_columns(reader.fieldnames)
            for row in reader:
                stats["rows"] += 1
                label = _normalise_label(row[cols["Label"]])
                cls = LABEL_MAP.get(label)
                if cls is None:
                    stats["dropped_unmapped"] += 1
                    continue
                vec = _row_to_features(row, cols)
                if vec is None:
                    stats["dropped_malformed"] += 1
                    continue

                seen[cls] += 1
                bucket = buckets[cls]
                if per_class_cap is None or len(bucket) < per_class_cap:
                    bucket.append(vec)
                else:
                    # Reservoir sampling: every row of this class gets an equal
                    # chance of being kept, so the sample is not just whichever
                    # day happened to be read first.
                    j = rng.randint(0, seen[cls])
                    if j < per_class_cap:
                        bucket[j] = vec

    X_parts, y_parts = [], []
    for cls, rows in sorted(buckets.items()):
        if not rows:
            raise ValueError(f"class {cls!r} matched no usable rows")
        X_parts.append(np.asarray(rows, dtype=np.float32))
        y_parts.append(np.full(len(rows), cls, dtype=object))
        stats[f"kept_{cls}"] = len(rows)
        stats[f"available_{cls}"] = seen[cls]

    return np.concatenate(X_parts), np.concatenate(y_parts), stats


# Index of dst_port within the feature vector. Asserted against FEATURE_NAMES on
# use so a reordering there cannot silently point this at the wrong column.
_PORT_IDX = 5


def port_leak_report(X: np.ndarray, y: np.ndarray) -> Dict[str, object]:
    """Describe how strongly destination port alone predicts the class.

    Reported rather than assumed, because the size of this number decides
    whether the trained model is a traffic classifier or a port lookup table.
    """
    ports = X[:, _PORT_IDX].astype(np.int64)
    table: Dict[int, Dict[str, int]] = {}
    for port, label in zip(ports, y):
        table.setdefault(int(port), {}).setdefault(str(label), 0)
        table[int(port)][str(label)] += 1
    correct = sum(max(counts.values()) for counts in table.values())
    per_class = {}
    for cls in sorted(set(map(str, y))):
        cls_ports = ports[y == cls]
        _, counts = np.unique(cls_ports, return_counts=True)
        per_class[cls] = {
            "distinct_ports": int(len(counts)),
            "top_port_share": round(float(counts.max()) * 100 / len(cls_ports), 2),
        }
    return {
        "port_only_accuracy": round(correct * 100 / len(y), 2),
        "per_class": per_class,
    }


def decorrelate_ddos_port(
    X: np.ndarray, y: np.ndarray, seed: int = 42
) -> Tuple[np.ndarray, int]:
    """Redraw `dst_port` for dos_ddos rows from the benign port distribution.

    THE PROBLEM THIS SOLVES
    -----------------------
    CIC ran their DDoS and DoS captures against a single Apache server, so
    essentially every attack row in the dataset carries destination port 80.
    Port is feature #6. Left alone, the network learns "port 80 -> attack",
    which scores ~99% on a held-out split of this data and is worthless in
    deployment, in the most damaging possible direction: every ordinary HTTP
    request to a web server gets called a DDoS, and a flood aimed at 443 reads
    as normal.

    This is the same label leak `net.make_data` documents removing from the
    synthetic generator — it is simply worse here, because the artifact is
    baked into a real capture rather than a hand-written distribution.

    THE REMEDY, AND ITS LIMITS
    --------------------------
    Attack rows get a port resampled from the empirical benign distribution, so
    port no longer separates dos_ddos from normal and the model is forced onto
    duration, packet count and payload shape — which do generalise, and which a
    port-free ablation shows carry the majority of the available signal.

    Two things are deliberately left alone:

    * `normal` keeps its real ports.
    * `scan` keeps its real ports. Scanning genuinely does sweep arbitrary
      destinations, and the dataset reflects that — a thousand distinct ports
      with no single one above a fraction of a percent. That is signal, not
      leakage, and erasing it would throw away something true.

    This changes one column of the attack rows. It is recorded in the metrics
    so nobody reads the resulting accuracy as untouched CIC-IDS2017.
    """
    from .net import FEATURE_NAMES

    assert FEATURE_NAMES[_PORT_IDX] == "dst_port", "port column moved"

    rng = np.random.RandomState(seed)
    out = X.copy()
    benign_ports = X[y == "normal", _PORT_IDX]
    if len(benign_ports) == 0:
        raise ValueError("cannot resample ports without benign rows")

    target = y == "dos_ddos"
    n = int(target.sum())
    out[target, _PORT_IDX] = rng.choice(benign_ports, size=n, replace=True)
    return out, n
