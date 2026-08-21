"""Turn a network flow into the 6-feature vector the model expects.

This is the single most breakage-prone seam in the system: if the ordering here
ever drifts from FEATURE_NAMES in net.py, the model keeps returning confident
predictions that are quietly nonsense. Keep them together.
"""

from typing import Dict, List

from .net import N_FEATURES

# Guards against divide-by-zero on instantaneous flows (scans are ~1ms).
_MIN_DURATION = 1e-3


def flow_to_features(flow: Dict) -> List[float]:
    """Build [duration, packets, total_bytes, pkts/s, bytes/pkt, dst_port].

    Accepts either `total_bytes` or `bytes_per_sec` — real collectors report one
    or the other, so we derive whichever is missing.
    """
    duration = max(float(flow.get("duration", 0.0)), _MIN_DURATION)
    packets = max(int(flow.get("packets", 0)), 0)

    if flow.get("total_bytes") is not None:
        total_bytes = float(flow["total_bytes"])
    elif flow.get("bytes_per_sec") is not None:
        total_bytes = float(flow["bytes_per_sec"]) * duration
    else:
        total_bytes = 0.0

    packets_per_sec = packets / duration
    bytes_per_packet = total_bytes / packets if packets > 0 else 0.0
    dst_port = float(flow.get("dst_port", 0))

    vec = [
        duration,
        float(packets),
        total_bytes,
        packets_per_sec,
        bytes_per_packet,
        dst_port,
    ]
    assert len(vec) == N_FEATURES, "feature vector drifted from net.FEATURE_NAMES"
    return vec
