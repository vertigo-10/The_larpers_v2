"""Tests for the feature seam and the synthetic training distribution.

Two things are pinned here.

`flow_to_features` is described in its own module docstring as "the single most
breakage-prone seam in the system" — if its ordering drifts from FEATURE_NAMES
the model keeps returning confident predictions that are quietly nonsense — and
it had no test at all.

The generator tests exist because `make_data` originally hardcoded the
destination port per class (443 for every normal sample, 80 for every
dos_ddos sample). Since dst_port is a model input, that made the label
recoverable from a single feature, and every accuracy figure the project
reported was measuring the leak rather than the model. Nothing about that is
visible on a held-out split of the same data, so only an explicit test catches
a regression.
"""

import numpy as np

from backend.app.ml.features import flow_to_features
from backend.app.ml.net import CLASS_NAMES, FEATURE_NAMES, N_FEATURES, make_data


# ── the feature seam ──────────────────────────────────────────────────────
def test_feature_vector_matches_the_declared_names():
    vec = flow_to_features({
        "duration": 2.0, "packets": 10, "total_bytes": 1000, "dst_port": 443,
    })
    assert len(vec) == N_FEATURES == len(FEATURE_NAMES)


def test_feature_values_are_in_the_declared_order():
    """Order is the whole risk — a silent transposition is undetectable later."""
    vec = flow_to_features({
        "duration": 2.0, "packets": 10, "total_bytes": 1000, "dst_port": 443,
    })
    assert dict(zip(FEATURE_NAMES, vec)) == {
        "duration": 2.0,
        "packets": 10.0,
        "total_bytes": 1000.0,
        "packets_per_sec": 5.0,       # 10 / 2
        "bytes_per_packet": 100.0,    # 1000 / 10
        "dst_port": 443.0,
    }


def test_bytes_per_sec_is_accepted_instead_of_total_bytes():
    """Real collectors report one or the other."""
    vec = flow_to_features({
        "duration": 4.0, "packets": 8, "bytes_per_sec": 250, "dst_port": 80,
    })
    assert vec[FEATURE_NAMES.index("total_bytes")] == 1000.0     # 250 * 4
    assert vec[FEATURE_NAMES.index("bytes_per_packet")] == 125.0  # 1000 / 8


def test_instantaneous_flow_does_not_divide_by_zero():
    """A scan is ~1ms and can round to a reported duration of zero."""
    vec = flow_to_features({
        "duration": 0.0, "packets": 1, "total_bytes": 60, "dst_port": 22,
    })
    assert all(np.isfinite(v) for v in vec)
    assert vec[FEATURE_NAMES.index("packets_per_sec")] > 0


def test_zero_packet_flow_does_not_divide_by_zero():
    vec = flow_to_features({
        "duration": 1.0, "packets": 0, "total_bytes": 0, "dst_port": 443,
    })
    assert all(np.isfinite(v) for v in vec)
    assert vec[FEATURE_NAMES.index("bytes_per_packet")] == 0.0


def test_missing_fields_fall_back_rather_than_raising():
    """An agent that omits a field should degrade, not 500 the ingest route."""
    vec = flow_to_features({})
    assert len(vec) == N_FEATURES
    assert all(np.isfinite(v) for v in vec)


# ── the training distribution ─────────────────────────────────────────────
def test_generator_emits_every_class():
    _, y = make_data(n=300)
    assert sorted(set(y.tolist())) == sorted(CLASS_NAMES)


def test_generator_is_deterministic_for_a_seed():
    a, _ = make_data(n=200, seed=7)
    b, _ = make_data(n=200, seed=7)
    assert np.array_equal(a, b)


def test_destination_port_does_not_leak_the_label():
    """normal and dos_ddos must be indistinguishable on dst_port alone.

    The regression this guards: with a port hardcoded per class, the rule
    "dst_port == 80 implies dos_ddos" scored 100% on normal-vs-flood. Against
    real traffic that means every plain-HTTP request is called a DDoS, and a
    flood aimed at 443 reads as normal.
    """
    X, y = make_data(n=1500)
    port = X[:, FEATURE_NAMES.index("dst_port")]

    normal_ports = set(port[y == "normal"].tolist())
    flood_ports = set(port[y == "dos_ddos"].tolist())

    assert len(normal_ports) > 1, "normal traffic must not sit on a single port"
    assert len(flood_ports) > 1, "floods must not sit on a single port"

    overlap = normal_ports & flood_ports
    assert len(overlap) >= min(len(normal_ports), len(flood_ports)) * 0.8, (
        "normal and dos_ddos ports barely overlap — dst_port is still "
        "close to a giveaway for the label"
    )

    mask = (y == "normal") | (y == "dos_ddos")
    guess = np.where(port[mask] == 80, "dos_ddos", "normal")
    accuracy = (guess == y[mask]).mean()
    assert accuracy < 0.65, (
        f"port alone separates normal from dos_ddos at {accuracy:.0%} — "
        "the label leak is back"
    )


def test_no_single_feature_separates_the_classes_cleanly():
    """Guards the other half of the problem the port leak was hiding.

    The original distributions gave every class a disjoint packet-count range
    ([1,5], [10,500], [3000,50000]), so a two-threshold if-statement scored
    100% and the network was decorative. Classes must actually overlap for the
    reported accuracy to mean anything.
    """
    X, y = make_data(n=1500)
    for i, name in enumerate(FEATURE_NAMES):
        if name == "dst_port":
            continue  # scan legitimately sweeps arbitrary ports
        ranges = {}
        for c in CLASS_NAMES:
            v = X[y == c][:, i]
            ranges[c] = (v.min(), v.max())
        pairs = [(a, b) for a in CLASS_NAMES for b in CLASS_NAMES if a < b]
        for a, b in pairs:
            lo_a, hi_a = ranges[a]
            lo_b, hi_b = ranges[b]
            assert min(hi_a, hi_b) >= max(lo_a, lo_b), (
                f"{name}: {a} and {b} occupy disjoint ranges "
                f"({ranges[a]} vs {ranges[b]}) — a single threshold "
                "separates them and the model is not learning anything"
            )
