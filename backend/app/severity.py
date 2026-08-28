"""How bad a scored flow looks.

Its own module only because two things need it and they cannot import each
other: `engine` scores flows and `mitigation` decides how hard to respond to
them, and mitigation is called *from* engine. Left in engine.py, the response
tiers would have had to re-derive severity from confidence and bps, and the two
copies would have drifted the first time a threshold was tuned — the dashboard
calling something critical while the escalation ladder treated it as medium.

`engine.severity_for` still resolves, so nothing that imported it from there
had to change. This is not the anomaly severity in baseline.py, which grades a
z-score against a learned baseline and shares only the four rung names.
"""

from __future__ import annotations

BENIGN = "normal"


def severity_for(label: str, confidence: float, bps: float) -> str:
    if label == BENIGN:
        return "low"
    if label == "dos_ddos":
        if confidence >= 0.95 and bps > 5_000_000:
            return "critical"
        return "high" if confidence >= 0.9 else "medium"
    # scan
    return "medium" if confidence >= 0.9 else "low"


# Comparing severities needs an order, and the strings do not have one —
# "critical" sorts below "low" alphabetically, which is exactly backwards.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
