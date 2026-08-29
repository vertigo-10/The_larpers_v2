"""Train the detector and persist everything needed to serve it.

Run:  python -m backend.app.ml.train --dataset cicids --data-dir data/cicids2017
      python -m backend.app.ml.train --dataset synthetic          (the old path)

Writes into the artifacts directory:
    model.pt      state_dict for net.Net
    scaler.joblib fitted transform pipeline  (without this, inference is wrong)
    labels.joblib fitted LabelEncoder
    metrics.json  REAL held-out metrics, measured — never hand-written

Every number in metrics.json comes from evaluating the trained net on a
stratified held-out split it never saw. If you change the data or the loop,
rerun this; nothing downstream invents numbers.

THE SCALER IS A PIPELINE, NOT A BARE StandardScaler
---------------------------------------------------
It is `signed_log1p -> StandardScaler`, saved as one object. The serving path in
infer.py calls `scaler.transform(raw_vector)` and must not need to know which
steps are inside. Putting the log transform anywhere else — in the trainer only,
or in infer.py separately — is how train/serve skew gets introduced.
"""

import argparse
import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder, StandardScaler
from torch.utils.data import DataLoader, TensorDataset

from .features import signed_log1p
from .net import CLASS_NAMES, FEATURE_NAMES, Net, make_data

DEFAULT_OUT = os.path.join(os.path.dirname(__file__), "..", "..", "artifacts")
DEFAULT_DATA = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "cicids2017")


def _build_scaler() -> Pipeline:
    """log-compress, then standardise. Persisted as a single transform."""
    return Pipeline([
        ("log", FunctionTransformer(signed_log1p, validate=False)),
        ("scale", StandardScaler()),
    ])


def _ablation(X_tr, y_tr, X_te, y_te, seed: int) -> dict:
    """Retrain on feature subsets to show where the accuracy actually comes from.

    Without this, a single headline number cannot be told apart from a model
    that has memorised one column. Cheap to compute and the most informative
    thing in the file, so it is not optional.
    """
    from sklearn.linear_model import LogisticRegression

    def score(cols):
        sc = _build_scaler()
        a = sc.fit_transform(X_tr[:, cols])
        b = sc.transform(X_te[:, cols])
        m = LogisticRegression(max_iter=400, multi_class="multinomial", n_jobs=-1)
        m.fit(a, y_tr)
        return round(float(m.score(b, y_te)) * 100, 2)

    port_idx = FEATURE_NAMES.index("dst_port")
    shape = [i for i in range(len(FEATURE_NAMES)) if i != port_idx]
    return {
        "port_only": score([port_idx]),
        "shape_only_no_port": score(shape),
        "note": (
            "Linear probes on feature subsets, same split. If the headline "
            "accuracy is close to port_only, the model is a port lookup rather "
            "than a traffic classifier."
        ),
    }


def train(epochs: int = 30, batch_size: int = 512, lr: float = 1e-3,
          n_per_class: int = 2000, seed: int = 42, out_dir: str = DEFAULT_OUT,
          dataset: str = "combined", data_dir: str = DEFAULT_DATA,
          per_class_cap: int = 150_000) -> dict:
    torch.manual_seed(seed)
    np.random.seed(seed)

    provenance: dict = {}
    domain = None  # per-row provenance, so accuracy can be reported per domain

    if dataset in ("cicids", "combined"):
        from . import cicids

        X, y_raw, load_stats = cicids.load(data_dir, per_class_cap=per_class_cap, seed=seed)
        leak_before = cicids.port_leak_report(X, y_raw)
        X, n_resampled = cicids.decorrelate_ddos_port(X, y_raw, seed=seed)
        leak_after = cicids.port_leak_report(X, y_raw)

        provenance = {
            "dataset": "cicids2017",
            "dataset_label": "CIC-IDS2017",
            "dataset_note": (
                "Trained and evaluated on CIC-IDS2017, a labelled capture of five "
                "working days of traffic recorded by the Canadian Institute for "
                "Cybersecurity in July 2017. Scores are measured on a stratified "
                "held-out split of that capture."
            ),
            "source_rows": load_stats["rows"],
            "rows_per_class_sampled": per_class_cap,
            "excluded_labels": list(cicids.EXCLUDED_LABELS),
            "excluded_rows": load_stats["dropped_unmapped"],
            "excluded_note": (
                "This model has three classes; the capture has fifteen labels. "
                "Brute-force, web-attack, botnet, infiltration and Heartbleed "
                "rows have no class to map to and were excluded from training "
                "and scoring. The model cannot detect those families — traffic "
                "of that kind will be scored as one of three classes that do not "
                "describe it."
            ),
            "malformed_rows_dropped": load_stats["dropped_malformed"],
            "port_decorrelation": {
                "applied": True,
                "rows_resampled": n_resampled,
                "port_only_accuracy_before": leak_before["port_only_accuracy"],
                "port_only_accuracy_after": leak_after["port_only_accuracy"],
                "note": (
                    "CIC ran every DoS/DDoS capture against a single web server, "
                    "so ~100% of attack rows carry destination port 80. Port is "
                    "feature #6, so left untouched the network learns 'port 80 = "
                    "attack' — which scores near-perfectly on this data and "
                    "inverts in deployment, calling ordinary HTTP a flood and "
                    "missing a flood aimed at 443. Attack rows therefore get a "
                    "port resampled from the benign distribution. Benign and "
                    "scan ports are left untouched, because a scan sweeping many "
                    "ports is real behaviour rather than an artifact."
                ),
            },
        }
        domain = np.full(len(X), "cicids", dtype=object)

        if dataset == "combined":
            # SENTRY's own flows are per-peer aggregates: the collector keys on
            # (peer, local port, protocol), so a flood from one address arrives
            # as ONE flow carrying tens of thousands of packets. CIC-IDS2017 is
            # per-TCP-connection, so its DDoS rows are individually small and
            # slow — median 9 packets at 0.6 packets/sec.
            #
            # Those two distributions barely overlap, and training on CIC alone
            # is measurably catastrophic here: such a model scores 97% on a CIC
            # held-out split and then classifies 100% of SENTRY's floods and
            # 100% of its scans as `normal`. It detects nothing while reporting
            # excellent accuracy, which is the worst failure this project has.
            #
            # So both domains go in. The model has to cover the traffic it is
            # actually served as well as the public benchmark, and the metrics
            # below report the two separately rather than averaging them into
            # one number that describes neither.
            n_syn = min(len(X), 60_000)
            X_syn, y_syn = make_data(n=n_syn // 3, seed=seed)
            keep = np.random.RandomState(seed).permutation(len(X))[:n_syn]
            X, y_raw = X[keep], y_raw[keep]
            domain = np.concatenate([
                np.full(len(X), "cicids", dtype=object),
                np.full(len(X_syn), "synthetic", dtype=object),
            ])
            X = np.concatenate([X, X_syn])
            y_raw = np.concatenate([y_raw, y_syn])
            provenance["dataset"] = "cicids2017+synthetic"
            provenance["dataset_label"] = "CIC-IDS2017 + SENTRY flow shapes"
            provenance["dataset_note"] = (
                "Trained on CIC-IDS2017 — a labelled capture of five working "
                "days recorded by the Canadian Institute for Cybersecurity in "
                "July 2017 — combined with generated flows matching the "
                "aggregation SENTRY's own collector performs. Both are needed: "
                "CIC-IDS2017 supplies real labelled attack traffic, but its "
                "flows are per-TCP-connection while SENTRY aggregates per peer, "
                "and a model trained on CIC alone detects none of the traffic "
                "this system actually receives. Accuracy is reported separately "
                "for each domain."
            )
            provenance["synthetic_rows"] = int(len(X_syn))
            provenance["cicids_rows"] = int(n_syn)
    elif dataset == "synthetic":
        X, y_raw = make_data(n=n_per_class, seed=seed)
        provenance = {
            "dataset": "synthetic",
            "dataset_label": "Synthetic",
            "dataset_note": (
                "Trained and evaluated on synthetically generated flows, not on "
                "captured traffic or CIC-IDS2017. These scores measure separation "
                "of three synthetic clusters and should not be read as real-world "
                "detection accuracy."
            ),
        }
        domain = np.full(len(X), "synthetic", dtype=object)
    else:
        raise ValueError(
            f"unknown dataset {dataset!r}; expected cicids, synthetic or combined"
        )

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)

    # Sanity: the served CLASS_NAMES must match the encoder's ordering, or every
    # prediction index maps to the wrong name.
    assert list(label_encoder.classes_) == CLASS_NAMES, (
        f"class order drift: encoder={list(label_encoder.classes_)} "
        f"vs net.CLASS_NAMES={CLASS_NAMES}"
    )

    X_tr, X_te, y_tr, y_te, _dom_tr, dom_te = train_test_split(
        X, y, domain, test_size=0.2, stratify=y, random_state=seed
    )

    # Fit on TRAIN ONLY. Fitting on everything leaks test statistics into
    # training and inflates the reported score.
    scaler = _build_scaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    tr_ds = TensorDataset(
        torch.tensor(X_tr_s, dtype=torch.float32), torch.tensor(y_tr, dtype=torch.long)
    )
    loader = DataLoader(tr_ds, batch_size=batch_size, shuffle=True)

    net = Net()
    opt = torch.optim.Adam(net.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss()

    for epoch in range(epochs):
        net.train()
        running = 0.0
        for xb, yb in loader:
            opt.zero_grad()
            loss = loss_fn(net(xb), yb)
            loss.backward()
            opt.step()
            running += loss.item() * len(xb)
        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(f"epoch {epoch + 1:3d}/{epochs}  loss={running / len(tr_ds):.5f}")

    # ── honest evaluation on the held-out split ──────────────────────────
    net.eval()
    X_te_t = torch.tensor(X_te_s, dtype=torch.float32)
    with torch.no_grad():
        logits = net(X_te_t)
        probs = torch.softmax(logits, dim=1)
        preds = logits.argmax(1).numpy()

    accuracy = float((preds == y_te).mean())
    report = classification_report(
        y_te, preds, target_names=list(label_encoder.classes_),
        output_dict=True, zero_division=0,
    )
    matrix = confusion_matrix(y_te, preds).tolist()

    print("measuring feature ablation…")
    ablation = _ablation(X_tr, y_tr, X_te, y_te, seed)

    metrics = {
        "accuracy": round(accuracy * 100, 3),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "framework": f"PyTorch {torch.__version__}",
        "architecture": "MLP 6-64-32-3",
        "preprocessing": "signed_log1p -> StandardScaler (fitted on train split only)",
        "features": FEATURE_NAMES,
        "classes": list(label_encoder.classes_),
        "test_samples": int(len(y_te)),
        "train_samples": int(len(y_tr)),
        "epochs": epochs,
        "confusion_matrix": matrix,
        "per_class": {
            name: {
                "precision": round(report[name]["precision"] * 100, 2),
                "recall": round(report[name]["recall"] * 100, 2),
                "f1": round(report[name]["f1-score"] * 100, 2),
                "support": int(report[name]["support"]),
            }
            for name in label_encoder.classes_
        },
        "mean_confidence": round(float(probs.max(dim=1).values.mean()) * 100, 2),
        "ablation": ablation,
    }

    # Reported per domain, never averaged away. A single blended number would
    # hide the case this whole arrangement exists to prevent: strong scores on
    # the public benchmark while detecting nothing in the traffic actually
    # served to it.
    domains = sorted(set(map(str, dom_te)))
    if len(domains) > 1:
        per_domain = {}
        for dm in domains:
            mask = dom_te == dm
            dm_acc = float((preds[mask] == y_te[mask]).mean())
            per_domain[dm] = {
                "accuracy": round(dm_acc * 100, 2),
                "test_samples": int(mask.sum()),
                "recall": {
                    name: round(
                        float(
                            (preds[mask & (y_te == idx)] == idx).mean()
                            if (mask & (y_te == idx)).any() else 0.0
                        ) * 100, 2)
                    for idx, name in enumerate(label_encoder.classes_)
                },
            }
        metrics["per_domain"] = per_domain
        metrics["per_domain_note"] = (
            "cicids = real per-connection flows from the public capture. "
            "synthetic = the per-peer aggregated shape SENTRY's own collector "
            "produces. The model must work on both; these are not averaged."
        )
    # Consumed by the UI to label the numbers accurately. Do not remove.
    metrics.update(provenance)

    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    torch.save(net.state_dict(), os.path.join(out_dir, "model.pt"))
    joblib.dump(scaler, os.path.join(out_dir, "scaler.joblib"))
    joblib.dump(label_encoder, os.path.join(out_dir, "labels.joblib"))
    with open(os.path.join(out_dir, "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)

    print(f"\nheld-out accuracy: {metrics['accuracy']}%  ({len(y_te)} samples)")
    for name, m in metrics["per_class"].items():
        print(f"  {name:<10} precision={m['precision']:6.2f}  recall={m['recall']:6.2f}")
    for dm, d in metrics.get("per_domain", {}).items():
        print(f"  [{dm}] {d['accuracy']}%  " +
              "  ".join(f"{k}={v}%" for k, v in d["recall"].items()))
    print(f"\nablation: port_only={ablation['port_only']}%  "
          f"shape_only={ablation['shape_only_no_port']}%")
    print(f"artifacts written to {out_dir}")
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the SENTRY detector.")
    ap.add_argument("--dataset", choices=("combined", "cicids", "synthetic"),
                    default="combined")
    ap.add_argument("--data-dir", type=str, default=DEFAULT_DATA)
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=512)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--samples", type=int, default=2000,
                    help="synthetic: samples per class")
    ap.add_argument("--cap", type=int, default=150_000,
                    help="cicids: rows sampled per class")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=str, default=DEFAULT_OUT)
    a = ap.parse_args()
    train(epochs=a.epochs, batch_size=a.batch_size, lr=a.lr,
          n_per_class=a.samples, seed=a.seed, out_dir=a.out,
          dataset=a.dataset, data_dir=a.data_dir, per_class_cap=a.cap)


if __name__ == "__main__":
    main()
