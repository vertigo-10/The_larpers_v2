"""Train the detector and persist everything needed to serve it.

Run:  python -m backend.app.ml.train  [--epochs N] [--out DIR]

Writes into the artifacts directory:
    model.pt      state_dict for net.Net
    scaler.joblib fitted StandardScaler  (without this, inference is wrong)
    labels.joblib fitted LabelEncoder
    metrics.json  REAL held-out metrics, measured — never hand-written

Every number in metrics.json comes from evaluating the trained net on a
stratified held-out split it never saw. If you change the data or the loop,
rerun this; nothing downstream invents numbers.
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
from sklearn.preprocessing import LabelEncoder, StandardScaler
from torch.utils.data import DataLoader, TensorDataset

from .net import CLASS_NAMES, FEATURE_NAMES, Net, make_data

DEFAULT_OUT = os.path.join(os.path.dirname(__file__), "..", "..", "artifacts")


def train(epochs: int = 60, batch_size: int = 128, lr: float = 1e-3,
          n_per_class: int = 2000, seed: int = 42, out_dir: str = DEFAULT_OUT) -> dict:
    torch.manual_seed(seed)
    np.random.seed(seed)

    X, y_raw = make_data(n=n_per_class, seed=seed)

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)

    # Sanity: the served CLASS_NAMES must match the encoder's ordering, or every
    # prediction index maps to the wrong name.
    assert list(label_encoder.classes_) == CLASS_NAMES, (
        f"class order drift: encoder={list(label_encoder.classes_)} "
        f"vs net.CLASS_NAMES={CLASS_NAMES}"
    )

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=seed
    )

    # Fit the scaler on TRAIN ONLY. Fitting on everything leaks test statistics
    # into training and inflates the reported score.
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_tr)
    X_te = scaler.transform(X_te)

    tr_ds = TensorDataset(
        torch.tensor(X_tr, dtype=torch.float32), torch.tensor(y_tr, dtype=torch.long)
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
        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"epoch {epoch + 1:3d}/{epochs}  loss={running / len(tr_ds):.5f}")

    # ── honest evaluation on the held-out split ──────────────────────────
    net.eval()
    X_te_t = torch.tensor(X_te, dtype=torch.float32)
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

    metrics = {
        "accuracy": round(accuracy * 100, 3),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "framework": f"PyTorch {torch.__version__}",
        "architecture": "MLP 6-64-32-3",
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
        # Consumed by the UI to label the numbers accurately. Do not remove.
        "dataset": "synthetic",
        "dataset_note": (
            "Trained and evaluated on synthetically generated flows, not on "
            "captured traffic or CIC-IDS2017. These scores measure separation of "
            "three synthetic clusters and should not be read as real-world "
            "detection accuracy."
        ),
    }

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
    print(f"\nartifacts written to {out_dir}")
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the SENTRY detector.")
    ap.add_argument("--epochs", type=int, default=60)
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--samples", type=int, default=2000, help="samples per class")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=str, default=DEFAULT_OUT)
    a = ap.parse_args()
    train(epochs=a.epochs, batch_size=a.batch_size, lr=a.lr,
          n_per_class=a.samples, seed=a.seed, out_dir=a.out)


if __name__ == "__main__":
    main()
