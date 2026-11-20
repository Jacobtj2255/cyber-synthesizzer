"""
Step 2 - Train & evaluate the hybrid CNN-LSTM intrusion detection model.

    python scripts/train.py                 # default 25 epochs, early stopping
    python scripts/train.py --epochs 5      # quick run
    python scripts/train.py --extra data/threat_intel.csv   # + honeypot intelligence

Outputs
  models/   cnn_lstm.keras, scaler.joblib, meta.json, background.npy
  reports/  metrics.json, classification_report.txt, confusion_matrix.png,
            training_curves.png, model_comparison.png, shap_global.png
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.preprocessing import StandardScaler

import config
from ndacs.features import FEATURES, LABEL_COL, transform
from ndacs.model import (BACKGROUND_PATH, META_PATH, MODEL_PATH, SCALER_PATH,
                         build_cnn_lstm)

R = config.REPORT_DIR


def load(name):
    p = config.PROCESSED_DIR / f"{name}.pkl"
    if not p.exists():
        sys.exit(f"{p} not found - run scripts/prepare_dataset.py first")
    return pd.read_pickle(p)


def binary_rates(y_true, y_pred, benign):
    t_att, p_att = y_true != benign, y_pred != benign
    tp = int(np.sum(t_att & p_att)); fn = int(np.sum(t_att & ~p_att))
    fp = int(np.sum(~t_att & p_att)); tn = int(np.sum(~t_att & ~p_att))
    return {"detection_rate": tp / max(tp + fn, 1), "false_positive_rate": fp / max(fp + tn, 1),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn}


def plot_cm(cm, classes, path, title):
    cmn = cm.astype(float) / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(8.5, 7))
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(classes)), classes, rotation=40, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, f"{cmn[i, j]*100:.1f}%\n({cm[i, j]})", ha="center", va="center", fontsize=7,
                    color="white" if cmn[i, j] > 0.5 else "black")
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(title)
    fig.colorbar(im, fraction=0.046)
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--batch", type=int, default=512)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--extra", default=None, help="extra labelled CSV (e.g. data/threat_intel.csv)")
    ap.add_argument("--no-baseline", action="store_true", help="skip Random Forest comparison")
    ap.add_argument("--no-shap", action="store_true", help="skip global SHAP plot")
    args = ap.parse_args()

    import tensorflow as tf
    from tensorflow import keras
    tf.random.set_seed(42); np.random.seed(42)

    train, val, test = load("train"), load("val"), load("test")
    if args.extra and Path(args.extra).exists():
        extra = pd.read_csv(args.extra)[FEATURES + [LABEL_COL]]
        print(f"Adding {len(extra):,} threat-intelligence rows from {args.extra}")
        train = pd.concat([train, extra], ignore_index=True)

    classes = sorted(train[LABEL_COL].unique(), key=lambda c: (c != "BENIGN", c))
    cidx = {c: i for i, c in enumerate(classes)}
    print("Classes:", classes)

    scaler = StandardScaler()
    Xtr = scaler.fit_transform(transform(train[FEATURES].values)).astype(np.float32)
    Xva = scaler.transform(transform(val[FEATURES].values)).astype(np.float32)
    Xte = scaler.transform(transform(test[FEATURES].values)).astype(np.float32)
    ytr = train[LABEL_COL].map(cidx).values
    yva = val[LABEL_COL].map(cidx).values
    yte = test[LABEL_COL].map(cidx).values

    # imbalance: sqrt-dampened inverse-frequency class weights
    counts = np.bincount(ytr, minlength=len(classes))
    w = np.sqrt(counts.max() / np.maximum(counts, 1))
    class_weight = {i: float(min(wi, 20.0)) for i, wi in enumerate(w)}
    print("Class weights:", {classes[i]: round(v, 2) for i, v in class_weight.items()})

    nf = len(FEATURES)
    model = build_cnn_lstm(nf, len(classes), args.lr)
    model.summary()
    cbs = [keras.callbacks.EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True),
           keras.callbacks.ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=2, min_lr=1e-5)]
    t0 = time.time()
    hist = model.fit(Xtr.reshape(-1, nf, 1), ytr, validation_data=(Xva.reshape(-1, nf, 1), yva),
                     epochs=args.epochs, batch_size=args.batch, class_weight=class_weight,
                     callbacks=cbs, verbose=2)
    train_time = time.time() - t0

    # ---------------------------------------------------------- evaluation
    t0 = time.time()
    probs = model.predict(Xte.reshape(-1, nf, 1), batch_size=2048, verbose=0)
    latency_ms = (time.time() - t0) / len(Xte) * 1000
    pred = probs.argmax(1)
    benign = cidx.get("BENIGN", -1)
    report_txt = classification_report(yte, pred, target_names=classes, digits=4, zero_division=0)
    report = classification_report(yte, pred, target_names=classes, output_dict=True, zero_division=0)
    cm = confusion_matrix(yte, pred, labels=range(len(classes)))
    metrics = {
        "model": "CNN-LSTM",
        "accuracy": accuracy_score(yte, pred),
        "precision_macro": precision_score(yte, pred, average="macro", zero_division=0),
        "recall_macro": recall_score(yte, pred, average="macro", zero_division=0),
        "f1_macro": f1_score(yte, pred, average="macro", zero_division=0),
        "f1_weighted": f1_score(yte, pred, average="weighted", zero_division=0),
        **binary_rates(yte, pred, benign),
        "latency_ms_per_flow": latency_ms,
        "train_time_s": train_time,
        "epochs_run": len(hist.history["loss"]),
        "per_class": {c: {k: report[c][k] for k in ("precision", "recall", "f1-score", "support")}
                      for c in classes},
    }
    print("\n" + report_txt)
    print(f"Accuracy {metrics['accuracy']:.4f} | macro-F1 {metrics['f1_macro']:.4f} | "
          f"detection rate {metrics['detection_rate']:.4f} | FPR {metrics['false_positive_rate']:.4f}")

    # ---------------------------------------------------------- save model
    model.save(MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    rng = np.random.default_rng(0)
    bg_idx = np.concatenate([rng.choice(np.where(ytr == i)[0], min(8, counts[i]), replace=False)
                             for i in range(len(classes)) if counts[i]])
    np.save(BACKGROUND_PATH, Xtr[bg_idx])
    info_p = config.PROCESSED_DIR / "info.json"
    info = json.loads(info_p.read_text()) if info_p.exists() else {}
    META_PATH.write_text(json.dumps({
        "classes": classes, "features": FEATURES, "trained_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": info.get("dataset", "unknown"), "train_rows": len(train),
    }, indent=2))

    # ---------------------------------------------------------- charts
    plot_cm(cm, classes, R / "confusion_matrix.png", "CNN-LSTM confusion matrix (test set)")
    fig, ax = plt.subplots(1, 2, figsize=(11, 4))
    ax[0].plot(hist.history["accuracy"], label="train"); ax[0].plot(hist.history["val_accuracy"], label="validation")
    ax[0].set_title("Accuracy"); ax[0].set_xlabel("epoch"); ax[0].legend()
    ax[1].plot(hist.history["loss"], label="train"); ax[1].plot(hist.history["val_loss"], label="validation")
    ax[1].set_title("Loss"); ax[1].set_xlabel("epoch"); ax[1].legend()
    fig.tight_layout(); fig.savefig(R / "training_curves.png", dpi=150); plt.close(fig)

    comparison = {"CNN-LSTM": {k: metrics[k] for k in ("accuracy", "f1_macro", "detection_rate", "false_positive_rate")}}
    if not args.no_baseline:
        print("\nTraining Random Forest baseline for comparison ...")
        n = min(len(Xtr), 150_000)
        sel = rng.choice(len(Xtr), n, replace=False)
        rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=0, class_weight="balanced_subsample")
        rf.fit(Xtr[sel], ytr[sel])
        rp = rf.predict(Xte)
        comparison["Random Forest"] = {
            "accuracy": accuracy_score(yte, rp), "f1_macro": f1_score(yte, rp, average="macro", zero_division=0),
            **{k: v for k, v in binary_rates(yte, rp, benign).items() if k in ("detection_rate", "false_positive_rate")}}
        names = list(comparison)
        keys = ["accuracy", "f1_macro", "detection_rate"]
        fig, ax = plt.subplots(figsize=(7, 4))
        for i, nm in enumerate(names):
            vals = [comparison[nm][k] for k in keys]
            bars = ax.bar(np.arange(len(keys)) + i * 0.38, vals, 0.36, label=nm)
            ax.bar_label(bars, fmt="%.3f", fontsize=8)
        ax.set_xticks(np.arange(len(keys)) + 0.19, ["Accuracy", "Macro F1", "Detection rate"])
        ax.set_ylim(min(0.5, ax.get_ylim()[0]), 1.05); ax.legend(); ax.set_title("Model comparison (test set)")
        fig.tight_layout(); fig.savefig(R / "model_comparison.png", dpi=150); plt.close(fig)
        print(json.dumps(comparison, indent=2))
    metrics["comparison"] = comparison

    if not args.no_shap:
        try:
            global_shap(model, Xtr[bg_idx], Xte, yte, pred, classes, benign)
            metrics["shap_global"] = True
        except Exception as e:
            print("SHAP global explanation skipped:", e)

    metrics["dataset"] = info.get("dataset", "unknown")
    (R / "metrics.json").write_text(json.dumps(metrics, indent=2, default=float))
    (R / "classification_report.txt").write_text(report_txt)
    print(f"\nSaved model to {MODEL_PATH} and reports to {R}")


def global_shap(model, background, Xte, yte, pred, classes, benign, n=60):
    """Mean |SHAP| per feature over correctly detected attacks -> bar chart."""
    import shap
    nf = len(FEATURES)
    idx = np.where((pred == yte) & (yte != benign))[0]
    if len(idx) == 0:
        return
    idx = np.random.default_rng(1).choice(idx, min(n, len(idx)), replace=False)
    f = lambda x: model.predict(x.reshape(-1, nf, 1), batch_size=4096, verbose=0)
    print(f"Computing global SHAP values on {len(idx)} attack flows ...")
    ex = shap.KernelExplainer(f, background)
    sv = ex.shap_values(Xte[idx], nsamples=200, silent=True)
    sv = np.asarray(sv)
    # shap>=0.45 returns (n, features, classes); older returns list per class
    if sv.ndim == 3 and sv.shape[0] == len(classes) and sv.shape[1] == len(idx):
        sv = np.transpose(sv, (1, 2, 0))
    contrib = np.abs(np.stack([sv[i, :, pred[j]] for i, j in enumerate(idx)]))
    imp = contrib.mean(0)
    order = np.argsort(imp)[-15:]
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh([FEATURES[i] for i in order], imp[order], color="#d9534f")
    ax.set_xlabel("mean |SHAP value| (impact on predicted attack class)")
    ax.set_title("Explainable AI: most influential features for attack detection")
    fig.tight_layout(); fig.savefig(R / "shap_global.png", dpi=150); plt.close(fig)


if __name__ == "__main__":
    main()
