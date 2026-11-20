"""
Step 1 - Dataset collection & preprocessing (CICIDS2017).

Download "MachineLearningCSV.zip" (MachineLearningCVE folder, 8 CSV files) from
https://www.unb.ca/cic/datasets/ids-2017.html  and extract the CSVs into
data/raw/   then run:

    python scripts/prepare_dataset.py

What it does
  * reads only the 40 features our live sniffer can reproduce (low RAM use)
  * cleans NaN / Infinity values and duplicate rows
  * groups 15 labels into 8 attack families (BENIGN, DoS, DDoS, PortScan,
    BruteForce, WebAttack, Bot, Infiltration)
  * handles class imbalance by capping the huge classes (undersampling)
  * stratified split into train / validation / test (70 / 15 / 15)
"""
import argparse
import glob
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

import config
from ndacs.features import FEATURES, LABEL_COL, map_label, normalise_column


def load_csv(path):
    header = pd.read_csv(path, nrows=0, encoding="latin-1").columns
    mapping = {c: normalise_column(c) for c in header}
    wanted = [c for c in header if mapping[c] in FEATURES + [LABEL_COL]]
    df = pd.read_csv(path, usecols=wanted, encoding="latin-1", low_memory=False)
    df = df.rename(columns=mapping)
    df = df.loc[:, ~df.columns.duplicated()]      # CICIDS2017 repeats some headers
    # Some CICIDS2017 files contain blank lines at the end
    df = df.dropna(subset=[LABEL_COL])
    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce").astype(np.float32)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df[LABEL_COL] = df[LABEL_COL].map(map_label)
    df = df.dropna(subset=[LABEL_COL])
    return df[FEATURES + [LABEL_COL]]


def sample_per_class(df, cap_for, seed):
    """Undersample each class to at most cap_for(label) rows."""
    out = []
    for lbl, g in df.groupby(LABEL_COL):
        n = cap_for(lbl)
        out.append(g.sample(n, random_state=seed) if len(g) > n else g)
    return pd.concat(out, ignore_index=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(config.RAW_DIR), help="folder with CICIDS2017 CSVs")
    ap.add_argument("--out", default=str(config.PROCESSED_DIR))
    ap.add_argument("--benign-cap", type=int, default=250_000, help="max BENIGN rows kept")
    ap.add_argument("--attack-cap", type=int, default=60_000, help="max rows per attack family")
    ap.add_argument("--min-class", type=int, default=500, help="drop families smaller than this")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    files = sorted(glob.glob(str(Path(args.input) / "*.csv")))
    if not files:
        sys.exit(f"No CSV files found in {args.input}. Download CICIDS2017 MachineLearningCSV first "
                 "(or run scripts/make_synthetic_dataset.py for a quick pipeline test).")

    parts = []
    for f in files:
        df = load_csv(f)
        print(f"  {Path(f).name:70s} rows={len(df):>8,}  {df[LABEL_COL].value_counts().to_dict()}")
        # cap per file to keep RAM low on small VMs
        parts.append(sample_per_class(df, lambda lbl: args.benign_cap, args.seed))
    df = pd.concat(parts, ignore_index=True)
    before = len(df)
    df = df.drop_duplicates()
    print(f"\nRemoved {before - len(df):,} duplicate rows")

    counts = df[LABEL_COL].value_counts()
    keep = counts[counts >= args.min_class].index
    dropped = counts[counts < args.min_class]
    if len(dropped):
        print("Dropping tiny classes:", dropped.to_dict())
    df = df[df[LABEL_COL].isin(keep)]

    df = sample_per_class(
        df, lambda lbl: args.benign_cap if lbl == "BENIGN" else args.attack_cap, args.seed)

    print("\nFinal class distribution:")
    print(df[LABEL_COL].value_counts().to_string())

    train, tmp = train_test_split(df, test_size=0.30, stratify=df[LABEL_COL], random_state=args.seed)
    val, test = train_test_split(tmp, test_size=0.50, stratify=tmp[LABEL_COL], random_state=args.seed)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    train.to_pickle(out / "train.pkl")
    val.to_pickle(out / "val.pkl")
    test.to_pickle(out / "test.pkl")
    test.to_csv(out / "test.csv", index=False)      # used by replay / demo mode
    synthetic = any(Path(f).name.upper().startswith("SYNTHETIC") for f in files)
    (out / "info.json").write_text(json.dumps({
        "source_files": [Path(f).name for f in files],
        "dataset": "SYNTHETIC (pipeline test only)" if synthetic else "CICIDS2017",
        "class_counts": df[LABEL_COL].value_counts().to_dict(),
        "rows": {"train": len(train), "val": len(val), "test": len(test)},
    }, indent=2))
    print(f"\nSaved train={len(train):,}  val={len(val):,}  test={len(test):,}  -> {out}")


if __name__ == "__main__":
    main()
