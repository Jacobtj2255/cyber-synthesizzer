"""
SYNTHETIC dataset generator - for testing the pipeline only.

Simulates packet sequences for benign traffic and each attack family, runs
them through the SAME flow meter used for live capture, and writes a
CICIDS2017-format CSV into data/raw/.

Use it to check that everything installs and runs. For results you present,
train on the real CICIDS2017 dataset (see README).

    python scripts/make_synthetic_dataset.py --per-class 3000
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

import config
from ndacs.features import FEATURES, LABEL_COL
from ndacs.flowmeter import ACK, FIN, PSH, RST, SYN, Flow

rng = np.random.default_rng(7)


def tcp_session(dport, req_sizes, resp_sizes, gap, win_f=29200, win_b=28960, close="fin"):
    """Return list of packets (dt, is_fwd, payload, flags, win)."""
    pk = [(0, True, 0, SYN, win_f), (gap(), False, 0, SYN | ACK, win_b), (gap(), True, 0, ACK, win_f)]
    for q, r in zip(req_sizes, resp_sizes):
        pk.append((gap(), True, int(q), PSH | ACK, win_f))
        for chunk in _chunks(int(r)):
            pk.append((gap(), False, chunk, ACK | (PSH if chunk < 1448 else 0), win_b))
        pk.append((gap(), True, 0, ACK, win_f))
    if close == "fin":
        pk += [(gap(), True, 0, FIN | ACK, win_f), (gap(), False, 0, FIN | ACK, win_b),
               (gap(), True, 0, ACK, win_f)]
    elif close == "rst":
        pk.append((gap(), False, 0, RST, win_b))
    return pk


def _chunks(n):
    out = []
    while n > 0:
        out.append(min(n, 1448))
        n -= 1448
    return out


def g(lo, hi):          # log-uniform gap generator in seconds
    return lambda: float(np.exp(rng.uniform(np.log(lo), np.log(hi))))


def benign():
    kind = rng.choice(["web", "dns", "ssh", "tls"], p=[0.35, 0.3, 0.1, 0.25])
    if kind == "dns":
        return [(0, True, int(rng.integers(28, 60)), 0, None),
                (float(rng.uniform(0.005, 0.08)), False, int(rng.integers(60, 300)), 0, None)], 53, "UDP"
    port = {"web": 80, "ssh": 22, "tls": 443}[kind]
    k = int(rng.integers(1, 8))
    return tcp_session(port, rng.integers(200, 900, k), rng.integers(500, 40000, k),
                       g(0.0005, 0.4), win_f=int(rng.choice([29200, 64240, 65535, 8192])),
                       win_b=int(rng.choice([28960, 65160, 26883, 235]))), port, "TCP"


def portscan():
    port = int(rng.integers(1, 65535))
    open_ = rng.random() < 0.05
    pk = [(0, True, 0, SYN, 1024)]
    pk.append((float(rng.uniform(2e-5, 3e-4)), False, 0, (SYN | ACK) if open_ else (RST | ACK), 0 if not open_ else 29200))
    if open_:
        pk.append((float(rng.uniform(1e-5, 1e-4)), True, 0, RST, 0))
    return pk, port, "TCP"


def dos():
    if rng.random() < 0.5:   # slowloris / slowhttptest: long, tiny, slow
        pk = [(0, True, 0, SYN, 29200), (1e-4, False, 0, SYN | ACK, 28960), (1e-4, True, 0, ACK, 29200)]
        for _ in range(int(rng.integers(3, 12))):
            pk.append((float(rng.uniform(5, 15)), True, int(rng.integers(5, 30)), PSH | ACK, 29200))
            pk.append((float(rng.uniform(1e-4, 1e-3)), False, 0, ACK, 28960))
        return pk, 80, "TCP"
    # HULK / GoldenEye: big random GETs, server busy
    return tcp_session(80, rng.integers(300, 450, 1), rng.integers(0, 12000, 1), g(1e-4, 0.05),
                       win_f=29200, win_b=235, close=rng.choice(["fin", "rst"])), 80, "TCP"


def ddos():   # LOIC HTTP flood
    pk = [(0, True, 0, SYN, 8192), (1e-4, False, 0, SYN | ACK, 229), (1e-4, True, 0, ACK, 8192),
          (float(rng.uniform(1e-4, 1e-2)), True, int(rng.integers(0, 20)), PSH | ACK, 8192)]
    for chunk in _chunks(int(rng.choice([0, 11595, 5840]))):
        pk.append((float(rng.uniform(1e-4, 1e-2)), False, chunk, ACK, 229))
    pk.append((float(rng.uniform(0.5, 3)), True, 0, RST | ACK, 0))
    return pk, 80, "TCP"


def bruteforce():
    port = int(rng.choice([21, 22]))
    k = int(rng.integers(3, 8))
    return tcp_session(port, rng.integers(10, 40, k), rng.integers(20, 80, k), g(0.05, 1.5),
                       win_f=29200, win_b=227 if port == 21 else 247), port, "TCP"


def webattack():
    k = int(rng.integers(1, 4))
    return tcp_session(80, rng.integers(600, 1400, k), rng.integers(300, 4000, k), g(0.01, 1.0),
                       win_f=29200, win_b=235), 80, "TCP"


def bot():
    return tcp_session(8080, rng.integers(100, 250, 1), rng.integers(100, 400, 1), g(0.001, 0.05),
                       win_f=8192, win_b=237), 8080, "TCP"


GENERATORS = {"BENIGN": benign, "PortScan": portscan, "DoS": dos, "DDoS": ddos,
              "BruteForce": bruteforce, "WebAttack": webattack, "Bot": bot}


def build_flow(pkts, dport, proto):
    sport = int(rng.integers(32768, 61000))
    t = 1_700_000_000.0
    f = Flow(t, "10.0.0.5", "10.0.0.10", sport, dport, proto)
    for dt, is_fwd, plen, flags, win in pkts:
        t += dt
        f.add(t, is_fwd, plen, flags, win)
    return f.features()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=3000)
    ap.add_argument("--benign-multiplier", type=int, default=3)
    ap.add_argument("--out", default=str(config.RAW_DIR / "SYNTHETIC-demo.csv"))
    a = ap.parse_args()
    rows = []
    for label, gen in GENERATORS.items():
        n = a.per_class * (a.benign_multiplier if label == "BENIGN" else 1)
        for _ in range(n):
            pkts, port, proto = gen()
            rows.append(build_flow(pkts, port, proto) + [label])
    df = pd.DataFrame(rows, columns=FEATURES + [LABEL_COL]).sample(frac=1, random_state=1)
    df.to_csv(a.out, index=False)
    print(f"Wrote {len(df):,} synthetic flows -> {a.out}")
    print(df[LABEL_COL].value_counts().to_string())


if __name__ == "__main__":
    main()
