"""
The NDACS engine - ties every module together:

  capture (live Scapy / replay) -> flow features -> CNN-LSTM detection
        -> alert + XAI explanation -> automated response (block / honeypot)
  behaviour rules  ----------------^
  honeypot events  -> threat intelligence (known attackers, data for retraining)
"""
import csv
import logging
import queue
import random
import threading
import time
from collections import deque
from datetime import datetime

import numpy as np

import config
from ndacs import db
from ndacs.explainer import Explainer, rule_explanation
from ndacs.features import FEATURES, LABEL_COL

log = logging.getLogger("ndacs.engine")

HONEYPOT_SERVICE_LABEL = {"ftp": "BruteForce", "telnet": "BruteForce", "ssh": "PortScan",
                          "ssh-cowrie": "BruteForce", "http": "WebAttack"}


class Engine:
    def __init__(self, mode="live", response_mode=None):
        self.mode = mode
        self.started = time.time()
        db.init_db()
        from ndacs.responder import Responder
        self.responder = Responder("simulated" if mode == "replay" else response_mode)
        self.detector = None
        self.explainer = None
        try:
            from ndacs.model import Detector
            self.detector = Detector()
            log.info("CNN-LSTM model loaded (%d classes, trained on %s)",
                     len(self.detector.classes), self.detector.meta.get("dataset"))
            if config.EXPLAIN_ALERTS:
                self.explainer = Explainer(self.detector, config.EXPLAINER)
        except FileNotFoundError as e:
            log.warning("%s  -> running with behaviour/signature detection only.", e)

        self.flow_q = queue.Queue(maxsize=50000)
        self.explain_q = queue.Queue(maxsize=1000)
        self.feed = deque(maxlen=150)              # live flow feed for the dashboard
        self.known_bad = {}                        # ip -> label (threat intelligence)
        self.stats = {"flows": 0, "benign": 0, "malicious": 0, "dropped": 0, "packets": 0}
        self._pending = [0, 0]
        self._intel_rows = 0
        self._intel_lock = threading.Lock()
        self._stop = threading.Event()
        self.capture = None
        self.meter = None
        self.honeypot = None

    # ================================================================ inputs
    def on_flow(self, meta, features):
        try:
            self.flow_q.put_nowait((meta, features))
        except queue.Full:
            self.stats["dropped"] += 1

    def on_behaviour(self, src, dst, dport, label, text, facts):
        meta = {"src_ip": src, "dst_ip": dst, "src_port": None, "dst_port": dport, "protocol": "TCP"}
        self.handle_detection(meta, label, 1.0, "signature", explanation=rule_explanation(label, text, facts))

    def on_honeypot(self, ip, service, event, details):
        label = HONEYPOT_SERVICE_LABEL.get(service, "PortScan")
        self.known_bad.setdefault(ip, label)
        if event == "connect":
            return
        what = {"login_attempt": f"tried to log in to the fake {service.upper()} service "
                                 f"(user='{details.get('username')}', password='{details.get('password')}')",
                "web_attack": "sent an attack payload to the fake web admin page",
                "command": f"sent a command to the fake {service.upper()} service",
                "client_version": f"probed the fake SSH service ({details.get('data')})",
                "request": "requested the fake web admin page"}.get(event, event)
        port = {k: v for k, v in config.HONEYPOT_PORTS.items()}.get(service.split("-")[0])
        meta = {"src_ip": ip, "dst_ip": "honeypot", "src_port": None, "dst_port": port, "protocol": "TCP"}
        self.handle_detection(meta, "Honeypot-Contact", 1.0, "honeypot",
                              explanation=rule_explanation(
                                  "Honeypot-Contact",
                                  f"{ip} {what}. Legitimate users never touch the honeypot, so this IP is "
                                  f"now tracked as a known attacker (threat intelligence).",
                                  {"service": service, "event": event}))

    # ================================================================ core logic
    def handle_detection(self, meta, label, conf, source, features=None, explanation=None):
        src = meta["src_ip"]
        severity = config.SEVERITY.get(label, "medium")
        policy = config.ACTION_POLICY.get(label, "block")
        hp_ports = set(config.HONEYPOT_PORTS.values())
        if conf < config.BLOCK_THRESHOLD:
            action = "alert"
        elif meta.get("dst_port") in hp_ports and policy != "monitor":
            action = "monitor"          # attacker is busy with the honeypot - keep collecting intel
        else:
            action = policy
        if src in self.known_bad and severity == "medium":
            severity = "high"           # repeat offender seen by the honeypot
        alert_id, is_new = db.record_alert(
            src, meta.get("dst_ip"), meta.get("src_port"), meta.get("dst_port"), meta.get("protocol"),
            label, float(conf), severity, source, action,
            features=dict(zip(FEATURES, map(float, features))) if features is not None else None)
        if action in ("block", "redirect"):
            taken = self.responder.act(src, label, action)
            if is_new or taken != "already-blocked":
                db.set_alert_action(alert_id, taken)
        if is_new:
            if explanation is not None:
                db.set_alert_explanation(alert_id, explanation)
            elif self.explainer is not None and features is not None:
                try:
                    self.explain_q.put_nowait((alert_id, np.asarray(features)))
                except queue.Full:
                    pass
        if label in config.SEVERITY and label not in ("Honeypot-Contact", "SYN-Flood"):
            self.known_bad.setdefault(src, label)
        if features is not None and label not in ("Honeypot-Contact",):
            self._save_intel(features, "DoS" if label == "SYN-Flood" else label)

    def _save_intel(self, features, label, cap=20000):
        """Store attacker flows -> data/threat_intel.csv (use with train.py --extra)."""
        if self.mode == "replay" or self._intel_rows >= cap:
            return
        with self._intel_lock:
            new = not config.THREAT_INTEL_CSV.exists()
            with open(config.THREAT_INTEL_CSV, "a", newline="") as f:
                w = csv.writer(f)
                if new:
                    w.writerow(FEATURES + [LABEL_COL])
                w.writerow(list(map(float, features)) + [label])
            self._intel_rows += 1

    def _detect_loop(self):
        while not self._stop.is_set():
            batch = []
            try:
                batch.append(self.flow_q.get(timeout=0.5))
                while len(batch) < 256:
                    batch.append(self.flow_q.get_nowait())
            except queue.Empty:
                pass
            if not batch:
                self._flush_stats()
                continue
            metas = [b[0] for b in batch]
            X = np.array([b[1] for b in batch], dtype=np.float64)
            if self.detector is not None:
                labels, confs, _ = self.detector.predict(X)
            else:
                labels, confs = ["UNKNOWN"] * len(batch), np.zeros(len(batch))
            for meta, x, lab, c in zip(metas, X, labels, confs):
                c = float(c)
                malicious = lab not in ("BENIGN", "UNKNOWN") and c >= config.ALERT_THRESHOLD
                self.stats["flows"] += 1
                self.stats["malicious" if malicious else "benign"] += 1
                self._pending[1 if malicious else 0] += 1
                self.feed.appendleft({
                    "t": datetime.now().strftime("%H:%M:%S"), "src": meta["src_ip"], "dst": meta["dst_ip"],
                    "sport": meta["src_port"], "dport": meta["dst_port"], "proto": meta["protocol"],
                    "pkts": int(x[2] + x[3]), "bytes": int(x[4] + x[5]),
                    "label": lab, "conf": round(c, 3), "malicious": malicious,
                    "intel": meta["src_ip"] in self.known_bad})
                if malicious:
                    self.handle_detection(meta, lab, c, "model", features=x)
            self._flush_stats()

    def _flush_stats(self, every=2.0):
        now = time.time()
        if now - getattr(self, "_last_flush", 0) < every or not any(self._pending):
            return
        self._last_flush = now
        b, m = self._pending
        self._pending = [0, 0]
        try:
            db.add_traffic(b, m)
        except Exception:
            log.exception("stats flush failed")

    def _explain_loop(self):
        while not self._stop.is_set():
            try:
                alert_id, x = self.explain_q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                db.set_alert_explanation(alert_id, self.explainer.explain(x))
            except Exception:
                log.exception("explanation failed")

    # ================================================================ sources
    def start_live(self, iface=None):
        from ndacs.behaviour import BehaviourEngine
        from ndacs.flowmeter import FlowMeter, LiveCapture
        from ndacs.responder import local_addresses
        self.meter = FlowMeter(self.on_flow, config.FLOW_IDLE_TIMEOUT, config.FLOW_ACTIVE_TIMEOUT,
                               config.MAX_ACTIVE_FLOWS)
        beh = BehaviourEngine(self.on_behaviour, own_ips=local_addresses())
        self.meter.packet_listeners.append(beh.on_packet)
        self.meter.ignore_ports = {config.DASHBOARD_PORT}
        bpf = f"ip and not port {config.DASHBOARD_PORT}"
        self.capture = LiveCapture(self.meter, iface or config.INTERFACE, bpf)
        self.capture.start()

    def start_replay(self, csv_path=None, rate=15.0, attack_ratio=0.35):
        import pandas as pd
        csv_path = csv_path or (config.PROCESSED_DIR / "test.csv")
        df = pd.read_csv(csv_path)
        groups = {lbl: g[FEATURES].values for lbl, g in df.groupby(LABEL_COL)}
        attacks = [l for l in groups if l != "BENIGN"]
        benign = groups.get("BENIGN")
        log.info("Replay mode: %s (%d flows, attacks: %s)", csv_path, len(df), attacks)
        pools = {l: [f"203.0.113.{10 + i * 10 + k}" for k in range(3)] for i, l in enumerate(attacks)}
        clients = [f"192.168.56.{i}" for i in range(20, 60)]
        servers = {"PortScan": None, "BruteForce": 22, "WebAttack": 80, "DoS": 80, "DDoS": 80, "Bot": 8080}

        def run():
            campaign, left = None, 0
            while not self._stop.is_set():
                if left <= 0 and random.random() < attack_ratio / 4:
                    campaign = random.choice(attacks)
                    attacker = random.choice(pools[campaign])
                    left = random.randint(8, 40)
                if left > 0 and campaign:
                    x = groups[campaign][random.randrange(len(groups[campaign]))]
                    src, left = attacker, left - 1
                elif benign is not None:
                    x = benign[random.randrange(len(benign))]
                    src = random.choice(clients)
                else:
                    continue
                dport = int(x[0])
                meta = {"src_ip": src, "dst_ip": "192.168.56.10", "src_port": random.randint(32768, 60999),
                        "dst_port": dport, "protocol": "TCP" if dport != 53 else "UDP"}
                self.on_flow(meta, x.tolist())
                time.sleep(random.expovariate(rate))
        threading.Thread(target=run, daemon=True, name="replay").start()

    def start_honeypot(self):
        from ndacs.honeypot import Honeypot
        self.honeypot = Honeypot(self.on_honeypot)
        self.honeypot.start()

    def start(self):
        threading.Thread(target=self._detect_loop, daemon=True, name="detector").start()
        if self.explainer is not None:
            threading.Thread(target=self._explain_loop, daemon=True, name="xai").start()
        self.responder.start()

    def stop(self):
        self._stop.set()
        if self.capture:
            self.capture.stop()
        self.responder.shutdown()

    # ================================================================ status
    def status(self):
        return {
            "mode": self.mode,
            "uptime_s": int(time.time() - self.started),
            "model_loaded": self.detector is not None,
            "model_dataset": self.detector.meta.get("dataset") if self.detector else None,
            "model_trained_at": self.detector.meta.get("trained_at") if self.detector else None,
            "explainer": self.explainer.method.upper() if self.explainer else "off",
            "response_mode": self.responder.mode,
            "database": db.db_name(),
            "honeypot": self.honeypot.running if self.honeypot else [],
            "queue": self.flow_q.qsize(),
            "packets": self.meter.packets if self.meter else None,
            "active_flows": len(self.meter.flows) if self.meter else None,
            "known_attackers": len(self.known_bad),
            "session": self.stats,
        }
