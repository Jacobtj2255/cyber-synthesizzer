"""
Feature definition shared by TRAINING (CICIDS2017 CSVs) and LIVE CAPTURE
(our Scapy flow meter).

CICIDS2017 has 78 CICFlowMeter features. We deliberately train on the 40
features that our live sniffer can compute exactly the same way, so the model
trained offline works on real traffic captured from the network.
Units follow CICFlowMeter: times in MICROSECONDS, lengths = payload bytes.
"""
import re
import numpy as np

FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
]
N_FEATURES = len(FEATURES)
LABEL_COL = "Label"
FAMILIES = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot", "Infiltration"]


def map_label(raw: str):
    """Group the 15 CICIDS2017 labels into 8 attack families.
    Returns None for labels we drop."""
    s = str(raw).strip()
    if s in FAMILIES:          # already grouped (synthetic data / threat intel)
        return s
    low = s.lower()
    if low == "benign":
        return "BENIGN"
    if low == "ddos":
        return "DDoS"
    if low.startswith("dos") or low == "heartbleed":
        return "DoS"
    if low == "portscan":
        return "PortScan"
    if "patator" in low:
        return "BruteForce"
    if low.startswith("web attack"):
        return "WebAttack"
    if low == "bot":
        return "Bot"
    if low == "infiltration":
        return "Infiltration"
    return None


def normalise_column(name: str) -> str:
    """CICIDS2017 headers contain leading spaces / odd spacing."""
    return re.sub(r"\s+", " ", str(name)).strip()


def transform(X):
    """Signed log transform applied before standard scaling.
    Network features span many orders of magnitude (bytes/s up to 1e9),
    log compresses them so the neural network trains stably."""
    X = np.asarray(X, dtype=np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    return np.sign(X) * np.log1p(np.abs(X))


# Human-readable hints used by the XAI layer when writing explanations
FEATURE_HINTS = {
    "Destination Port": "target service port",
    "Flow Duration": "how long the connection lasted",
    "Total Fwd Packets": "packets sent by the source",
    "Total Backward Packets": "packets returned by the target",
    "Total Length of Fwd Packets": "bytes sent by the source",
    "Total Length of Bwd Packets": "bytes returned by the target",
    "Flow Bytes/s": "data rate of the flow",
    "Flow Packets/s": "packet rate of the flow",
    "Flow IAT Mean": "average gap between packets",
    "Flow IAT Max": "longest gap between packets",
    "SYN Flag Count": "connection-open (SYN) packets",
    "RST Flag Count": "connection resets",
    "FIN Flag Count": "connection-close packets",
    "PSH Flag Count": "pushed data packets",
    "ACK Flag Count": "acknowledgement packets",
    "Init_Win_bytes_forward": "initial TCP window of the source",
    "Init_Win_bytes_backward": "initial TCP window of the target",
    "Average Packet Size": "average packet size",
    "act_data_pkt_fwd": "source packets carrying data",
    "Bwd Packet Length Mean": "average size of replies",
    "Fwd Packet Length Mean": "average size of requests",
}
