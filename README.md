# NDACS — Network Defense Automated Cyber Synthesizer

AI-powered network intrusion detection and automated response system.
SCMS School of Engineering and Technology · Dept. of Computer Science and Engineering

| Module (from the project presentation) | Where it lives |
|---|---|
| Real-time traffic capture & monitoring (Scapy) | `ndacs/flowmeter.py` |
| Pre-processing & feature extraction (CICFlowMeter-compatible, 40 features) | `ndacs/features.py`, `scripts/prepare_dataset.py` |
| Hybrid **CNN-LSTM** detection & classification (TensorFlow) | `ndacs/model.py`, `scripts/train.py` |
| **Explainable AI** — SHAP / LIME | `ndacs/explainer.py` |
| Signature & behaviour-based detection | `ndacs/behaviour.py` |
| **Honeypot server** (FTP, Telnet, SSH, HTTP decoys + optional Cowrie) | `ndacs/honeypot.py`, `deploy/cowrie-docker-compose.yml` |
| Automated response — block IP / redirect to honeypot (iptables) | `ndacs/responder.py` |
| Attack logs & threat intelligence (MySQL / SQLite) | `ndacs/db.py`, `data/threat_intel.csv` |
| Centralised dashboard (Flask + HTML/CSS/JS + Chart.js) | `ndacs/dashboard.py`, `web/` |
| Orchestration | `ndacs/engine.py`, `run.py` |

---

## 1. How it works

```
             ┌──────────────── Defender VM (Ubuntu) ─────────────────────────────────────┐
 network ──► │ Scapy sniffer ─► Flow meter ─► 40 features ─► CNN-LSTM ─► alert?           │
 traffic     │      │                                            │        │              │
             │      └─► Behaviour rules (scan / SYN flood / brute force) ──┤              │
             │                                                            ▼              │
             │   SHAP / LIME explanation ◄── alert ──► Response engine (iptables)        │
             │                                   │       ├─ block  : DROP attacker       │
             │                                   │       └─ redirect: attacker ─► honeypot│
             │   Honeypot (FTP/Telnet/SSH/HTTP) ─┼─► credentials, payloads, attacker IPs │
             │                                   ▼                                       │
             │                         MySQL / SQLite  ──►  Flask dashboard :5000        │
             │                         threat_intel.csv ──► retrain (train.py --extra)   │
             └───────────────────────────────────────────────────────────────────────────┘
```

* **Why 40 features?** CICIDS2017 has 78 CICFlowMeter features. We train only on the 40 that our live
  Scapy flow meter computes in exactly the same way (same units: microseconds, payload bytes), so the
  model trained offline works on real captured traffic.
* **Class imbalance:** large classes are undersampled and the remaining imbalance is handled with class weights.
* **Two detection layers:** the CNN-LSTM classifies every finished flow; behaviour rules react per packet
  (fast, and keep working even before a model is trained).
* **Explainability:** every model alert gets a SHAP explanation (top features that pushed the decision,
  with real values and a plain-English sentence), computed in a background thread so detection is not delayed.
* **Threat intelligence:** IPs that touch the honeypot are tracked as known attackers, and flows from
  detected attackers are saved to `data/threat_intel.csv` so the model can be retrained with them.

---

## 2. Lab setup in VirtualBox

Recommended: **two VMs** on the same internal network.

| VM | OS | Role |
|---|---|---|
| Defender | Ubuntu 22.04/24.04 (your existing VM) | runs NDACS |
| Attacker | Kali Linux (or any Linux with nmap/hydra/hping3) | generates attacks |

**Network:** VirtualBox → *File → Tools → Network Manager → NAT Networks → Create* (e.g. `NdacsNet`, 10.0.5.0/24).
For each VM: *Settings → Network → Adapter 1 → Attached to: NAT Network → NdacsNet* (both VMs keep internet access).
Then `ip a` in each VM to see its IP (e.g. defender `10.0.5.4`, attacker `10.0.5.5`) and the interface name (e.g. `enp0s3`).

To open the dashboard from your Windows browser too, add *Adapter 2 → Host-only Adapter* to the defender VM
and browse to its host-only IP (`192.168.56.x:5000`).

> No second VM? Use **replay mode** (section 5A) — it streams real CICIDS2017 attack flows through the
> whole pipeline. You can also attack from the Windows host via the host-only network (nmap for Windows).

Optional but nice for the demo: install a real web server on the defender so DoS/web attacks hit a real service:
`sudo apt install -y apache2`

---

## 3. Installation (defender VM)

```bash
cd ~/NDACS                      # wherever you extracted the project
bash deploy/setup_ubuntu.sh     # apt packages + venv + pip requirements (+ optional MySQL)
cp .env.example .env            # then edit passwords / options
```

Manual alternative:
```bash
sudo apt install -y python3-venv python3-pip tcpdump libpcap-dev iptables
python3 -m venv venv && venv/bin/pip install -r requirements.txt
```

Open the folder in **VS Code** (`code .`), choose the interpreter `venv/bin/python` — the Run & Debug
panel already has launch entries for dataset preparation, training and the replay demo.

**MySQL (as in the design):** `sudo apt install mysql-server && sudo mysql < deploy/mysql_setup.sql`, then put
`NDACS_DB_URL=mysql+pymysql://ndacs:ndacs123@localhost/ndacs` in `.env`.
If MySQL is not reachable the app automatically falls back to SQLite (`ndacs.db`) — the dashboard shows which one is in use.

---

## 4. Dataset & training

### 4.1 Get CICIDS2017
Download **MachineLearningCSV.zip** (the `MachineLearningCVE` folder, 8 CSV files, ~840 MB) from
<https://www.unb.ca/cic/datasets/ids-2017.html> (free registration form), or the same files from Kaggle
(search “CIC-IDS2017 MachineLearningCVE”). Extract **the 8 CSV files** into `data/raw/`.

### 4.2 Pre-process
```bash
venv/bin/python scripts/prepare_dataset.py
```
Cleans NaN/Infinity and duplicates, groups the 15 labels into 8 families
(BENIGN, DoS, DDoS, PortScan, BruteForce, WebAttack, Bot, Infiltration*), undersamples big classes
(`--benign-cap 250000 --attack-cap 60000`) and makes a stratified 70/15/15 split.
*Infiltration has only 36 rows and is dropped by `--min-class 500`.
Low on RAM (< 4 GB)? use `--benign-cap 120000 --attack-cap 30000`.

### 4.3 Train & evaluate
```bash
venv/bin/python scripts/train.py            # ~10–30 min on a VM CPU
```
Saves the model to `models/` and presentation-ready results to `reports/`:
`confusion_matrix.png`, `training_curves.png`, `model_comparison.png` (CNN-LSTM vs Random Forest),
`shap_global.png` (most influential features), `classification_report.txt`, `metrics.json`.
All of these also appear on the dashboard’s **AI Model** page.

Retrain later with the intelligence collected by the honeypot/detector:
`venv/bin/python scripts/train.py --extra data/threat_intel.csv`

### 4.4 Quick pipeline test without the dataset (2 minutes)
```bash
venv/bin/python scripts/make_synthetic_dataset.py   # simulated flows -> data/raw/SYNTHETIC-demo.csv
venv/bin/python scripts/prepare_dataset.py --min-class 100
venv/bin/python scripts/train.py --epochs 10
```
Synthetic data is only for checking the installation — its scores are meaningless (the dashboard shows a
warning banner). **Delete `data/raw/SYNTHETIC-demo.csv` before preparing the real CICIDS2017 data.**

---

## 5. Running NDACS

### A. Replay / demo mode (no root, no attacker VM needed)
```bash
venv/bin/python run.py replay            # --rate 15 flows/s, --attack-ratio 0.35
```
Streams real CICIDS2017 test-set flows (benign traffic with attack “campaigns” from attacker IPs
`203.0.113.x`) through the full pipeline: CNN-LSTM → SHAP → simulated response → dashboard.
Firewall actions are recorded as *simulated* (the IPs are fictitious).

### B. Live mode (real traffic, needs root)
```bash
sudo venv/bin/python run.py live --iface enp0s3                      # detect + alert (dry-run response)
sudo venv/bin/python run.py live --iface enp0s3 --response block     # auto-block attackers
sudo venv/bin/python run.py live --iface enp0s3 --response redirect  # scanners/brute-forcers -> honeypot
```
Open **http://<defender-ip>:5000** — default login `admin` / `ndacs@123` (change it in `.env`).
`Ctrl+C` stops everything and removes all NDACS firewall rules.

Check the firewall rules NDACS created: `sudo iptables -L NDACS -n -v` and `sudo iptables -t nat -L NDACS_NAT -n -v`.

### C. Dashboard only (browse stored results)
`venv/bin/python run.py dashboard`

### Honeypot services (started automatically)
| Service | Port | Records |
|---|---|---|
| FTP (vsFTPd look-alike) | 2121 | usernames/passwords tried |
| Telnet (Ubuntu login) | 2323 | usernames/passwords tried |
| SSH banner (OpenSSH) | 2222 | client software versions (use Cowrie for full SSH) |
| HTTP fake router admin | 8081 | requests, login attempts, SQLi/XSS/traversal payloads |

In **redirect** mode an attacker’s connections to ports 22/21/23/80 are silently redirected to these decoys and
everything else from that IP is dropped. Legitimate users never touch the honeypot, so any contact is a high-quality signal.

---

## 6. Attack demonstration (from the Kali VM)

Copy `scripts/simulate_attacks.sh` to the attacker VM and run it **against your own defender VM only**:
```bash
bash simulate_attacks.sh 10.0.5.4 scan          # nmap SYN scan        -> PortScan (behaviour + CNN-LSTM)
bash simulate_attacks.sh 10.0.5.4 bruteforce    # hydra on FTP honeypot -> BruteForce + captured credentials
bash simulate_attacks.sh 10.0.5.4 web           # SQLi / XSS payloads  -> honeypot web_attack events
bash simulate_attacks.sh 10.0.5.4 synflood      # hping3 10 s          -> SYN-Flood, IP blocked
bash simulate_attacks.sh 10.0.5.4 all
```
With `--response block`, try `ping 10.0.5.4` from the attacker after the scan — it stops answering.
Blocks expire automatically after `BLOCK_DURATION_MIN` (30 min) or can be released on the **Automated Response** page.

### Suggested presentation flow (≈ 8 min)
1. **AI Model page** — accuracy, per-class F1, confusion matrix, CNN-LSTM vs Random Forest, global SHAP chart.
2. Start `sudo venv/bin/python run.py live --iface enp0s3 --response redirect`; show **Live Traffic** classifying normal browsing.
3. From Kali run `scan` → alert appears; open it to show the **Explainable AI** reasoning; show the IP on **Automated Response** and the iptables rules in a terminal.
4. Run `bruteforce` and `web` → **Honeypot** page fills with the credentials and payloads the “attacker” used.
5. Run `synflood` → blocked automatically; the Overview timeline shows the spike.
6. Backup if anything misbehaves: `venv/bin/python run.py replay`.

---

## 7. Configuration

All settings are in `config.py`; override them in `.env` (`NDACS_<NAME>=value`). Important ones:

| Setting | Default | Meaning |
|---|---|---|
| `RESPONSE_MODE` | `dry-run` | `dry-run` / `block` / `redirect` |
| `ALERT_THRESHOLD` / `BLOCK_THRESHOLD` | 0.70 / 0.90 | model confidence needed to alert / to act |
| `WHITELIST` | 127.0.0.1, VirtualBox NAT gateway | never blocked (add your host PC, gateway) |
| `BLOCK_DURATION_MIN` | 30 | auto-release time |
| `EXPLAINER` | `shap` | `shap`, `lime` or `occlusion` (fastest) |
| `PORTSCAN_PORTS`, `SYNFLOOD_SYNS`, `BRUTEFORCE_CONNS` | 25 / 300 / 15 | behaviour rule thresholds |
| `ACTION_POLICY` | see file | what to do per attack type |

The defender’s own IPs are always whitelisted, and the dashboard port is never blocked, so you cannot lock yourself out.

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `Illegal instruction (core dumped)` when importing TensorFlow | The VM CPU lacks AVX. On Windows: disable *Core isolation → Memory integrity*, run `bcdedit /set hypervisorlaunchtype off` (admin PowerShell), reboot. Check in the VM: `grep -o avx /proc/cpuinfo \| head -1` |
| `Kernel BPF filter unavailable` warning | `sudo apt install tcpdump libpcap-dev` (NDACS still works, filtering in Python) |
| No traffic in Live Traffic | wrong interface — check `ip a` and pass `--iface`; in VirtualBox set *Promiscuous Mode: Allow All* on the adapter if monitoring other VMs |
| `Live capture needs root` | run with `sudo venv/bin/python run.py live ...` (put settings in `.env`, sudo drops exported variables) |
| Dashboard not reachable from Windows | use the host-only adapter IP; `sudo ufw allow 5000/tcp` if ufw is enabled |
| `Could not connect to mysql` | NDACS falls back to SQLite automatically; check `sudo systemctl status mysql` and the URL in `.env` |
| Training killed / out of memory | give the VM ≥ 4 GB RAM, or lower `--benign-cap/--attack-cap` in `prepare_dataset.py` |
| Port already in use (2121/2222/…) | another honeypot instance is running; `sudo ss -ltnp` |

---

## 9. Project structure

```
NDACS/
├── run.py                      entry point (live | replay | dashboard)
├── config.py                   all settings (+ .env overrides)
├── requirements.txt
├── ndacs/
│   ├── features.py             40 shared features, label mapping, transform
│   ├── flowmeter.py            Scapy capture + bidirectional flow feature extraction
│   ├── model.py                CNN-LSTM architecture + Detector (inference)
│   ├── explainer.py            SHAP / LIME / occlusion explanations
│   ├── behaviour.py            port-scan / SYN-flood / brute-force rules
│   ├── honeypot.py             FTP / Telnet / SSH / HTTP decoys + Cowrie log import
│   ├── responder.py            iptables block / redirect / expiry / cleanup
│   ├── engine.py               pipeline orchestration, threat intelligence, replay
│   ├── db.py                   SQLAlchemy models (MySQL / SQLite)
│   └── dashboard.py            Flask REST API + login
├── scripts/
│   ├── prepare_dataset.py      CICIDS2017 pre-processing
│   ├── train.py                training, evaluation, charts, baseline, global SHAP
│   ├── make_synthetic_dataset.py  installation test data
│   └── simulate_attacks.sh     attacker-VM script (nmap / hydra / hping3 / curl)
├── web/                        dashboard UI (templates, CSS, JS, Chart.js)
├── deploy/                     setup_ubuntu.sh, mysql_setup.sql, cowrie-docker-compose.yml
├── data/raw/                   ← put CICIDS2017 CSVs here
├── models/  reports/  logs/    generated
```

## 10. Security & ethics notes
* Run attacks only inside your isolated VirtualBox lab network.
* The honeypot is low-interaction: it never executes attacker input, limits connection count, line length and
  time; Cowrie (optional) runs inside a capability-dropped container.
* Dashboard is password protected; state-changing API calls require a CSRF token; all attacker-supplied text is
  HTML-escaped in the UI.
* Change the default dashboard password and `SECRET_KEY` in `.env`.
