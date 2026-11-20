# 🛡️ Cyber Synthesizer – Automated Network Defense System

## 📌 Overview

Cyber Synthesizer is an automated network defense system designed to detect, analyze, and respond to malicious network activities using machine learning and cybersecurity techniques.

The system combines a CNN-LSTM-based intrusion detection model, explainable AI (SHAP), honeypot technology, and automated threat containment to improve network security.

## 🚀 Key Features

- **Intrusion Detection:** Detects benign traffic and multiple categories of network attacks.
- **CNN-LSTM Model:** Uses deep learning for network traffic classification.
- **Explainable AI:** Uses SHAP to understand model predictions.
- **Honeypot Integration:** Deploys decoy services to capture suspicious activities.
- **Threat Containment:** Simulates IP blocking with temporary expiry.
- **Admin Dashboard:** Provides network monitoring, alerts, and attack analysis.
- **Event Logging:** Stores security events using SQLite.

## 🛠️ Technologies Used

| Category | Technology |
|---|---|
| Programming Language | Python |
| Machine Learning | CNN-LSTM |
| Explainable AI | SHAP |
| Dataset | CICIDS2017 |
| Database | SQLite |
| Operating System | Kali Linux |
| Development Environment | Visual Studio Code |
| Security Techniques | Honeypots, Intrusion Detection |

## 🏗️ System Architecture

1. Network traffic collection
2. Data preprocessing
3. CNN-LSTM attack classification
4. SHAP-based prediction explanation
5. Threat alert generation
6. Honeypot monitoring
7. Threat containment and event logging
8. Dashboard visualization

## 📂 Project Structure

```text
Cyber-Synthesizer/
│
├── dataset/
├── models/
├── preprocessing/
├── detection/
├── honeypot/
├── dashboard/
├── database/
├── logs/
├── requirements.txt
├── README.md
└── main.py
```

*Note: Update this structure to match your actual project folders and files.*

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/Jacobtj2255/cyber-synthesizzer.git
```

Navigate to the project:

```bash
cd cyber-synthesizzer
```

Create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## ▶️ Running the Project

Run the main application:

```bash
python3 main.py
```

*Update this command according to your actual application entry point.*

## 📊 Project Status

Under development.

Current development areas include live network traffic capture, real-time monitoring, and improved threat enforcement.

## 👨‍💻 Author

**Jacob Thomas**

GitHub: [Jacobtj2255](https://github.com/Jacobtj2255)

## ⚠️ Disclaimer

This project is developed for educational and authorized cybersecurity research purposes only. Do not use its capabilities against systems or networks without permission.