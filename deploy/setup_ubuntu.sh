#!/usr/bin/env bash
# One-time setup for the NDACS defender VM (Ubuntu 22.04 / 24.04).
# Run from the project folder:   bash deploy/setup_ubuntu.sh
set -e
cd "$(dirname "$0")/.."

echo "==> Checking CPU support for TensorFlow (AVX)"
if ! grep -qw avx /proc/cpuinfo; then
  echo "!!  Your VM CPU does not expose AVX - TensorFlow will crash with 'Illegal instruction'."
  echo "!!  Fix on the Windows host: turn OFF Hyper-V / 'Memory integrity' (Core isolation),"
  echo "!!  reboot, then in PowerShell (admin):  bcdedit /set hypervisorlaunchtype off"
  echo "!!  See README -> Troubleshooting. Continuing with the rest of the setup..."
fi

echo "==> Installing system packages"
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-dev build-essential \
                    tcpdump libpcap-dev iptables net-tools curl unzip

echo "==> Creating Python virtual environment (venv/)"
python3 -m venv venv
venv/bin/pip install --upgrade pip wheel setuptools
venv/bin/pip install -r requirements.txt || {
  echo "Retrying without LIME (optional)"; grep -v '^lime' requirements.txt > /tmp/req.txt
  venv/bin/pip install -r /tmp/req.txt; }

echo "==> Verifying imports"
venv/bin/python - <<'EOF'
import tensorflow as tf, sklearn, shap, scapy, flask, sqlalchemy
print("TensorFlow", tf.__version__, "| scikit-learn", sklearn.__version__, "| SHAP", shap.__version__)
EOF

read -p "Install MySQL server too? (y/N) " yn
if [[ "$yn" == [yY]* ]]; then
  sudo apt install -y mysql-server
  sudo systemctl enable --now mysql
  sudo mysql < deploy/mysql_setup.sql
  echo "MySQL ready. Use it with:"
  echo "  export NDACS_DB_URL='mysql+pymysql://ndacs:ndacs123@localhost/ndacs'"
fi

echo
echo "Setup complete. Next steps:"
echo "  1. Put CICIDS2017 CSVs in data/raw/   (see README)"
echo "  2. venv/bin/python scripts/prepare_dataset.py"
echo "  3. venv/bin/python scripts/train.py"
echo "  4. sudo venv/bin/python run.py live --iface \$(ip route | awk '/default/ {print \$5; exit}')"
