#!/usr/bin/env python3
"""
NDACS - Network Defense Automated Cyber Synthesizer
====================================================

  sudo venv/bin/python run.py live   --iface enp0s3            # real-time monitoring (needs root)
  sudo venv/bin/python run.py live   --iface enp0s3 --response block
  sudo venv/bin/python run.py live   --iface enp0s3 --response redirect
       venv/bin/python run.py replay                            # demo: replays CICIDS2017 test flows
       venv/bin/python run.py dashboard                         # view stored results only

Then open http://<VM-IP>:5000  (default login admin / ndacs@123 - change in config.py)
"""
import argparse
import logging
import os
import signal
import sys

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import config


def setup_logging(verbose=False):
    fmt = "%(asctime)s %(levelname)-7s %(name)-16s %(message)s"
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format=fmt, datefmt="%H:%M:%S",
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler(config.LOG_DIR / "ndacs.log")])
    for noisy in ("werkzeug", "scapy.runtime", "shap", "absl", "tensorflow"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def main():
    ap = argparse.ArgumentParser(description="Network Defense Automated Cyber Synthesizer")
    ap.add_argument("mode", choices=["live", "replay", "dashboard"])
    ap.add_argument("--iface", help="network interface to monitor, e.g. enp0s3 (see: ip a)")
    ap.add_argument("--response", choices=["dry-run", "block", "redirect"], help="override RESPONSE_MODE")
    ap.add_argument("--no-honeypot", action="store_true")
    ap.add_argument("--replay-file", help="CSV for replay mode (default data/processed/test.csv)")
    ap.add_argument("--rate", type=float, default=15.0, help="replay: flows per second")
    ap.add_argument("--attack-ratio", type=float, default=0.35, help="replay: how often attack campaigns start")
    ap.add_argument("--port", type=int, default=config.DASHBOARD_PORT)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    setup_logging(args.verbose)
    log = logging.getLogger("ndacs")

    from ndacs import db
    from ndacs.dashboard import create_app

    engine = None
    if args.mode == "dashboard":
        db.init_db()
    else:
        from ndacs.engine import Engine
        if args.mode == "live" and os.geteuid() != 0:
            sys.exit("Live capture needs root privileges:  sudo venv/bin/python run.py live --iface <iface>")
        engine = Engine(mode=args.mode, response_mode=args.response)
        engine.start()
        if config.HONEYPOT_ENABLED and not args.no_honeypot:
            engine.start_honeypot()
        if args.mode == "live":
            engine.start_live(args.iface)
        else:
            engine.start_replay(args.replay_file, args.rate, args.attack_ratio)

    def shutdown(*_):
        log.info("Shutting down ...")
        if engine:
            engine.stop()
        os._exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    app = create_app(engine)
    log.info("Dashboard: http://%s:%d  (user: %s)", config.DASHBOARD_HOST, args.port, config.DASHBOARD_USER)
    app.run(host=config.DASHBOARD_HOST, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
