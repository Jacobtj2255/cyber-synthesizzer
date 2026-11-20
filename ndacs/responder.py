"""
Automated threat response using Linux iptables.

Modes
  dry-run   : decide and log the action, do not touch the firewall (safe default)
  block     : DROP all traffic from the attacker IP
  redirect  : send the attacker's SSH/FTP/Telnet/HTTP connections to the
              honeypot and DROP everything else from that IP
  simulated : used by replay/demo mode (fake IPs) - recorded in DB only

All rules live in dedicated chains (NDACS in filter, NDACS_NAT in nat) so they
are easy to inspect (sudo iptables -L NDACS -n) and are removed on shutdown.
The dashboard port is always exempt so you can never lock yourself out of it.
"""
import ipaddress
import logging
import os
import shutil
import subprocess
import threading
from datetime import datetime, timedelta

import config
from ndacs import db

log = logging.getLogger("ndacs.response")

CHAIN, NAT_CHAIN = "NDACS", "NDACS_NAT"


def local_addresses():
    addrs = {"127.0.0.1"}
    try:
        from scapy.all import get_if_list, get_if_addr
        for i in get_if_list():
            a = get_if_addr(i)
            if a and a != "0.0.0.0":
                addrs.add(a)
    except Exception:
        pass
    return addrs


class Responder:
    def __init__(self, mode=None):
        self.mode = mode or config.RESPONSE_MODE
        self.whitelist = set(config.WHITELIST) | local_addresses()
        self.lock = threading.Lock()
        self.firewall_ready = False
        self._stop = threading.Event()
        if self.mode in ("block", "redirect"):
            self._setup_firewall()

    # ------------------------------------------------------------ firewall
    def _ipt(self, *args, check=True):
        cmd = ["iptables", "-w", *map(str, args)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
        return r

    def _setup_firewall(self):
        if os.geteuid() != 0 or not shutil.which("iptables"):
            log.warning("Response mode '%s' needs root + iptables. Falling back to dry-run. "
                        "Start with: sudo venv/bin/python run.py ...", self.mode)
            self.mode = "dry-run"
            return
        try:
            for table, chain, parent in (("filter", CHAIN, "INPUT"), ("nat", NAT_CHAIN, "PREROUTING")):
                self._ipt("-t", table, "-N", chain, check=False)          # create (ok if exists)
                self._ipt("-t", table, "-F", chain)                       # start clean
                if self._ipt("-t", table, "-C", parent, "-j", chain, check=False).returncode != 0:
                    self._ipt("-t", table, "-I", parent, "1", "-j", chain)
            # never block the dashboard or already-established admin sessions on it
            self._ipt("-A", CHAIN, "-p", "tcp", "--dport", config.DASHBOARD_PORT, "-j", "RETURN")
            self.firewall_ready = True
            log.info("iptables chains ready (mode=%s)", self.mode)
        except Exception as e:
            log.error("iptables setup failed (%s) - falling back to dry-run", e)
            self.mode = "dry-run"

    def _apply_block(self, ip):
        self._ipt("-A", CHAIN, "-s", ip, "-j", "DROP")

    def _apply_redirect(self, ip):
        hp_ports = sorted(set(config.REDIRECT_MAP.values()))
        for real, hp in config.REDIRECT_MAP.items():
            self._ipt("-t", "nat", "-A", NAT_CHAIN, "-s", ip, "-p", "tcp", "--dport", real,
                      "-j", "REDIRECT", "--to-ports", hp)
        self._ipt("-A", CHAIN, "-s", ip, "-p", "tcp", "-m", "multiport", "--dports",
                  ",".join(map(str, hp_ports)), "-j", "ACCEPT")
        self._ipt("-A", CHAIN, "-s", ip, "-j", "DROP")

    def _remove_rules(self, ip):
        for table, chain in (("filter", CHAIN), ("nat", NAT_CHAIN)):
            r = self._ipt("-t", table, "-S", chain, check=False)
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts[:2] == ["-A", chain] and f"{ip}/32" in parts:
                    self._ipt("-t", table, "-D", *parts[1:], check=False)

    # ------------------------------------------------------------ public API
    def act(self, ip, label, action, minutes=None):
        """Apply action ('block' | 'redirect') to ip. Returns the action actually taken."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return "invalid-ip"
        if ip in self.whitelist:
            return "whitelisted"
        if action not in ("block", "redirect"):
            return action
        minutes = minutes or config.BLOCK_DURATION_MIN
        with self.lock, db.session_scope() as s:
            if s.query(db.BlockedIP).filter(db.BlockedIP.ip == ip, db.BlockedIP.active.is_(True)).first():
                return "already-blocked"
            if self.mode == "redirect" and action == "redirect":
                effective = "redirect"
            elif self.mode == "block" and action == "redirect":
                effective = "block"            # honeypot redirect disabled -> plain block
            else:
                effective = action
            if self.mode in ("dry-run", "simulated"):
                record_mode, taken = self.mode, f"{effective} ({self.mode})"
            else:
                try:
                    (self._apply_redirect if effective == "redirect" else self._apply_block)(ip)
                    record_mode, taken = effective, "redirected" if effective == "redirect" else "blocked"
                except Exception as e:
                    log.error("firewall action failed for %s: %s", ip, e)
                    return "action-failed"
            s.add(db.BlockedIP(ip=ip, mode=record_mode, reason=label,
                               expires=datetime.now() + timedelta(minutes=minutes)))
        log.warning("RESPONSE: %s %s (%s)", taken.upper(), ip, label)
        return taken

    def unblock(self, ip):
        with self.lock:
            if self.firewall_ready:
                self._remove_rules(ip)
            with db.session_scope() as s:
                n = 0
                for row in s.query(db.BlockedIP).filter(db.BlockedIP.ip == ip, db.BlockedIP.active.is_(True)):
                    row.active = False
                    n += 1
        log.info("Unblocked %s", ip)
        return n

    def expiry_loop(self):
        while not self._stop.wait(15):
            with db.session_scope() as s:
                ips = [r.ip for r in s.query(db.BlockedIP).filter(
                    db.BlockedIP.active.is_(True), db.BlockedIP.expires < datetime.now())]
            for ip in ips:
                self.unblock(ip)

    def start(self):
        threading.Thread(target=self.expiry_loop, daemon=True, name="block-expiry").start()

    def shutdown(self):
        """Remove all NDACS firewall rules so the VM is left in a clean state."""
        self._stop.set()
        if self.firewall_ready:
            for table, chain, parent in (("filter", CHAIN, "INPUT"), ("nat", NAT_CHAIN, "PREROUTING")):
                self._ipt("-t", table, "-D", parent, "-j", chain, check=False)
                self._ipt("-t", table, "-F", chain, check=False)
                self._ipt("-t", table, "-X", chain, check=False)
            log.info("iptables rules removed")
        with db.session_scope() as s:
            for row in s.query(db.BlockedIP).filter(db.BlockedIP.active.is_(True)):
                row.active = False
