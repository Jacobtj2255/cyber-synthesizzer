"""
Signature & behaviour-based detection (runs per packet, alongside the AI model).

Catches attacks quickly - even before a flow has finished - and also works when
no trained model is available:
  * Port scan   : one source touches many different destination ports
  * SYN flood   : one source sends a burst of SYN packets
  * Brute force : many new connections to login services (SSH/FTP/Telnet/RDP)
"""
import time
from collections import defaultdict, deque

import config
from ndacs.flowmeter import ACK, SYN


class BehaviourEngine:
    def __init__(self, on_detection, own_ips=()):
        self.on_detection = on_detection   # fn(src, dst, dport, label, text, facts)
        self.own = set(own_ips)
        self.syns = defaultdict(deque)     # src -> deque[(ts, dport)]
        self.auth = defaultdict(deque)     # src -> deque[ts]
        self.cooldown = {}                 # (src, label) -> ts
        self._n = 0

    def _fire(self, src, dst, dport, label, text, facts, now):
        if now - self.cooldown.get((src, label), 0) < 30:
            return
        self.cooldown[(src, label)] = now
        self.on_detection(src, dst, dport, label, text, facts)

    def on_packet(self, ts, src, dst, sport, dport, proto, flags):
        if proto != "TCP" or not (flags & SYN) or (flags & ACK) or src in self.own:
            return
        now = ts
        q = self.syns[src]
        q.append((now, dport))
        horizon = max(config.PORTSCAN_WINDOW, config.SYNFLOOD_WINDOW)
        while q and now - q[0][0] > horizon:
            q.popleft()

        recent_ports = {p for t, p in q if now - t <= config.PORTSCAN_WINDOW}
        if len(recent_ports) >= config.PORTSCAN_PORTS:
            self._fire(src, dst, dport, "PortScan",
                       f"{src} probed {len(recent_ports)} different ports on {dst} within "
                       f"{config.PORTSCAN_WINDOW}s - typical of a port scan (e.g. nmap).",
                       {"distinct ports": len(recent_ports), "window (s)": config.PORTSCAN_WINDOW,
                        "sample ports": ",".join(map(str, sorted(recent_ports)[:10]))}, now)

        syn_count = sum(1 for t, _ in q if now - t <= config.SYNFLOOD_WINDOW)
        if syn_count >= config.SYNFLOOD_SYNS:
            self._fire(src, dst, dport, "SYN-Flood",
                       f"{src} sent {syn_count} connection requests (SYN) in {config.SYNFLOOD_WINDOW}s "
                       f"- a SYN flood denial-of-service pattern.",
                       {"SYN packets": syn_count, "window (s)": config.SYNFLOOD_WINDOW}, now)

        if dport in config.AUTH_PORTS:
            a = self.auth[src]
            a.append(now)
            while a and now - a[0] > config.BRUTEFORCE_WINDOW:
                a.popleft()
            if len(a) >= config.BRUTEFORCE_CONNS:
                self._fire(src, dst, dport, "BruteForce",
                           f"{src} opened {len(a)} connections to login service port {dport} in "
                           f"{config.BRUTEFORCE_WINDOW}s - password brute-force behaviour (e.g. hydra).",
                           {"connections": len(a), "service port": dport,
                            "window (s)": config.BRUTEFORCE_WINDOW}, now)

        self._n += 1
        if self._n % 5000 == 0:      # housekeeping: forget idle sources
            cutoff = time.time() - 120
            for d in (self.syns, self.auth):
                for k in [k for k, v in d.items() if not v or (v[-1][0] if isinstance(v[-1], tuple) else v[-1]) < cutoff]:
                    del d[k]
