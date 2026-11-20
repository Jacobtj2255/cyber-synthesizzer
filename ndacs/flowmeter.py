"""
Real-time traffic capture + flow feature extraction (CICFlowMeter-compatible
subset) using Scapy.

Packets are grouped into bidirectional flows (5-tuple). When a flow finishes
(FIN from both sides, RST, idle timeout or active timeout) its 40 features are
computed and handed to the detection engine.
"""
import logging
import math
import threading
import time

from ndacs.features import FEATURES

log = logging.getLogger("ndacs.capture")

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


class RunningStat:
    """Streaming count / sum / min / max / sample-std (Welford) - O(1) memory."""
    __slots__ = ("n", "total", "mn", "mx", "mean", "m2")

    def __init__(self):
        self.n, self.total, self.mn, self.mx, self.mean, self.m2 = 0, 0.0, 0.0, 0.0, 0.0, 0.0

    def add(self, x):
        self.n += 1
        self.total += x
        if self.n == 1:
            self.mn = self.mx = x
        else:
            self.mn = min(self.mn, x)
            self.mx = max(self.mx, x)
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self):
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0

    def stats(self):
        return (self.mx, self.mn, self.mean, self.std) if self.n else (0.0, 0.0, 0.0, 0.0)


class Flow:
    __slots__ = ("src", "dst", "sport", "dport", "proto", "start", "last",
                 "fwd", "bwd", "all", "iat", "fwd_iat", "bwd_iat",
                 "last_fwd", "last_bwd", "flags", "init_win_fwd", "init_win_bwd",
                 "act_data_fwd", "fin_fwd", "fin_bwd", "rst", "segment_start")

    def __init__(self, ts, src, dst, sport, dport, proto):
        self.src, self.dst, self.sport, self.dport, self.proto = src, dst, sport, dport, proto
        self.start = self.last = self.segment_start = ts
        self.fwd, self.bwd, self.all = RunningStat(), RunningStat(), RunningStat()
        self.iat, self.fwd_iat, self.bwd_iat = RunningStat(), RunningStat(), RunningStat()
        self.last_fwd = self.last_bwd = None
        self.flags = {FIN: 0, SYN: 0, RST: 0, PSH: 0, ACK: 0, URG: 0}
        self.init_win_fwd = self.init_win_bwd = -1
        self.act_data_fwd = 0
        self.fin_fwd = self.fin_bwd = self.rst = False

    def add(self, ts, is_fwd, plen, flags=0, win=None):
        if self.all.n:
            self.iat.add((ts - self.last) * 1e6)
        self.last = ts
        self.all.add(plen)
        if is_fwd:
            if self.last_fwd is not None:
                self.fwd_iat.add((ts - self.last_fwd) * 1e6)
            self.last_fwd = ts
            self.fwd.add(plen)
            if plen >= 1:
                self.act_data_fwd += 1
            if win is not None and self.init_win_fwd == -1:
                self.init_win_fwd = win
            if flags & FIN:
                self.fin_fwd = True
        else:
            if self.last_bwd is not None:
                self.bwd_iat.add((ts - self.last_bwd) * 1e6)
            self.last_bwd = ts
            self.bwd.add(plen)
            if win is not None and self.init_win_bwd == -1:
                self.init_win_bwd = win
            if flags & FIN:
                self.fin_bwd = True
        for f in self.flags:
            if flags & f:
                self.flags[f] += 1
        if flags & RST:
            self.rst = True

    @property
    def finished(self):
        return self.rst or (self.fin_fwd and self.fin_bwd)

    def features(self):
        dur_us = (self.last - self.start) * 1e6
        dur_s = dur_us / 1e6
        n_f, n_b = self.fwd.n, self.bwd.n
        n = n_f + n_b
        tot_bytes = self.fwd.total + self.bwd.total
        fmax, fmin, fmean, fstd = self.fwd.stats()
        bmax, bmin, bmean, bstd = self.bwd.stats()
        amax, amin, amean, astd = self.all.stats()
        imax, imin, imean, istd = self.iat.stats()
        rate = (lambda c: c / dur_s if dur_s > 0 else 0.0)
        v = {
            "Destination Port": self.dport,
            "Flow Duration": dur_us,
            "Total Fwd Packets": n_f,
            "Total Backward Packets": n_b,
            "Total Length of Fwd Packets": self.fwd.total,
            "Total Length of Bwd Packets": self.bwd.total,
            "Fwd Packet Length Max": fmax, "Fwd Packet Length Min": fmin,
            "Fwd Packet Length Mean": fmean, "Fwd Packet Length Std": fstd,
            "Bwd Packet Length Max": bmax, "Bwd Packet Length Min": bmin,
            "Bwd Packet Length Mean": bmean, "Bwd Packet Length Std": bstd,
            "Flow Bytes/s": rate(tot_bytes),
            "Flow Packets/s": rate(n),
            "Flow IAT Mean": imean, "Flow IAT Std": istd,
            "Flow IAT Max": imax, "Flow IAT Min": imin,
            "Fwd IAT Total": self.fwd_iat.total, "Fwd IAT Mean": self.fwd_iat.mean,
            "Bwd IAT Total": self.bwd_iat.total, "Bwd IAT Mean": self.bwd_iat.mean,
            "Fwd Packets/s": rate(n_f), "Bwd Packets/s": rate(n_b),
            "Min Packet Length": amin, "Max Packet Length": amax,
            "Packet Length Mean": amean, "Packet Length Std": astd,
            "FIN Flag Count": self.flags[FIN], "SYN Flag Count": self.flags[SYN],
            "RST Flag Count": self.flags[RST], "PSH Flag Count": self.flags[PSH],
            "ACK Flag Count": self.flags[ACK],
            "Down/Up Ratio": (n_b // n_f) if n_f else 0,
            "Average Packet Size": tot_bytes / n if n else 0.0,
            "Init_Win_bytes_forward": self.init_win_fwd,
            "Init_Win_bytes_backward": self.init_win_bwd,
            "act_data_pkt_fwd": self.act_data_fwd,
        }
        return [float(v[f]) for f in FEATURES]

    def meta(self):
        return {"src_ip": self.src, "dst_ip": self.dst, "src_port": self.sport,
                "dst_port": self.dport, "protocol": self.proto}


class FlowMeter:
    """Groups packets into flows and emits finished flows via on_flow(meta, features)."""

    def __init__(self, on_flow, idle_timeout=5.0, active_timeout=30.0, max_flows=100000):
        self.on_flow = on_flow
        self.idle, self.active, self.max_flows = idle_timeout, active_timeout, max_flows
        self.flows = {}
        self.closed = {}             # key -> ts of flows closed by FIN/RST (absorbs late duplicates)
        self.lock = threading.Lock()
        self.packet_listeners = []   # behaviour engine hooks: fn(ts, src, dst, sport, dport, proto, flags)
        self.packets = 0
        self.ignore_ports = set()    # e.g. the dashboard port (used when no BPF filter is available)

    def process(self, ts, src, dst, sport, dport, proto, plen, flags=0, win=None):
        self.packets += 1
        for fn in self.packet_listeners:
            try:
                fn(ts, src, dst, sport, dport, proto, flags)
            except Exception:  # never let a listener kill capture
                log.exception("packet listener failed")
        a, b = (src, sport), (dst, dport)
        key = (proto,) + ((a, b) if a <= b else (b, a))
        done = None
        with self.lock:
            flow = self.flows.get(key)
            if flow is None and ts - self.closed.get(key, -1e9) < 2.0:
                return               # straggler of a connection that was just reset/closed
            if flow is not None and ts - flow.last > self.idle:   # stale -> close it, start new
                self._emit(self.flows.pop(key))
                flow = None
            if flow is None:
                if len(self.flows) >= self.max_flows:
                    oldest = min(self.flows, key=lambda k: self.flows[k].last)
                    self._emit(self.flows.pop(oldest))
                flow = Flow(ts, src, dst, sport, dport, proto)
                self.flows[key] = flow
            flow.add(ts, src == flow.src and sport == flow.sport, plen, flags, win)
            if flow.finished:
                done = self.flows.pop(key)
                self.closed[key] = ts
            elif ts - flow.start > self.active:
                done = self.flows.pop(key)
        if done is not None:
            self._emit(done)

    def sweep(self, now=None):
        now = now or time.time()
        with self.lock:
            expired = [k for k, f in self.flows.items() if now - f.last > self.idle]
            flows = [self.flows.pop(k) for k in expired]
            self.closed = {k: t for k, t in self.closed.items() if now - t < 2.0}
        for f in flows:
            self._emit(f)

    def flush(self):
        with self.lock:
            flows, self.flows = list(self.flows.values()), {}
        for f in flows:
            self._emit(f)

    def _emit(self, flow):
        try:
            self.on_flow(flow.meta(), flow.features())
        except Exception:
            log.exception("on_flow callback failed")

    # ------------------------------------------------------------ scapy glue
    def process_scapy(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        if IP not in pkt:
            return
        ip = pkt[IP]
        ts = float(pkt.time)
        ip_payload = max(int(ip.len) - int(ip.ihl) * 4, 0)
        if TCP in pkt:
            t = pkt[TCP]
            if self.ignore_ports and (t.sport in self.ignore_ports or t.dport in self.ignore_ports):
                return
            plen = max(ip_payload - int(t.dataofs) * 4, 0)
            self.process(ts, ip.src, ip.dst, int(t.sport), int(t.dport), "TCP",
                         plen, int(t.flags), int(t.window))
        elif UDP in pkt:
            u = pkt[UDP]
            self.process(ts, ip.src, ip.dst, int(u.sport), int(u.dport), "UDP",
                         max(int(u.len) - 8, 0))
        elif ICMP in pkt:
            self.process(ts, ip.src, ip.dst, 0, 0, "ICMP", max(ip_payload - 8, 0))


class LiveCapture:
    """Runs a Scapy AsyncSniffer + a sweeper thread that expires idle flows."""

    def __init__(self, meter: FlowMeter, iface=None, bpf=None):
        self.meter, self.iface, self.bpf = meter, iface, bpf
        self.sniffer = None
        self._stop = threading.Event()

    def start(self):
        from scapy.all import AsyncSniffer
        if self.bpf:
            try:
                from scapy.arch.common import compile_filter
                compile_filter(self.bpf, iface=self.iface)
            except Exception as e:
                log.warning("Kernel BPF filter unavailable (%s) - filtering in Python instead. "
                            "Install tcpdump/libpcap for better performance: sudo apt install tcpdump", e)
                self.bpf = None
        self.sniffer = AsyncSniffer(iface=self.iface, filter=self.bpf, store=False,
                                    prn=self.meter.process_scapy)
        self.sniffer.start()
        time.sleep(0.5)
        if getattr(self.sniffer, "exception", None):
            raise RuntimeError(f"Packet capture failed: {self.sniffer.exception}")
        threading.Thread(target=self._sweeper, daemon=True, name="flow-sweeper").start()
        log.info("Live capture started on %s (filter: %s)", self.iface or "default iface", self.bpf)

    def _sweeper(self):
        while not self._stop.wait(1.0):
            self.meter.sweep()

    def stop(self):
        self._stop.set()
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
        self.meter.flush()
