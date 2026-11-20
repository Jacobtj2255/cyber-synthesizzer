"""
Database layer (SQLAlchemy). Works with MySQL (as in the project design) and
falls back to SQLite automatically, so the demo never breaks.
"""
import json
import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import (Boolean, Column, DateTime, Float, Integer, String, Text,
                        create_engine, func, text)
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

import config

log = logging.getLogger("ndacs.db")
Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.now, index=True)
    last_seen = Column(DateTime, default=datetime.now)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(8))
    label = Column(String(32), index=True)
    confidence = Column(Float)
    severity = Column(String(16))
    source = Column(String(16))          # model | signature | honeypot | intel
    action = Column(String(32))          # alert | blocked | redirected | monitor | whitelisted ...
    count = Column(Integer, default=1)   # deduplicated repeats
    explanation = Column(Text)           # JSON (XAI output)
    features = Column(Text)              # JSON (raw flow features)

    def to_dict(self, full=False):
        d = {
            "id": self.id, "ts": _iso(self.ts), "last_seen": _iso(self.last_seen),
            "src_ip": self.src_ip, "dst_ip": self.dst_ip, "src_port": self.src_port,
            "dst_port": self.dst_port, "protocol": self.protocol, "label": self.label,
            "confidence": round(self.confidence or 0, 4), "severity": self.severity,
            "source": self.source, "action": self.action, "count": self.count,
            "explained": bool(self.explanation),
        }
        if full:
            d["explanation"] = json.loads(self.explanation) if self.explanation else None
            d["features"] = json.loads(self.features) if self.features else None
        return d


class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), index=True)
    mode = Column(String(16))            # block | redirect | simulated
    reason = Column(String(128))
    ts = Column(DateTime, default=datetime.now)
    expires = Column(DateTime)
    active = Column(Boolean, default=True, index=True)

    def to_dict(self):
        return {"id": self.id, "ip": self.ip, "mode": self.mode, "reason": self.reason,
                "ts": _iso(self.ts), "expires": _iso(self.expires), "active": self.active}


class HoneypotEvent(Base):
    __tablename__ = "honeypot_events"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.now, index=True)
    src_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    service = Column(String(16))
    event = Column(String(32))           # connect | login_attempt | command | request
    username = Column(String(128))
    password = Column(String(128))
    data = Column(Text)

    def to_dict(self):
        return {"id": self.id, "ts": _iso(self.ts), "src_ip": self.src_ip,
                "src_port": self.src_port, "service": self.service, "event": self.event,
                "username": self.username, "password": self.password, "data": self.data}


class TrafficStat(Base):
    """Per-minute traffic counters for the dashboard timeline."""
    __tablename__ = "traffic_stats"
    id = Column(Integer, primary_key=True)
    minute = Column(DateTime, unique=True, index=True)
    flows = Column(Integer, default=0)
    benign = Column(Integer, default=0)
    malicious = Column(Integer, default=0)


def _iso(dt):
    return dt.isoformat(timespec="seconds") if dt else None


# ------------------------------------------------------------------ engine
_engine = None
Session = None
_lock = threading.Lock()


def init_db(url=None):
    global _engine, Session
    url = url or config.DB_URL
    try:
        _engine = create_engine(url, pool_pre_ping=True, future=True)
        with _engine.connect() as c:
            c.execute(text("SELECT 1"))
        log.info("Database connected: %s", url.split("@")[-1])
    except Exception as e:  # MySQL down / not installed -> SQLite
        fallback = f"sqlite:///{config.BASE_DIR / 'ndacs.db'}"
        log.warning("Could not connect to %s (%s). Falling back to SQLite.", url.split("@")[-1], e)
        _engine = create_engine(fallback, future=True,
                                connect_args={"check_same_thread": False})
    Base.metadata.create_all(_engine)
    Session = scoped_session(sessionmaker(bind=_engine, expire_on_commit=False))
    return _engine


def db_name():
    return _engine.dialect.name if _engine is not None else "none"


class session_scope:
    def __enter__(self):
        self.s = Session()
        return self.s

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self.s.commit()
            else:
                self.s.rollback()
        finally:
            Session.remove()


# ------------------------------------------------------------------ helpers
def record_alert(src_ip, dst_ip, src_port, dst_port, protocol, label, confidence,
                 severity, source, action, features=None):
    """Insert an alert, or bump the counter of a recent identical alert
    (deduplication keeps floods from filling the table). Returns (alert_id, is_new)."""
    since = datetime.now() - timedelta(seconds=config.ALERT_DEDUP_SECONDS)
    with _lock, session_scope() as s:
        existing = (s.query(Alert)
                    .filter(Alert.src_ip == src_ip, Alert.label == label, Alert.last_seen >= since)
                    .order_by(Alert.id.desc()).first())
        if existing:
            existing.count += 1
            existing.last_seen = datetime.now()
            existing.confidence = max(existing.confidence or 0, confidence)
            if existing.action in (None, "alert") and action and action != "alert":
                existing.action = action          # escalate, never downgrade a taken action
            return existing.id, False
        a = Alert(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                  protocol=protocol, label=label, confidence=confidence, severity=severity,
                  source=source, action=action,
                  features=json.dumps(features) if features is not None else None)
        s.add(a)
        s.flush()
        return a.id, True


def set_alert_explanation(alert_id, explanation):
    with _lock, session_scope() as s:
        a = s.get(Alert, alert_id)
        if a:
            a.explanation = json.dumps(explanation)


def set_alert_action(alert_id, action):
    with _lock, session_scope() as s:
        a = s.get(Alert, alert_id)
        if a:
            a.action = action


def add_traffic(benign, malicious):
    minute = datetime.now().replace(second=0, microsecond=0)
    with _lock, session_scope() as s:
        row = s.query(TrafficStat).filter(TrafficStat.minute == minute).first()
        if row is None:
            row = TrafficStat(minute=minute, flows=0, benign=0, malicious=0)
            s.add(row)
        row.flows += benign + malicious
        row.benign += benign
        row.malicious += malicious


def add_honeypot_event(**kw):
    with _lock, session_scope() as s:
        s.add(HoneypotEvent(**kw))


def summary(minutes=30):
    since = datetime.now() - timedelta(minutes=minutes)
    with session_scope() as s:
        total_alerts = s.query(func.count(Alert.id)).scalar() or 0
        attack_events = s.query(func.coalesce(func.sum(Alert.count), 0)).scalar() or 0
        flows = s.query(func.coalesce(func.sum(TrafficStat.flows), 0)).scalar() or 0
        mal = s.query(func.coalesce(func.sum(TrafficStat.malicious), 0)).scalar() or 0
        blocked = s.query(func.count(BlockedIP.id)).filter(BlockedIP.active.is_(True)).scalar() or 0
        hp = s.query(func.count(HoneypotEvent.id)).scalar() or 0
        hp_ips = s.query(func.count(func.distinct(HoneypotEvent.src_ip))).scalar() or 0
        dist = dict(s.query(Alert.label, func.sum(Alert.count)).group_by(Alert.label).all())
        sev = dict(s.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all())
        rows = (s.query(TrafficStat).filter(TrafficStat.minute >= since)
                .order_by(TrafficStat.minute).all())
        timeline = [{"t": r.minute.strftime("%H:%M"), "benign": r.benign,
                     "malicious": r.malicious} for r in rows]
        top_ips = (s.query(Alert.src_ip, func.sum(Alert.count).label("n"))
                   .group_by(Alert.src_ip).order_by(text("n DESC")).limit(5).all())
    return {
        "flows": int(flows), "malicious_flows": int(mal), "alerts": int(total_alerts),
        "attack_events": int(attack_events), "blocked": int(blocked),
        "honeypot_events": int(hp), "honeypot_ips": int(hp_ips),
        "distribution": {k: int(v) for k, v in dist.items()},
        "severity": {k: int(v) for k, v in sev.items() if k},
        "timeline": timeline,
        "top_attackers": [{"ip": ip, "count": int(n)} for ip, n in top_ips],
    }
