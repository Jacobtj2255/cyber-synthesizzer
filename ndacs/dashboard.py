"""
Centralised monitoring dashboard - Flask REST API + web UI.
"""
import ipaddress
import json
import secrets
from functools import wraps

from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)
from sqlalchemy import func

import config
from ndacs import db


def create_app(engine=None):
    app = Flask(__name__, template_folder=str(config.BASE_DIR / "web" / "templates"),
                static_folder=str(config.BASE_DIR / "web" / "static"))
    app.secret_key = config.SECRET_KEY
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "login required"}), 401
                return redirect(url_for("login"))
            return fn(*a, **kw)
        return wrapper

    def csrf_ok():
        return request.headers.get("X-CSRF-Token") == session.get("csrf")

    # ------------------------------------------------------------ pages
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            u, p = request.form.get("username", ""), request.form.get("password", "")
            if secrets.compare_digest(u, config.DASHBOARD_USER) and \
                    secrets.compare_digest(p, config.DASHBOARD_PASSWORD):
                session["user"] = u
                session["csrf"] = secrets.token_hex(16)
                return redirect(url_for("index"))
            error = "Invalid username or password"
        return render_template("login.html", error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        return render_template("index.html", csrf=session.get("csrf"), user=session.get("user"))

    @app.route("/reports/<path:name>")
    @login_required
    def reports(name):
        return send_from_directory(config.REPORT_DIR, name)

    # ------------------------------------------------------------ API
    @app.route("/api/summary")
    @login_required
    def api_summary():
        data = db.summary(minutes=int(request.args.get("minutes", 30)))
        data["status"] = engine.status() if engine else {"mode": "dashboard-only"}
        return jsonify(data)

    @app.route("/api/feed")
    @login_required
    def api_feed():
        return jsonify(list(engine.feed)[:80] if engine else [])

    @app.route("/api/alerts")
    @login_required
    def api_alerts():
        limit = min(int(request.args.get("limit", 200)), 1000)
        q = db.Session().query(db.Alert)
        if request.args.get("label"):
            q = q.filter(db.Alert.label == request.args["label"])
        if request.args.get("severity"):
            q = q.filter(db.Alert.severity == request.args["severity"])
        rows = [a.to_dict() for a in q.order_by(db.Alert.id.desc()).limit(limit)]
        db.Session.remove()
        return jsonify(rows)

    @app.route("/api/alerts/<int:aid>")
    @login_required
    def api_alert(aid):
        a = db.Session().get(db.Alert, aid)
        d = a.to_dict(full=True) if a else None
        db.Session.remove()
        return jsonify(d) if d else (jsonify({"error": "not found"}), 404)

    @app.route("/api/blocked")
    @login_required
    def api_blocked():
        s = db.Session()
        rows = [b.to_dict() for b in s.query(db.BlockedIP).order_by(db.BlockedIP.id.desc()).limit(200)]
        db.Session.remove()
        return jsonify(rows)

    @app.route("/api/block", methods=["POST"])
    @login_required
    def api_block():
        if not csrf_ok():
            abort(403)
        body = request.get_json(force=True)
        ip = str(body.get("ip", "")).strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": "invalid IP address"}), 400
        if not engine:
            return jsonify({"error": "engine not running"}), 400
        mode = body.get("mode", "block") if body.get("mode") in ("block", "redirect") else "block"
        taken = engine.responder.act(ip, "Manual", mode, int(body.get("minutes", config.BLOCK_DURATION_MIN)))
        return jsonify({"ip": ip, "result": taken})

    @app.route("/api/unblock", methods=["POST"])
    @login_required
    def api_unblock():
        if not csrf_ok():
            abort(403)
        ip = str(request.get_json(force=True).get("ip", "")).strip()
        if not engine:
            return jsonify({"error": "engine not running"}), 400
        return jsonify({"ip": ip, "removed": engine.responder.unblock(ip)})

    @app.route("/api/honeypot")
    @login_required
    def api_honeypot():
        s = db.Session()
        H = db.HoneypotEvent
        events = [e.to_dict() for e in s.query(H).order_by(H.id.desc()).limit(200)]
        creds = (s.query(H.username, H.password, func.count(H.id).label("n"))
                 .filter(H.event.in_(["login_attempt", "login_success"]))
                 .group_by(H.username, H.password).order_by(func.count(H.id).desc()).limit(15).all())
        by_service = dict(s.query(H.service, func.count(H.id)).group_by(H.service).all())
        ips = (s.query(H.src_ip, func.count(H.id).label("n")).group_by(H.src_ip)
               .order_by(func.count(H.id).desc()).limit(10).all())
        db.Session.remove()
        return jsonify({"events": events,
                        "credentials": [{"username": u, "password": p, "count": n} for u, p, n in creds],
                        "by_service": by_service,
                        "attackers": [{"ip": i, "count": n} for i, n in ips],
                        "services": engine.honeypot.running if engine and engine.honeypot else []})

    @app.route("/api/model")
    @login_required
    def api_model():
        p = config.REPORT_DIR / "metrics.json"
        m = json.loads(p.read_text()) if p.exists() else {}
        m["images"] = [f for f in ("confusion_matrix.png", "training_curves.png", "model_comparison.png",
                                   "shap_global.png") if (config.REPORT_DIR / f).exists()]
        return jsonify(m)

    @app.teardown_appcontext
    def _cleanup(exc):
        if db.Session is not None:
            db.Session.remove()

    return app
