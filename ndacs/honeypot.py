"""
Low-interaction honeypot server.

Fake services that look real to attackers but never give them a shell:
  ssh    (2222) - OpenSSH banner, records client software
  ftp    (2121) - vsFTPd login prompt, records every username/password tried
  telnet (2323) - Ubuntu login prompt, records credentials
  http   (8081) - fake "router admin" login page, records requests, credentials,
                  and flags SQL-injection / XSS / path-traversal payloads

Safety: no command execution, read limits + timeouts on every connection,
connection cap, nothing the attacker sends is ever executed or stored as a file.
Every event is written to the database and reported to the engine as threat
intelligence. For a full interactive SSH honeypot, run Cowrie (deploy/).
"""
import asyncio
import json
import logging
import re
import threading
import time
from urllib.parse import parse_qs, unquote_plus

import config
from ndacs import db

log = logging.getLogger("ndacs.honeypot")

READ_TIMEOUT = 30
MAX_LINE = 1024
MAX_CONN = 200

ATTACK_PATTERNS = {
    "sql-injection": re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s+'?\d|'\s*or\s+1=1|--\s|;\s*drop\s|sleep\(\d)", re.I),
    "xss": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<svg)", re.I),
    "path-traversal": re.compile(r"(\.\./|\.\.%2f|/etc/passwd)", re.I),
    "command-injection": re.compile(r"(;\s*(cat|wget|curl|nc|bash)\b|\|\s*(sh|bash)\b|`.+`|\$\(.+\))", re.I),
}

LOGIN_PAGE = b"""<!doctype html><html><head><title>NetGear R7000 - Admin Login</title>
<style>body{font-family:Arial;background:#eef1f5;display:flex;justify-content:center;padding-top:80px}
form{background:#fff;padding:30px 40px;border-radius:6px;box-shadow:0 2px 8px #0002}
input{display:block;margin:8px 0 16px;padding:8px;width:240px}</style></head><body>
<form method="POST" action="/login"><h3>Router Administration</h3>
<label>Username</label><input name="username"><label>Password</label>
<input name="password" type="password"><button>Log in</button></form></body></html>"""


def _clean(b: bytes) -> str:
    """Strip telnet IAC negotiation and non-printables."""
    b = re.sub(rb"\xff[\xfb-\xfe].|\xff\xfa.*?\xff\xf0|\xff.", b"", b, flags=re.S)
    return "".join(ch for ch in b.decode("utf-8", "ignore") if ch.isprintable()).strip()[:128]


class Honeypot:
    def __init__(self, on_event=None):
        self.on_event = on_event          # callback(src_ip, service, event, details)
        self.loop = None
        self.sem = None
        self.counts = {s: 0 for s in config.HONEYPOT_PORTS}
        self.running = []

    # ------------------------------------------------------------ logging
    def _log(self, writer, service, event, username=None, password=None, data=None):
        peer = writer.get_extra_info("peername") or ("?", 0)
        ip, port = peer[0], peer[1]
        self.counts[service.split("-")[0]] = self.counts.get(service.split("-")[0], 0) + 1
        try:
            db.add_honeypot_event(src_ip=ip, src_port=port, service=service, event=event,
                                  username=username, password=password,
                                  data=(data or "")[:1000])
        except Exception:
            log.exception("could not store honeypot event")
        log.info("HONEYPOT %s %s from %s %s", service, event, ip,
                 f"user={username!r} pass={password!r}" if username is not None else (data or "")[:80])
        if self.on_event:
            try:
                self.on_event(ip, service, event, {"username": username, "password": password, "data": data})
            except Exception:
                log.exception("honeypot callback failed")

    async def _readline(self, reader):
        line = await asyncio.wait_for(reader.readline(), READ_TIMEOUT)
        return line[:MAX_LINE]

    def _wrap(self, handler, service):
        async def run(reader, writer):
            if self.sem.locked():
                writer.close()
                return
            async with self.sem:
                try:
                    self._log(writer, service, "connect")
                    await handler(reader, writer)
                except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                    pass
                except Exception:
                    log.exception("%s handler error", service)
                finally:
                    try:
                        writer.close()
                    except Exception:
                        pass
        return run

    # ------------------------------------------------------------ services
    async def ssh(self, reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n")
        await writer.drain()
        client = _clean(await self._readline(reader))
        self._log(writer, "ssh", "client_version", data=client)
        await asyncio.sleep(2)   # keep the scanner waiting a little (tarpit)

    async def ftp(self, reader, writer):
        writer.write(b"220 (vsFTPd 3.0.3)\r\n")
        await writer.drain()
        user = None
        for _ in range(50):
            line = _clean(await self._readline(reader))
            if not line:
                break
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            if cmd == "USER":
                user = arg
                writer.write(b"331 Please specify the password.\r\n")
            elif cmd == "PASS":
                self._log(writer, "ftp", "login_attempt", username=user or "", password=arg)
                await asyncio.sleep(1)
                writer.write(b"530 Login incorrect.\r\n")
            elif cmd == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break
            elif cmd in ("SYST",):
                writer.write(b"215 UNIX Type: L8\r\n")
            elif cmd in ("FEAT", "AUTH", "OPTS"):
                writer.write(b"530 Please login with USER and PASS.\r\n")
            else:
                self._log(writer, "ftp", "command", data=line)
                writer.write(b"530 Please login with USER and PASS.\r\n")
            await writer.drain()

    async def telnet(self, reader, writer):
        writer.write(b"\r\nUbuntu 18.04.6 LTS\r\n")
        for _ in range(5):
            writer.write(b"server01 login: ")
            await writer.drain()
            raw = await self._readline(reader)
            if not raw:            # client disconnected
                break
            user = _clean(raw)
            writer.write(b"Password: ")
            await writer.drain()
            raw = await self._readline(reader)
            if not raw:
                break
            pw = _clean(raw)
            self._log(writer, "telnet", "login_attempt", username=user, password=pw)
            await asyncio.sleep(1.5)
            writer.write(b"\r\nLogin incorrect\r\n")

    async def http(self, reader, writer):
        request_line = _clean(await self._readline(reader))
        headers = {}
        for _ in range(60):
            h = (await self._readline(reader)).decode("latin-1").strip()
            if not h:
                break
            k, _, v = h.partition(":")
            headers[k.strip().lower()] = v.strip()[:300]
        body = b""
        length = min(int(headers.get("content-length", "0") or 0), 8192)
        if length:
            body = await asyncio.wait_for(reader.readexactly(length), READ_TIMEOUT)
        body_s = body.decode("utf-8", "ignore")
        parts = request_line.split(" ")
        method, path = (parts + ["", ""])[:2]
        decoded = unquote_plus(path + " " + body_s)
        attacks = [n for n, rx in ATTACK_PATTERNS.items() if rx.search(decoded)]
        details = json.dumps({"request": request_line, "ua": headers.get("user-agent", ""),
                              "body": body_s[:500], "attacks": attacks})
        if method == "POST" and "login" in path:
            form = parse_qs(body_s)
            u, p = form.get("username", [""])[0], form.get("password", [""])[0]
            self._log(writer, "http", "login_attempt", username=u[:128], password=p[:128], data=details)
            resp, status = b"<h3>Invalid username or password</h3>", b"401 Unauthorized"
        else:
            self._log(writer, "http", "web_attack" if attacks else "request", data=details)
            resp, status = LOGIN_PAGE, b"200 OK"
        writer.write(b"HTTP/1.1 " + status + b"\r\nServer: lighttpd/1.4.35\r\nContent-Type: text/html\r\n"
                     b"Content-Length: " + str(len(resp)).encode() + b"\r\nConnection: close\r\n\r\n" + resp)
        await writer.drain()

    # ------------------------------------------------------------ lifecycle
    async def _main(self):
        self.sem = asyncio.Semaphore(MAX_CONN)
        servers = []
        for service, port in config.HONEYPOT_PORTS.items():
            if service == "ssh" and config.COWRIE_JSON_LOG:
                continue   # Cowrie provides SSH
            try:
                srv = await asyncio.start_server(self._wrap(getattr(self, service), service),
                                                 config.HONEYPOT_BIND, port)
                servers.append(srv)
                self.running.append(f"{service}:{port}")
            except OSError as e:
                log.error("Honeypot %s could not bind port %s: %s", service, port, e)
        log.info("Honeypot services listening: %s", ", ".join(self.running) or "none")
        await asyncio.gather(*(s.serve_forever() for s in servers))

    def start(self):
        def runner():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self.loop.run_until_complete(self._main())
            except Exception:
                log.exception("honeypot stopped")
        threading.Thread(target=runner, daemon=True, name="honeypot").start()
        if config.COWRIE_JSON_LOG:
            threading.Thread(target=self._tail_cowrie, daemon=True, name="cowrie-tail").start()

    # ------------------------------------------------------------ Cowrie integration
    def _tail_cowrie(self):
        """Follow Cowrie's JSON log and import its events."""
        path = config.COWRIE_JSON_LOG
        log.info("Following Cowrie log %s", path)
        f = None
        while True:
            try:
                if f is None:
                    f = open(path, "r")
                    f.seek(0, 2)
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                e = json.loads(line)
                ev = e.get("eventid", "")
                kind = {"cowrie.session.connect": "connect", "cowrie.login.failed": "login_attempt",
                        "cowrie.login.success": "login_success", "cowrie.command.input": "command",
                        "cowrie.session.file_download": "download"}.get(ev)
                if not kind:
                    continue
                ip = e.get("src_ip", "?")
                db.add_honeypot_event(src_ip=ip, src_port=e.get("src_port"), service="ssh-cowrie",
                                      event=kind, username=e.get("username"), password=e.get("password"),
                                      data=(e.get("input") or e.get("url") or "")[:1000])
                if self.on_event:
                    self.on_event(ip, "ssh-cowrie", kind, e)
            except FileNotFoundError:
                time.sleep(5)
            except Exception:
                time.sleep(1)
