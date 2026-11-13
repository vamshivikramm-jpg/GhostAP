"""Alert notifications (F013 throttling, F056 webhooks, F057 phone push, F058 email,
F059 syslog / JSON lines). F055 desktop notifications live in the dashboard itself.

Everything is off until `notifications.enabled` is true and a channel is configured.
Secrets (webhook URLs with tokens, HMAC secrets, SMTP passwords) are read from
environment variables named in the settings, never from the settings themselves.

What is sent, and when (F013):
  raised     the first time an alert reaches notifications.min_level
  escalated  when it goes from MEDIUM to HIGH
  reminder   every realert_minutes while it is still active (0 = never)
Muted alerts and alerts marked "false positive" are skipped. Each channel sends at most
max_per_minute messages; the rest are counted and reported in the next message.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import smtplib
import socket
import ssl
import threading
import time
import urllib.request
from collections import deque
from email.message import EmailMessage
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .logs import get_logger
from .storage import Store

log = get_logger("notify")
ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
ACTIVE_GRACE_S = 30.0                     # an alert updated this recently (capture time) is active
USER_AGENT = "GhostAP/{} (notifications)".format(__version__)


# --------------------------------------------------------------------------- messages
def describe(alert: dict) -> str:
    kind = {"deauth": "deauthentication attack", "flood": "beacon flood"}.get(alert.get("detector"))
    what = kind or ("evil twin suspected" if alert["level"] == "HIGH" else "suspicious access point")
    return "{} on '{}'".format(what, alert["ssid"])


def reasons_short(alert: dict, n: int = 3) -> str:
    out = []
    for r in (alert.get("reasons") or "").split("; ")[:n]:
        name = r.split(" (")[0].replace("_", " ")
        if name:
            out.append(name)
    return ", ".join(out)


def text_message(event: str, alert: dict, session: str, url: str, suppressed: int = 0) -> Tuple[str, str]:
    """(title, body) in plain text. SSIDs come from the air: callers escape for their format."""
    prefix = {"raised": "", "escalated": "now HIGH: ", "reminder": "still active: ", "test": ""}[event]
    title = "[GhostAP] {} {}{}".format(alert["level"], prefix, describe(alert))
    lines = ["{} scores {:.0f}/100.".format(alert["bssid"], alert["score"])]
    if reasons_short(alert):
        lines.append("Why: " + reasons_short(alert) + ".")
    lines.append("Session: {}".format(session))
    if url:
        from urllib.parse import quote
        lines.append("{}#ap={}|{}".format(url.rstrip("/") + "/", quote(alert["ssid"]), quote(alert["bssid"])))
    if suppressed:
        lines.append("({} more message{} were held back by the rate limit.)".format(
            suppressed, "s" if suppressed > 1 else ""))
    if event == "test":
        title = "[GhostAP] test message"
        lines = ["Notifications from this GhostAP work.", "Session: {}".format(session)] + ([url] if url else [])
    return title, "\n".join(lines)


def json_payload(event: str, alert: dict, session: str, url: str) -> dict:
    keep = ("id", "ssid", "bssid", "level", "score", "detector", "first_ts", "high_ts", "last_ts", "reasons",
            "triage_status")
    return {"source": "ghostap", "version": __version__, "event": event, "session": session,
            "sent_at": time.time(), "dashboard_url": url or None, "alert": {k: alert.get(k) for k in keep}}


def cef_line(event: str, alert: dict, session: str) -> str:
    """ArcSight Common Event Format, escaped as the spec requires."""
    def hdr(v):
        return str(v).replace("\\", "\\\\").replace("|", "\\|")

    def ext(v):
        return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ")
    sev = 9 if alert["level"] == "HIGH" else 6
    sig = alert.get("detector") or "ghostap"
    return "CEF:0|GhostAP|GhostAP|{}|{}|{}|{}|act={} cs1Label=ssid cs1={} smac={} cn1Label=score cn1={:.1f} " \
           "cs2Label=session cs2={} msg={}".format(
               hdr(__version__), hdr(sig), hdr(describe(alert)), sev, ext(event), ext(alert["ssid"]),
               ext(alert["bssid"]), alert["score"], ext(session), ext(reasons_short(alert)))


# --------------------------------------------------------------------------- channels
class Channel:
    name = "channel"
    min_level = "MEDIUM"

    def send(self, event: str, alert: dict, session: str, url: str, suppressed: int) -> str:
        raise NotImplementedError


def _post(url: str, body: bytes, headers: Dict[str, str], timeout: float = 8.0) -> str:
    if not url.startswith(("http://", "https://")):
        raise ValueError("only http(s) URLs are allowed")
    req = urllib.request.Request(url, data=body, method="POST",  # noqa: S310 - http(s) checked above
                                 headers=dict(headers, **{"User-Agent": USER_AGENT}))
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - scheme checked above
        return "HTTP {}".format(r.status)


class Webhook(Channel):
    def __init__(self, spec: dict, env=os.environ):
        self.spec = spec
        self.fmt = spec.get("format", "json")
        self.name = spec.get("name") or "{} webhook".format(self.fmt)
        self.min_level = spec.get("min_level", "MEDIUM")
        self.url = spec.get("url") or env.get(spec.get("url_env") or "", "")
        self.secret = env.get(spec["secret_env"], "") if spec.get("secret_env") else ""
        if not self.url:
            raise ValueError("{}: environment variable {} is not set".format(self.name, spec.get("url_env")))

    def send(self, event, alert, session, url, suppressed):
        title, text = text_message(event, alert, session, url, suppressed)
        if self.fmt == "json":
            payload = json_payload(event, alert, session, url)
            payload["suppressed"] = suppressed
            body = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json"}
            if self.secret:                       # receivers check this to trust the message
                sig = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
                headers["X-GhostAP-Signature"] = "sha256=" + sig
            return _post(self.url, body, headers)
        if self.fmt == "ntfy":                     # https://ntfy.sh: phone push without an account
            ascii_title = title.encode("ascii", "replace").decode()
            # headers must be ASCII, so the full title (any network name) also opens the body
            return _post(self.url, (title + "\n" + text).encode(), {"Title": ascii_title, "Tags": "warning",
                                                   "Priority": "urgent" if alert["level"] == "HIGH" else "high"})
        if self.fmt == "telegram":                 # url_env holds https://api.telegram.org/bot<TOKEN>/sendMessage
            body = json.dumps({"chat_id": self.spec["chat_id"], "text": title + "\n" + text,
                               "disable_web_page_preview": True}).encode()
            return _post(self.url, body, {"Content-Type": "application/json"})
        if self.fmt == "slack":                    # incoming webhook; escape Slack's control characters
            esc = (title + "\n" + text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return _post(self.url, json.dumps({"text": esc}).encode(), {"Content-Type": "application/json"})
        raise ValueError("unknown webhook format " + self.fmt)


class Email(Channel):
    name = "email"

    def __init__(self, spec: dict, env=os.environ, smtp_class=smtplib.SMTP):
        self.spec, self.smtp_class = spec, smtp_class
        self.password = env.get(spec.get("password_env") or "", "")
        if spec.get("username") and not self.password:
            raise ValueError("email: environment variable {} (SMTP password) is not set".format(
                spec.get("password_env")))

    def send(self, event, alert, session, url, suppressed):
        title, text = text_message(event, alert, session, url, suppressed)
        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = self.spec["sender"]
        msg["To"] = ", ".join(self.spec["to"])
        msg.set_content(text + "\n\nGhostAP is a passive detector: it only listens to beacons.\n")
        with self.smtp_class(self.spec["host"], int(self.spec["port"]), timeout=10) as smtp:
            if self.spec.get("starttls", True):
                smtp.starttls(context=ssl.create_default_context())
            if self.spec.get("username"):
                smtp.login(self.spec["username"], self.password)
            smtp.send_message(msg)
        return "sent to {} recipient(s)".format(len(self.spec["to"]))


class Syslog(Channel):
    name = "syslog"

    def __init__(self, spec: dict):
        self.spec = spec

    def send(self, event, alert, session, url, suppressed):
        sev = 2 if alert["level"] == "HIGH" else 4               # critical / warning
        pri = 16 * 8 + sev                                       # facility local0
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        msg = cef_line(event, alert, session) if self.spec["format"] == "cef" else \
            json.dumps(json_payload(event, alert, session, url), separators=(",", ":"))
        line = "<{}>1 {} {} ghostap - {} - {}".format(pri, stamp, socket.gethostname() or "-",
                                                      "ALERT" if event != "test" else "TEST", msg)
        data = line.encode()
        addr = (self.spec["host"], int(self.spec["port"]))
        if self.spec["protocol"] == "tcp":
            with socket.create_connection(addr, timeout=5) as s:
                s.sendall(str(len(data)).encode() + b" " + data)      # RFC 6587 octet counting
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data[:8192], addr)
        return "{} {}:{}".format(self.spec["protocol"], *addr)


class JsonLines(Channel):
    name = "jsonl"

    def __init__(self, spec: dict):
        self.path = spec["path"]

    def send(self, event, alert, session, url, suppressed):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(json_payload(event, alert, session, url)) + "\n")
        return self.path


def build_channels(cfg: dict, env=os.environ) -> Tuple[List[Channel], List[str]]:
    """Channels from the settings, plus problems that kept a channel from starting."""
    n = cfg["notifications"]
    chans: List[Channel] = []
    problems: List[str] = []
    for spec in n["webhooks"]:
        try:
            chans.append(Webhook(spec, env))
        except ValueError as e:
            problems.append(str(e))
    if n["email"]["enabled"]:
        try:
            chans.append(Email(n["email"], env))
        except ValueError as e:
            problems.append(str(e))
    if n["syslog"]["enabled"]:
        chans.append(Syslog(n["syslog"]))
    if n["jsonl"]["enabled"]:
        chans.append(JsonLines(n["jsonl"]))
    return chans, problems


# --------------------------------------------------------------------------- decisions
def decide(alerts: List[dict], state: Dict[int, dict], muted: Callable[[dict], bool], min_level: str,
           realert_s: float, now: float, capture_end: Optional[float]) -> List[Tuple[str, dict]]:
    """F013: which alerts to send about this round, and why."""
    out = []
    for a in alerts:
        if ORDER.get(a["level"], 0) < ORDER[min_level] or a.get("triage_status") == "false_positive" or muted(a):
            continue
        st = state.get(a["id"])
        active = capture_end is None or a.get("last_ts") is None or a["last_ts"] >= capture_end - ACTIVE_GRACE_S
        if st is None:
            out.append(("raised", a))
        elif ORDER.get(a["level"], 0) > ORDER.get(st["level"] or "LOW", 0):
            out.append(("escalated", a))
        elif realert_s > 0 and active and st["last_sent"] is not None and now - st["last_sent"] >= realert_s:
            out.append(("reminder", a))
    return out


class RateLimit:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.sent: Dict[str, deque] = {}
        self.held: Dict[str, int] = {}

    def allow(self, channel: str, now: float) -> bool:
        q = self.sent.setdefault(channel, deque())
        while q and now - q[0] >= 60:
            q.popleft()
        if len(q) >= self.per_minute:
            self.held[channel] = self.held.get(channel, 0) + 1
            return False
        q.append(now)
        return True

    def take_held(self, channel: str) -> int:
        return self.held.pop(channel, 0)


class Notifier:
    """Runs one round per call to tick(); the web server calls it from a thread."""

    def __init__(self, cfg: dict, admin_db: str, channels: Optional[List[Channel]] = None, env=os.environ):
        self.cfg = cfg
        self.admin_db = admin_db
        if channels is None:
            channels, self.problems = build_channels(cfg, env)
        else:
            self.problems = []
        self.channels = channels
        self.limit = RateLimit(int(cfg["notifications"]["max_per_minute"]))
        for p in self.problems:
            log.warning("notification channel not started: %s", p)

    def _deliver(self, chan: Channel, event: str, alert: dict, session: str, now: float, check_limit=True) -> dict:
        url = self.cfg["notifications"]["dashboard_url"]
        if check_limit and not self.limit.allow(chan.name, now):
            self._log(now, chan.name, event, alert, False, "held back by the rate limit")
            return {"channel": chan.name, "ok": False, "detail": "rate limited"}
        held = self.limit.take_held(chan.name)
        detail, ok = "", False
        for attempt in range(3):                      # two retries with back-off
            try:
                detail = chan.send(event, alert, session, url, held)
                ok = True
                break
            except Exception as e:  # network / SMTP errors: logged and shown, never raised
                detail = "{}: {}".format(type(e).__name__, e)
                if attempt < 2:
                    time.sleep(1 + 2 * attempt)
        self._log(now, chan.name, event, alert, ok, detail)
        (log.info if ok else log.warning)("notification %s %s via %s: %s", event, alert.get("bssid"), chan.name, detail)
        return {"channel": chan.name, "ok": ok, "detail": detail}

    def _log(self, now, channel, event, alert, ok, detail):
        with Store(self.admin_db) as s:
            s.log_notification(now, channel, event, "{} {}".format(alert.get("ssid"), alert.get("bssid")), ok, detail)

    def tick(self, session: str, alerts: List[dict], muted: Callable[[dict], bool],
             capture_end: Optional[float], now: Optional[float] = None) -> List[dict]:
        now = time.time() if now is None else now
        n = self.cfg["notifications"]
        with Store(self.admin_db) as s:
            state = s.notify_state(session)
        results = []
        for event, a in decide(alerts, state, muted, n["min_level"], n["realert_minutes"] * 60, now, capture_end):
            for chan in self.channels:
                if ORDER.get(a["level"], 0) >= ORDER[chan.min_level]:
                    results.append(dict(self._deliver(chan, event, a, session, now), event=event, alert=a["id"]))
            with Store(self.admin_db) as s:            # recorded even if a channel failed: no resend storm
                s.set_notify_state(session, a["id"], a["level"], now)
        return results

    def test(self, session: str) -> List[dict]:
        fake = {"id": 0, "ssid": "GhostAP test", "bssid": "00:00:00:00:00:00", "level": "HIGH", "score": 0.0,
                "detector": "test", "reasons": ""}
        return [self._deliver(c, "test", fake, session, time.time(), check_limit=False) for c in self.channels]


class NotifierThread(threading.Thread):
    """Polls the current session every few seconds (only while notifications are on)."""

    def __init__(self, notifier: Notifier, ctx, every: float = 5.0):
        super().__init__(name="ghostap-notify", daemon=True)
        self.notifier, self.ctx, self.every = notifier, ctx, every
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.wait(self.every):
            try:
                ctx = self.ctx
                with Store(ctx.db) as s:
                    alerts = s.alerts("ghostap,deauth,flood")
                    end = s.conn.execute("SELECT MAX(last_seen) FROM ap_profiles").fetchone()[0]
                mutes = ctx.active_mutes()
                from .web import is_muted
                self.notifier.tick(ctx.current_session or ctx.db, alerts,
                                   lambda a, m=mutes: is_muted(a, m), end)
            except Exception:  # keep running; the error is in the log
                log.exception("notification round failed")
