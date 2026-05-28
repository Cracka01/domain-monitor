"""Flask application + background runner for Domain Monitor.

Public entry points:
    create_app(data_dir)   -> Flask app instance, plus a started background runner.
    run_server(...)        -> Convenience helper used by the CLI.

The application keeps all state in a SQLite database located inside ``data_dir``
(see :func:`default_data_dir`). No secrets ever live in the source code; the
VirusTotal API key is supplied at runtime through the web UI and stored
locally only.
"""
from __future__ import annotations

import csv
import io
import os
import re
import socket
import sqlite3
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request, send_file
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Defaults / constants
# ---------------------------------------------------------------------------
PACKAGE_DIR = Path(__file__).resolve().parent

DEFAULT_INTERVAL_HOURS = 4
DEFAULT_CONCURRENCY = 20
DEFAULT_TIMEOUT = 10
DEFAULT_VT_RATE_PER_MIN = 4    # VirusTotal free tier: 4 req/min, 500/day
DEFAULT_VT_CACHE_HOURS = 24    # Skip re-querying VT for domains seen recently
USER_AGENT = "Mozilla/5.0 (compatible; DomainMonitor/0.1)"
VT_API_BASE = "https://www.virustotal.com/api/v3"

PARKED_KEYWORDS = [
    "this domain is for sale", "domain is for sale", "buy this domain", "domain for sale",
    "parked", "domain parking", "is parked",
    "godaddy", "sedo.com", "dan.com", "hugedomains", "afternic", "namecheap marketplace",
    "expired domain", "domain has expired", "domain expired",
    "default web site page", "welcome to nginx", "apache2 ubuntu default page", "it works!",
    "buy now for", "make an offer", "interested in this domain",
]

INACTIVE_STATES = {"4XX", "5XX", "UNREACHABLE", "PARKED", "PENDING"}


def default_data_dir() -> Path:
    """Return the default per-user data directory.

    Honours the ``DOMAIN_MONITOR_DATA_DIR`` environment variable when set.
    """
    env = os.environ.get("DOMAIN_MONITOR_DATA_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return Path.home() / ".domain-monitor"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
class Store:
    """Thin wrapper around a SQLite database with schema migrations."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    code INTEGER,
                    title TEXT DEFAULT '',
                    prev_status TEXT,
                    is_new INTEGER NOT NULL DEFAULT 0,
                    last_checked INTEGER,
                    added_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    code INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_history_domain ON history(domain);
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                """
            )
            # Migrations: add columns when upgrading from older versions
            cols = {row[1] for row in c.execute("PRAGMA table_info(domains)").fetchall()}
            for col, ddl in [
                ("ip",            "ALTER TABLE domains ADD COLUMN ip TEXT"),
                ("vt_malicious",  "ALTER TABLE domains ADD COLUMN vt_malicious INTEGER"),
                ("vt_suspicious", "ALTER TABLE domains ADD COLUMN vt_suspicious INTEGER"),
                ("vt_harmless",   "ALTER TABLE domains ADD COLUMN vt_harmless INTEGER"),
                ("vt_undetected", "ALTER TABLE domains ADD COLUMN vt_undetected INTEGER"),
                ("vt_reputation", "ALTER TABLE domains ADD COLUMN vt_reputation INTEGER"),
                ("vt_verdict",    "ALTER TABLE domains ADD COLUMN vt_verdict TEXT"),
                ("vt_checked_at", "ALTER TABLE domains ADD COLUMN vt_checked_at INTEGER"),
                ("vt_error",      "ALTER TABLE domains ADD COLUMN vt_error TEXT"),
            ]:
                if col not in cols:
                    c.execute(ddl)
            c.commit()

    def get_setting(self, key: str, default: str) -> str:
        with self.connect() as c:
            row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            c.commit()


# ---------------------------------------------------------------------------
# Domain utilities
# ---------------------------------------------------------------------------
_DOMAIN_RE = re.compile(r"^[a-z0-9.\-]+\.[a-z]{2,}$")


def normalize_domain(raw: str) -> str | None:
    """Normalise a free-form input into a bare domain (lower-case, no scheme/path)."""
    if not raw:
        return None
    d = str(raw).strip().lower().strip('"\'')
    if not d:
        return None
    d = re.sub(r"^https?://", "", d)
    d = d.lstrip("/")
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = re.sub(r":\d+$", "", d)
    if not _DOMAIN_RE.match(d):
        return None
    return d


def now_ts() -> int:
    """Current time as milliseconds since epoch."""
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------
def _make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=0, connect=0, read=0)
    s.mount("http://",  HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50))
    s.mount("https://", HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50))
    s.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en;q=0.9"})
    return s


def classify(code: int | None, body: str) -> tuple[str, str]:
    """Classify an HTTP response. Returns (status, reason/keyword)."""
    if code is None:
        return "UNREACHABLE", ""
    if 200 <= code < 400:
        low = (body or "").lower()[:10000]
        for kw in PARKED_KEYWORDS:
            if kw in low:
                return "PARKED", kw
        return "ACTIVE", ""
    if 400 <= code < 500:
        return "4XX", ""
    if 500 <= code < 600:
        return "5XX", ""
    return "UNREACHABLE", ""


_TITLE_RE = re.compile(r"<title[^>]*>([\s\S]*?)</title>", re.IGNORECASE)


def extract_title(html: str) -> str:
    if not html:
        return ""
    m = _TITLE_RE.search(html)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:180]


def check_domain(session: requests.Session, domain: str, timeout: int) -> dict:
    """Probe a domain via HTTPS then HTTP. Returns {status, code, title}."""
    last_err = ""
    last_code: int | None = None
    body = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
            last_code = r.status_code
            try:
                chunks: list[bytes] = []
                read = 0
                for chunk in r.iter_content(chunk_size=4096, decode_unicode=False):
                    if not chunk:
                        break
                    chunks.append(chunk)
                    read += len(chunk)
                    if read >= 16384:
                        break
                raw = b"".join(chunks)
                enc = r.encoding or "utf-8"
                try:
                    body = raw.decode(enc, errors="replace")
                except Exception:
                    body = raw.decode("utf-8", errors="replace")
            finally:
                r.close()
            break
        except requests.exceptions.SSLError:
            last_err = "ssl-error"
            continue
        except requests.exceptions.ConnectTimeout:
            last_err = "connect-timeout"
            continue
        except requests.exceptions.ReadTimeout:
            last_err = "read-timeout"
            continue
        except requests.exceptions.ConnectionError:
            last_err = "conn-error"
            continue
        except requests.exceptions.RequestException as e:
            last_err = e.__class__.__name__
            continue

    status, reason = classify(last_code, body)
    title = extract_title(body) or reason or last_err
    return {"status": status, "code": last_code, "title": title}


def resolve_ip(domain: str) -> str | None:
    """Resolve the IPv4 address of ``domain``. Returns None on failure."""
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except (socket.gaierror, socket.herror, OSError):
        return None
    return None


# ---------------------------------------------------------------------------
# VirusTotal integration
# ---------------------------------------------------------------------------
class RateLimiter:
    """Sliding-window rate limiter: at most ``max_calls`` calls per ``window`` seconds."""

    def __init__(self, max_calls: int, window_sec: float = 60.0):
        self.max_calls = max(1, int(max_calls))
        self.window = window_sec
        self.calls: deque[float] = deque()
        self.lock = threading.Lock()

    def acquire(self, cancel_check=None) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                while self.calls and (now - self.calls[0]) > self.window:
                    self.calls.popleft()
                if len(self.calls) < self.max_calls:
                    self.calls.append(now)
                    return
                wait = self.window - (now - self.calls[0]) + 0.05
            slept = 0.0
            while slept < wait:
                if cancel_check and cancel_check():
                    return
                time.sleep(min(0.5, wait - slept))
                slept += 0.5


def vt_classify_stats(stats: dict, reputation: int | None) -> str:
    m = int(stats.get("malicious", 0) or 0)
    s = int(stats.get("suspicious", 0) or 0)
    h = int(stats.get("harmless", 0) or 0)
    if m >= 2:
        return "MALICIOUS"
    if m == 1 or s >= 2:
        return "SUSPICIOUS"
    if reputation is not None and reputation <= -10:
        return "SUSPICIOUS"
    if h + int(stats.get("undetected", 0) or 0) > 0:
        return "CLEAN"
    return "UNKNOWN"


def vt_check_domain(api_key: str, domain: str, timeout: int = 15) -> dict:
    """Look up a single domain on VirusTotal. Returns a dict of vt_* fields."""
    if not api_key:
        return {"vt_error": "no-api-key"}
    url = f"{VT_API_BASE}/domains/{domain}"
    try:
        r = requests.get(
            url,
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=timeout,
        )
        if r.status_code == 404:
            return {
                "vt_verdict": "UNKNOWN", "vt_malicious": 0, "vt_suspicious": 0,
                "vt_harmless": 0, "vt_undetected": 0, "vt_reputation": None,
                "vt_error": "not-in-vt",
            }
        if r.status_code == 401:
            return {"vt_error": "invalid-api-key"}
        if r.status_code == 429:
            return {"vt_error": "rate-limit"}
        if r.status_code >= 400:
            return {"vt_error": f"http-{r.status_code}"}
        data = r.json().get("data", {}).get("attributes", {}) or {}
        stats = data.get("last_analysis_stats", {}) or {}
        reputation = data.get("reputation")
        verdict = vt_classify_stats(stats, reputation)
        return {
            "vt_verdict": verdict,
            "vt_malicious": int(stats.get("malicious", 0) or 0),
            "vt_suspicious": int(stats.get("suspicious", 0) or 0),
            "vt_harmless": int(stats.get("harmless", 0) or 0),
            "vt_undetected": int(stats.get("undetected", 0) or 0),
            "vt_reputation": reputation,
            "vt_error": None,
        }
    except requests.exceptions.Timeout:
        return {"vt_error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"vt_error": e.__class__.__name__}
    except Exception as e:  # pragma: no cover - defensive
        return {"vt_error": f"err: {e.__class__.__name__}"}


# ---------------------------------------------------------------------------
# Background runner
# ---------------------------------------------------------------------------
class Runner:
    """Owns the worker threads that probe domains in the background."""

    def __init__(self, store: Store):
        self.store = store
        self.lock = threading.Lock()
        self.running = False
        self.cancel = False
        self.progress: dict = {"done": 0, "total": 0, "current": ""}
        self.last_run_ts: int | None = None
        self.next_run_ts: int | None = None
        self._auto_thread: threading.Thread | None = None
        self._stop_auto = threading.Event()
        self._vt_limiter: RateLimiter | None = None
        self._vt_limiter_lock = threading.Lock()

    # -- public API -------------------------------------------------------
    def status(self) -> dict:
        return {
            "running": self.running,
            "progress": dict(self.progress),
            "last_run": self.last_run_ts,
            "next_run": self.next_run_ts,
        }

    def start(self, only_domains: list[str] | None = None) -> bool:
        with self.lock:
            if self.running:
                return False
            self.running = True
            self.cancel = False
        threading.Thread(target=self._run, args=(only_domains,), daemon=True).start()
        return True

    def stop(self) -> None:
        self.cancel = True

    def reset_vt_limiter(self) -> None:
        with self._vt_limiter_lock:
            self._vt_limiter = None

    def get_vt_limiter(self) -> RateLimiter:
        rate = int(self.store.get_setting("vt_rate_per_min", str(DEFAULT_VT_RATE_PER_MIN)))
        with self._vt_limiter_lock:
            if self._vt_limiter is None or self._vt_limiter.max_calls != rate:
                self._vt_limiter = RateLimiter(rate, 60.0)
            return self._vt_limiter

    # -- internals --------------------------------------------------------
    def _run(self, only_domains: list[str] | None) -> None:  # noqa: PLR0912, PLR0915
        try:
            conc = int(self.store.get_setting("concurrency", str(DEFAULT_CONCURRENCY)))
            timeout = int(self.store.get_setting("timeout", str(DEFAULT_TIMEOUT)))
            vt_enabled = self.store.get_setting("vt_enabled", "0") == "1"
            vt_api_key = self.store.get_setting("vt_api_key", "")
            vt_cache_hours = float(self.store.get_setting("vt_cache_hours", str(DEFAULT_VT_CACHE_HOURS)))
            vt_cache_ms = int(vt_cache_hours * 3600 * 1000)

            with self.store.connect() as c:
                if only_domains:
                    placeholders = ",".join(["?"] * len(only_domains))
                    rows = c.execute(
                        f"SELECT domain, status, vt_checked_at FROM domains "
                        f"WHERE domain IN ({placeholders})",
                        only_domains,
                    ).fetchall()
                else:
                    rows = c.execute(
                        "SELECT domain, status, vt_checked_at FROM domains"
                    ).fetchall()
            domains = [(r["domain"], r["status"], r["vt_checked_at"]) for r in rows]
            if not domains:
                return

            self.progress = {"done": 0, "total": len(domains), "current": ""}
            session = _make_session()

            # Reset "is_new" flag at the start of a full pass.
            if not only_domains:
                with self.store.lock, self.store.connect() as c:
                    c.execute("UPDATE domains SET is_new=0")
                    c.commit()

            ts_run = now_ts()
            vt_limiter = self.get_vt_limiter() if (vt_enabled and vt_api_key) else None

            def task_http(item):
                domain, prev, _ = item
                if self.cancel:
                    return None
                res = check_domain(session, domain, timeout)
                ip = resolve_ip(domain)
                return domain, prev, res, ip

            # --- Phase 1: HTTP + DNS in parallel -----------------------------
            results: list[tuple[str, str, dict, str | None]] = []
            with ThreadPoolExecutor(max_workers=conc) as ex:
                futures = [ex.submit(task_http, item) for item in domains]
                for fut in as_completed(futures):
                    if self.cancel:
                        for f in futures:
                            f.cancel()
                        break
                    out = fut.result()
                    if out is None:
                        continue
                    domain, prev, res, ip = out
                    is_new = 1 if (prev in INACTIVE_STATES and res["status"] == "ACTIVE") else 0
                    with self.store.lock, self.store.connect() as c:
                        c.execute(
                            """UPDATE domains
                               SET status=?, code=?, title=?, prev_status=?,
                                   is_new=CASE WHEN ?=1 THEN 1 ELSE is_new END,
                                   last_checked=?, ip=COALESCE(?, ip)
                               WHERE domain=?""",
                            (res["status"], res["code"], res["title"], prev,
                             is_new, ts_run, ip, domain),
                        )
                        c.execute(
                            "INSERT INTO history(domain, ts, status, code) VALUES (?,?,?,?)",
                            (domain, ts_run, res["status"], res["code"]),
                        )
                        c.commit()
                    results.append((domain, prev, res, ip))
                    self.progress["done"] += 1
                    self.progress["current"] = domain

            # --- Phase 2: VirusTotal (sequential, rate-limited) --------------
            if vt_limiter and not self.cancel:
                with self.store.connect() as c:
                    vt_rows = {
                        r["domain"]: r["vt_checked_at"]
                        for r in c.execute(
                            "SELECT domain, vt_checked_at FROM domains"
                        ).fetchall()
                    }
                pending_vt = [
                    d for (d, _, _, _) in results
                    if not vt_rows.get(d) or (ts_run - (vt_rows.get(d) or 0)) > vt_cache_ms
                ]
                self.progress["vt_total"] = len(pending_vt)
                self.progress["vt_done"] = 0
                for d in pending_vt:
                    if self.cancel:
                        break
                    vt_limiter.acquire(cancel_check=lambda: self.cancel)
                    if self.cancel:
                        break
                    self.progress["current"] = f"VT: {d}"
                    vt = vt_check_domain(vt_api_key, d)
                    with self.store.lock, self.store.connect() as c:
                        c.execute(
                            """UPDATE domains
                               SET vt_verdict=?, vt_malicious=?, vt_suspicious=?, vt_harmless=?,
                                   vt_undetected=?, vt_reputation=?, vt_error=?, vt_checked_at=?
                               WHERE domain=?""",
                            (
                                vt.get("vt_verdict"), vt.get("vt_malicious"),
                                vt.get("vt_suspicious"), vt.get("vt_harmless"),
                                vt.get("vt_undetected"), vt.get("vt_reputation"),
                                vt.get("vt_error"), ts_run, d,
                            ),
                        )
                        c.commit()
                    self.progress["vt_done"] += 1
                    if vt.get("vt_error") in ("invalid-api-key", "no-api-key"):
                        break

            self.last_run_ts = ts_run
            self.store.set_setting("last_run", str(ts_run))
            self._schedule_next()
        finally:
            self.running = False
            self.progress["current"] = ""

    def _schedule_next(self) -> None:
        hours = float(self.store.get_setting("interval_hours", str(DEFAULT_INTERVAL_HOURS)))
        if self.last_run_ts:
            self.next_run_ts = self.last_run_ts + int(hours * 3600 * 1000)
            self.store.set_setting("next_run", str(self.next_run_ts))

    def start_auto_loop(self) -> None:
        if self._auto_thread and self._auto_thread.is_alive():
            return
        self._stop_auto.clear()

        def loop() -> None:
            lr = self.store.get_setting("last_run", "")
            nr = self.store.get_setting("next_run", "")
            if lr.isdigit():
                self.last_run_ts = int(lr)
            if nr.isdigit():
                self.next_run_ts = int(nr)
            while not self._stop_auto.is_set():
                if self.next_run_ts and now_ts() >= self.next_run_ts and not self.running:
                    self.start()
                self._stop_auto.wait(30)

        self._auto_thread = threading.Thread(target=loop, daemon=True)
        self._auto_thread.start()


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------
def create_app(data_dir: Path | str | None = None) -> Flask:
    """Build and return a configured Flask application.

    Parameters
    ----------
    data_dir: optional directory where ``monitor.db`` is stored. If omitted,
        falls back to :func:`default_data_dir`.
    """
    data_dir = Path(data_dir).expanduser().resolve() if data_dir else default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "monitor.db"

    store = Store(db_path)
    runner = Runner(store)
    runner.start_auto_loop()

    app = Flask(
        __name__,
        template_folder=str(PACKAGE_DIR / "templates"),
        static_folder=str(PACKAGE_DIR / "static"),
    )
    app.config["DOMAIN_MONITOR_STORE"] = store
    app.config["DOMAIN_MONITOR_RUNNER"] = runner
    app.config["DOMAIN_MONITOR_DATA_DIR"] = str(data_dir)

    _register_routes(app, store, runner)
    return app


def _register_routes(app: Flask, store: Store, runner: Runner) -> None:
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/state")
    def api_state():
        with store.connect() as c:
            rows = c.execute(
                """SELECT domain,status,code,title,prev_status,is_new,last_checked,
                          ip,vt_verdict,vt_malicious,vt_suspicious,vt_harmless,vt_undetected,
                          vt_reputation,vt_error,vt_checked_at
                   FROM domains ORDER BY is_new DESC, status, domain"""
            ).fetchall()
        domains = [dict(r) for r in rows]
        counts = {
            "ACTIVE": 0, "PARKED": 0, "4XX": 0, "5XX": 0, "UNREACHABLE": 0, "PENDING": 0,
            "TOTAL": len(domains), "NEW": 0,
            "VT_MALICIOUS": 0, "VT_SUSPICIOUS": 0, "VT_CLEAN": 0,
            "VT_UNKNOWN": 0, "VT_PENDING": 0,
        }
        for d in domains:
            counts[d["status"]] = counts.get(d["status"], 0) + 1
            if d["is_new"]:
                counts["NEW"] += 1
            v = d.get("vt_verdict")
            if v == "MALICIOUS":
                counts["VT_MALICIOUS"] += 1
            elif v == "SUSPICIOUS":
                counts["VT_SUSPICIOUS"] += 1
            elif v == "CLEAN":
                counts["VT_CLEAN"] += 1
            elif v == "UNKNOWN":
                counts["VT_UNKNOWN"] += 1
            else:
                counts["VT_PENDING"] += 1

        vt_key = store.get_setting("vt_api_key", "")
        settings = {
            "interval_hours": float(store.get_setting("interval_hours", str(DEFAULT_INTERVAL_HOURS))),
            "concurrency":    int(store.get_setting("concurrency", str(DEFAULT_CONCURRENCY))),
            "timeout":        int(store.get_setting("timeout", str(DEFAULT_TIMEOUT))),
            "vt_enabled":     store.get_setting("vt_enabled", "0") == "1",
            "vt_api_key_set": bool(vt_key),
            "vt_api_key_mask": (vt_key[:4] + "…" + vt_key[-4:]) if len(vt_key) >= 12
                               else ("•" * len(vt_key) if vt_key else ""),
            "vt_rate_per_min": int(store.get_setting("vt_rate_per_min", str(DEFAULT_VT_RATE_PER_MIN))),
            "vt_cache_hours":  float(store.get_setting("vt_cache_hours", str(DEFAULT_VT_CACHE_HOURS))),
        }
        return jsonify({
            "domains": domains,
            "counts": counts,
            "runner": runner.status(),
            "settings": settings,
        })

    @app.route("/api/add", methods=["POST"])
    def api_add():
        data = request.get_json(silent=True) or {}
        raw_list = data.get("domains") or []
        added = skipped = 0
        ts = now_ts()
        with store.lock, store.connect() as c:
            for raw in raw_list:
                d = normalize_domain(raw)
                if not d:
                    skipped += 1
                    continue
                try:
                    c.execute(
                        "INSERT INTO domains(domain, status, added_at) VALUES(?,?,?)",
                        (d, "PENDING", ts),
                    )
                    added += 1
                except sqlite3.IntegrityError:
                    skipped += 1
            c.commit()
        return jsonify({"added": added, "skipped": skipped})

    @app.route("/api/upload", methods=["POST"])
    def api_upload():
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "no file"}), 400
        text = f.read().decode("utf-8", errors="replace")
        candidates: list[str] = []
        for line in text.splitlines():
            for part in re.split(r"[,;\t]", line):
                candidates.append(part)
        added = skipped = 0
        ts = now_ts()
        with store.lock, store.connect() as c:
            for raw in candidates:
                d = normalize_domain(raw)
                if not d:
                    skipped += 1
                    continue
                try:
                    c.execute(
                        "INSERT INTO domains(domain, status, added_at) VALUES(?,?,?)",
                        (d, "PENDING", ts),
                    )
                    added += 1
                except sqlite3.IntegrityError:
                    skipped += 1
            c.commit()
        return jsonify({"added": added, "skipped": skipped, "total_lines": len(candidates)})

    @app.route("/api/check", methods=["POST"])
    def api_check():
        data = request.get_json(silent=True) or {}
        only = data.get("domains")
        started = runner.start(only_domains=only)
        return jsonify({"started": started, "runner": runner.status()})

    @app.route("/api/stop", methods=["POST"])
    def api_stop():
        runner.stop()
        return jsonify({"ok": True})

    @app.route("/api/delete", methods=["POST"])
    def api_delete():
        data = request.get_json(silent=True) or {}
        domain = data.get("domain")
        if not domain:
            return jsonify({"error": "domain required"}), 400
        with store.lock, store.connect() as c:
            c.execute("DELETE FROM domains WHERE domain=?", (domain,))
            c.execute("DELETE FROM history WHERE domain=?", (domain,))
            c.commit()
        return jsonify({"ok": True})

    @app.route("/api/clear", methods=["POST"])
    def api_clear():
        with store.lock, store.connect() as c:
            c.execute("DELETE FROM domains")
            c.execute("DELETE FROM history")
            c.commit()
        return jsonify({"ok": True})

    @app.route("/api/clear_new", methods=["POST"])
    def api_clear_new():
        data = request.get_json(silent=True) or {}
        domain = data.get("domain")
        with store.lock, store.connect() as c:
            if domain:
                c.execute("UPDATE domains SET is_new=0 WHERE domain=?", (domain,))
            else:
                c.execute("UPDATE domains SET is_new=0")
            c.commit()
        return jsonify({"ok": True})

    @app.route("/api/settings", methods=["POST"])
    def api_settings():
        data = request.get_json(silent=True) or {}
        for k in ("interval_hours", "concurrency", "timeout", "vt_rate_per_min", "vt_cache_hours"):
            if k in data:
                store.set_setting(k, str(data[k]))
        if "vt_enabled" in data:
            store.set_setting("vt_enabled", "1" if data["vt_enabled"] else "0")
        if "vt_api_key" in data:
            v = (data["vt_api_key"] or "").strip()
            if v == "__CLEAR__":
                store.set_setting("vt_api_key", "")
            elif v:
                store.set_setting("vt_api_key", v)
        if "interval_hours" in data and runner.last_run_ts:
            runner._schedule_next()
        runner.reset_vt_limiter()
        return jsonify({"ok": True})

    @app.route("/api/history/<domain>")
    def api_history(domain):
        with store.connect() as c:
            rows = c.execute(
                "SELECT ts,status,code FROM history WHERE domain=? "
                "ORDER BY ts DESC LIMIT 100",
                (domain,),
            ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/api/export")
    def api_export():
        with store.connect() as c:
            rows = c.execute(
                """SELECT domain,status,code,title,prev_status,is_new,last_checked,
                          ip,vt_verdict,vt_malicious,vt_suspicious,vt_harmless,vt_undetected,
                          vt_reputation,vt_error,vt_checked_at
                   FROM domains ORDER BY vt_verdict DESC, status, domain"""
            ).fetchall()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([
            "domain", "status", "http_code", "title", "previous_status", "newly_active",
            "last_checked", "ip", "vt_verdict", "vt_malicious", "vt_suspicious",
            "vt_harmless", "vt_undetected", "vt_reputation", "vt_error", "vt_checked_at",
        ])
        for r in rows:
            lc = datetime.fromtimestamp(r["last_checked"] / 1000, tz=timezone.utc).isoformat() if r["last_checked"] else ""
            vc = datetime.fromtimestamp(r["vt_checked_at"] / 1000, tz=timezone.utc).isoformat() if r["vt_checked_at"] else ""
            w.writerow([
                r["domain"], r["status"], r["code"] or "", r["title"] or "",
                r["prev_status"] or "", "YES" if r["is_new"] else "", lc,
                r["ip"] or "", r["vt_verdict"] or "", r["vt_malicious"] or "",
                r["vt_suspicious"] or "", r["vt_harmless"] or "", r["vt_undetected"] or "",
                r["vt_reputation"] if r["vt_reputation"] is not None else "",
                r["vt_error"] or "", vc,
            ])
        mem = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
        mem.seek(0)
        return send_file(
            mem,
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"domain-monitor-{datetime.now().strftime('%Y%m%d-%H%M')}.csv",
        )


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------
def run_server(
    host: str = "127.0.0.1",
    port: int = 5000,
    data_dir: Path | str | None = None,
    debug: bool = False,
) -> None:
    """Build the app and start the Flask development server."""
    app = create_app(data_dir=data_dir)
    try:
        app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
