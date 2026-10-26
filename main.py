#!/usr/bin/env python3
r"""
Telegram Broadcast Manager  -  single file, consent-based, restart-safe
=======================================================================

WHAT IT IS
  A CLI + Telegram-bot dashboard that sends messages from YOUR Telegram user
  account (Telethon) to recipients who explicitly consented. The bot (a normal
  BotFather bot) is only the admin control panel. Everything (config, drafts,
  recipients, consent/opt-out, jobs, progress, errors) persists in SQLite;
  secrets and the Telethon session live in an encrypted vault file.

WHAT IT DELIBERATELY DOES NOT DO
  No scraping, no adding people to groups, no account/proxy rotation, no
  randomized "human" delays, no evasion of Telegram limits. Only recipients with
  consent=granted and not opted out are ever messaged. A fixed, configurable
  delay is used; FloodWait is honoured; PeerFlood halts the job for human review.

REQUIREMENTS
  Python 3.11+  |  pip packages: telethon, cryptography   (see requirements.txt)

INSTALL
  Linux / macOS:
      python3 -m venv .venv && source .venv/bin/activate
      pip install -r requirements.txt
  Windows (PowerShell):
      py -3.11 -m venv .venv ; .venv\Scripts\Activate.ps1
      pip install -r requirements.txt
  Generate repo files once:   python telegram_manager.py --init-files

BEFORE FIRST RUN (get 3 things)
  1. Bot token:    Telegram -> @BotFather -> /newbot -> copy the token.
  2. API ID/hash:  https://my.telegram.org -> API development tools.
  3. Your numeric Telegram user ID (e.g. via @userinfobot) = the administrator.

COMMANDS
  python telegram_manager.py --setup        first-run wizard (also: runs on first start)
  python telegram_manager.py                start the manager + bot (Ctrl+C or dashboard
                                            "Shutdown" stops it cleanly)
  python telegram_manager.py --login        (re)authenticate the user account in the CLI:
                                            login code + 2FA are typed here, hidden, never
                                            sent through any chat and never logged
  python telegram_manager.py --status       safe status (no secrets, no passphrase needed)
  python telegram_manager.py --backup       zip: consistent DB copy + config + encrypted vault
  python telegram_manager.py --restore F.zip  validate then restore (app must be stopped)
  python telegram_manager.py --rotate       rotate bot token / API creds / vault passphrase
  python telegram_manager.py --selftest     run the built-in unit tests (no network)
  Options: --data-dir PATH (default ./data, or env TGM_DATA).
  Headless/service use: set env TGM_PASSPHRASE (otherwise you are prompted).

DASHBOARD
  Open your bot in Telegram, send /start. Only IDs in the admin allowlist get a
  response; everyone else is silently ignored. Typical flow:
  Recipients -> import CSV  ->  Composer -> set text / preview / test-send ->
  "Create job" -> job page shows preview + workload -> Start (confirm) -> Live Progress.
  CSV columns:  user (numeric ID or @username, required), consent (yes/no),
  source, consent_ts.  Rows without consent=yes are stored but never messaged.
  Opt-out: /optout <id or @user> in the bot, or the recipient replies STOP to your
  account (handled automatically). Opt-outs survive re-imports.
  Formatting: choose plain / markdown / html in Composer and type the markup literally
  (e.g. **bold** or <b>bold</b>). Media: send a file in "attach media" mode.

JOB STATES
  draft -> validating -> awaiting_confirmation -> running <-> paused,
  waiting_telegram, completed, completed_errors, cancelled, failed.

RECOVERY / RESTART
  Every recipient result is its own committed transaction. Before each send the
  row is marked 'sending'. After a crash, 'sending' rows become 'uncertain' (the
  request may or may not have been delivered), the job becomes 'paused' with
  review_required, and NOTHING restarts automatically. You review and press Resume
  (or Retry, which warns about possible duplicates). Exactly-once delivery is NOT
  guaranteed and is not claimed: a crash between Telegram accepting a message and
  the DB commit is unavoidable. FloodWait jobs auto-continue after the wait expires;
  PeerFlood / auth / unknown errors never auto-resume.

SECURITY MODEL
  * Vault (data/vault.enc): bot token, API hash, session string, phone, encrypted with
    Fernet; key from scrypt(passphrase). Passphrase is never stored; losing it =
    re-run --setup. Keep it in a password manager, NOT in the repo.
  * Secrets are masked in output and scrubbed from logs (exact-value + pattern filter).
  * POSIX permissions are tightened to 0600/0700 at every start (git clone resets them).
    Windows does not enforce this - rely on a private user profile / disk encryption.
  * Admin allowlist; confirmations before start, cancel, retry, resume, disconnect,
    shutdown, test-send, job creation.
  * Credential rotation: --rotate. Also revoke the old token in @BotFather (/revoke) and
    terminate old sessions in Telegram > Settings > Devices.
  Limitation: no OS keychain integration (keeps dependencies minimal).

PUSHING TO A PRIVATE GIT REPO AND CLONING ON ANOTHER DEVICE
  --init-files writes .gitignore. Tracked on purpose: data/config.json, data/vault.enc
  (encrypted), data/app.db (single-file SQLite; journal mode DELETE), data/media/.
  Ignored: logs, backups, reports, lock files, *.session, .env.
  New device:  git clone ... && pip install -r requirements.txt && python telegram_manager.py
  -> enter your passphrase; config, drafts, templates, recipients, jobs, progress and
  the account session load as they were. Rules:
    1. Commit/push only after a CLEAN shutdown; pull before you start.
    2. Never run two devices at once: the DB cannot merge, and Telegram may kill a
       session used from two places (AuthKeyDuplicatedError).
    3. app.db contains recipient IDs (personal data). Private repo + encrypted vault is
       reasonable, but if you prefer, uncomment `data/app.db` in .gitignore and move it
       between devices with --backup / --restore instead.
    4. The vault is only as strong as your passphrase if the repo ever leaks: use a long one.

LIMITATIONS
  * Telethon can message a numeric user ID only if the account has seen that user
    (access hash in session); otherwise the recipient fails as invalid_recipient. Prefer
    @usernames or people who have chatted with the account.
  * The data directory is chosen with --data-dir (needed to find config.json).
  * Restore is CLI-only by design (it replaces the DB the running app has open).
  * Network/server errors mark a recipient 'uncertain', not 'failed', and 3 in a row
    pause the job; there is no blind automatic re-send.

TROUBLESHOOTING
  "Wrong passphrase or corrupted vault"   passphrase typo, or vault file damaged -> restore backup.
  "Another instance is running"           stop the other process/device; the OS lock frees on exit.
  Bot silent                              your user ID not in admins (config.json) or wrong token.
  Account: NOT AUTHORIZED                 run --login.
  ApiIdInvalid                            wrong API ID/hash -> --rotate (option 2) then --login.
  Job paused, review required             read Error Reports; for PeerFlood check @SpamBot first.
  invalid_recipient everywhere            use @usernames or users known to the account.
  Windows ANSI/emoji glitches             use Windows Terminal.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import getpass
import io
import json
import logging
import logging.handlers
import os
import re
import secrets as pysecrets
import signal
import sqlite3
import stat
import sys
import tempfile
import time
import traceback
import unittest
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from telethon import Button, TelegramClient, errors, events
    from telethon.extensions import html as tl_html
    from telethon.extensions import markdown as tl_md
    from telethon.sessions import StringSession
except ImportError as _e:  # pragma: no cover
    sys.exit(f"Missing dependency ({_e.name}). Run: pip install -r requirements.txt")

VERSION = "1.0.0"
log = logging.getLogger("tgm")


class AppError(Exception):
    """User-facing, already-sanitized error."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ───────────────────────────── security helpers ─────────────────────────────
def mask(s: str) -> str:
    return ("…" + s[-4:]) if s and len(s) > 8 else "****"


class Redactor(logging.Filter):
    secrets: set[str] = set()
    PATTERNS = [re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), re.compile(r"\b[0-9a-fA-F]{32}\b")]

    @classmethod
    def clean(cls, text: str) -> str:
        for s in cls.secrets:
            if s and len(s) >= 4:
                text = text.replace(s, "***")
        for p in cls.PATTERNS:
            text = p.sub("[redacted]", text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg, record.args = self.clean(record.getMessage()), ()
        if record.exc_info:
            record.exc_text = self.clean("".join(traceback.format_exception(*record.exc_info)))
        return True


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(tmp, mode)
    except OSError:
        pass
    os.replace(tmp, path)


class Vault:
    MAGIC = b"TGM1"

    def __init__(self, path: Path):
        self.path = Path(path)

    @staticmethod
    def _key(pw: str, salt: bytes) -> bytes:
        return base64.urlsafe_b64encode(Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(pw.encode()))

    def exists(self) -> bool:
        return self.path.exists()

    def load(self, pw: str) -> dict:
        raw = self.path.read_bytes()
        if raw[:4] != self.MAGIC:
            raise AppError("Vault file is not recognised (corrupted?).")
        try:
            return json.loads(Fernet(self._key(pw, raw[4:20])).decrypt(raw[20:]))
        except InvalidToken:
            raise AppError("Wrong passphrase or corrupted vault.") from None

    def save(self, pw: str, data: dict) -> None:
        salt = os.urandom(16)
        token = Fernet(self._key(pw, salt)).encrypt(json.dumps(data).encode())
        atomic_write(self.path, self.MAGIC + salt + token)


def get_passphrase(confirm: bool = False) -> str:
    env = os.environ.get("TGM_PASSPHRASE")
    if env:
        return env
    if not confirm:
        return getpass.getpass("Vault passphrase (hidden): ")
    while True:
        a = getpass.getpass("Choose vault passphrase (min 12 chars, hidden): ")
        if len(a) < 12:
            print("  ✗ Too short.")
        elif getpass.getpass("Repeat passphrase: ") != a:
            print("  ✗ Does not match.")
        else:
            return a


class InstanceLock:
    """OS-level exclusive lock; released automatically if the process dies."""

    def __init__(self, path: Path):
        self.path, self.f = Path(path), None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(self.path, "a+")
        try:
            if os.name == "nt":
                import msvcrt
                self.f.seek(0)
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.f.close()
            self.f = None
            raise AppError("Another instance is running on this data directory.") from None

    def release(self) -> None:
        if self.f:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.f.seek(0)
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            self.f.close()
            self.f = None


# ───────────────────────────── validation ─────────────────────────────
def norm_ref(s: str) -> str | None:
    s = (s or "").strip()
    if re.fullmatch(r"\d{3,15}", s):
        return s
    m = re.fullmatch(r"@?([A-Za-z][A-Za-z0-9_]{4,31})", s)
    return "@" + m.group(1).lower() if m else None


class V:
    @staticmethod
    def token(s):
        s = s.strip()
        if not re.fullmatch(r"\d{6,12}:[A-Za-z0-9_-]{30,}", s):
            raise ValueError("Bot token looks wrong (expected 123456:ABC… from @BotFather).")
        return s

    @staticmethod
    def api_id(s):
        if not s.strip().isdigit() or int(s) <= 0:
            raise ValueError("API ID must be a positive number.")
        return int(s)

    @staticmethod
    def api_hash(s):
        s = s.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", s):
            raise ValueError("API hash must be 32 hex characters.")
        return s

    @staticmethod
    def phone(s):
        s = re.sub(r"[ \-()]", "", s)
        if not re.fullmatch(r"\+\d{7,15}", s):
            raise ValueError("Use international format, e.g. +491701234567.")
        return s

    @staticmethod
    def admins(s):
        try:
            ids = [int(x) for x in s.replace(" ", "").split(",") if x]
        except ValueError:
            raise ValueError("Comma-separated numeric user IDs only.") from None
        if not ids or any(i <= 0 for i in ids):
            raise ValueError("Provide at least one positive numeric user ID.")
        return ids

    @staticmethod
    def level(s):
        s = s.strip().upper()
        if s not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
            raise ValueError("One of DEBUG, INFO, WARNING, ERROR.")
        return s

    @staticmethod
    def delay(s):
        try:
            v = float(s)
        except ValueError:
            raise ValueError("Enter a number of seconds.") from None
        if not 1 <= v <= 3600:
            raise ValueError("Between 1 and 3600 seconds.")
        return v

    @staticmethod
    def posint(lo, hi):
        def f(s):
            if not str(s).strip().isdigit() or not lo <= int(s) <= hi:
                raise ValueError(f"Integer between {lo} and {hi}.")
            return int(s)
        return f

    @staticmethod
    def mode(s):
        s = s.strip().lower()
        if s not in ("plain", "markdown", "html"):
            raise ValueError("plain, markdown or html.")
        return s

    @staticmethod
    def optref(s):
        if not s.strip():
            return ""
        r = norm_ref(s)
        if not r:
            raise ValueError("Numeric ID or @username (min 5 chars).")
        return r

    @staticmethod
    def yn(s):
        if s.strip().lower() not in ("y", "yes", "n", "no"):
            raise ValueError("y or n.")
        return s.strip().lower().startswith("y")

    @staticmethod
    def path(s):
        if not s.strip():
            raise ValueError("Path required.")
        return s.strip()


# ───────────────────────────── config ─────────────────────────────
DEFAULTS = {
    "admins": [], "log_level": "INFO", "delay_seconds": 3.0, "parse_mode": "plain",
    "test_recipient": "", "db_path": "app.db", "vault_path": "vault.enc", "backup_dir": "backups",
    "backup_keep": 10, "backup_auto": True, "log_retention_days": 30, "error_retention_days": 90,
    "live_refresh_seconds": 10,
}


class Config:
    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.path = self.dir / "config.json"
        self.v = dict(DEFAULTS)

    def load(self):
        if not self.path.exists():
            raise AppError("Not configured yet. Run with --setup.")
        self.v.update(json.loads(self.path.read_text("utf-8")))
        return self

    def save(self):
        atomic_write(self.path, json.dumps(self.v, indent=2, sort_keys=True).encode())

    def get(self, k):
        return self.v[k]

    def p(self, key: str) -> Path:
        p = Path(self.v[key])
        return p if p.is_absolute() else self.dir / p


def harden(cfg: Config) -> list[str]:
    if os.name == "nt":
        return ["Windows: file permissions are not enforced; keep the data dir in a private profile."]
    out = []
    for p in (cfg.dir, cfg.path, cfg.p("vault_path"), cfg.p("db_path")):
        if p.exists():
            want = 0o700 if p.is_dir() else 0o600
            if stat.S_IMODE(p.stat().st_mode) & 0o077:
                os.chmod(p, want)
                out.append(f"tightened permissions on {p.name}")
    return out


def setup_logging(cfg: Config) -> None:
    logdir = cfg.dir / "logs"
    logdir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(cfg.get("log_level"))
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    fh = logging.handlers.RotatingFileHandler(logdir / "manager.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    for h in (logging.StreamHandler(), fh):
        h.setFormatter(fmt)
        h.addFilter(Redactor())
        root.addHandler(h)
    logging.getLogger("telethon").setLevel(logging.WARNING)


# ───────────────────────────── database ─────────────────────────────
MIGRATIONS = [
    """
    CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE recipients(
        ref TEXT PRIMARY KEY, consent TEXT NOT NULL DEFAULT 'unknown', consent_source TEXT, consent_ts TEXT,
        opted_out INTEGER NOT NULL DEFAULT 0, opted_out_ts TEXT, last_success TEXT, last_error TEXT);
    CREATE INDEX idx_rec_elig ON recipients(consent, opted_out);
    CREATE TABLE templates(name TEXT PRIMARY KEY, body TEXT NOT NULL, parse_mode TEXT NOT NULL, media_path TEXT, updated TEXT);
    CREATE TABLE jobs(
        id TEXT PRIMARY KEY, created TEXT, template_name TEXT, list_ref TEXT DEFAULT 'all-consented',
        body TEXT, parse_mode TEXT, media_path TEXT, status TEXT NOT NULL, started TEXT, last_activity TEXT,
        error_category TEXT, next_run TEXT, scheduled_at TEXT, confirmed INTEGER NOT NULL DEFAULT 0,
        review_required INTEGER NOT NULL DEFAULT 0, note TEXT, claimed_by TEXT);
    CREATE INDEX idx_jobs_status ON jobs(status);
    CREATE TABLE job_recipients(
        job_id TEXT NOT NULL, ref TEXT NOT NULL, state TEXT NOT NULL, error_class TEXT,
        retryable INTEGER NOT NULL DEFAULT 0, attempted TEXT,
        PRIMARY KEY(job_id, ref), FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE);
    CREATE INDEX idx_jr_state ON job_recipients(job_id, state);
    CREATE TABLE errors(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, job_id TEXT, cls TEXT, detail TEXT, action TEXT);
    CREATE INDEX idx_err_ts ON errors(ts);
    """,
]


class DB:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=DELETE")  # single file -> git/backup friendly
        self.conn.execute("PRAGMA synchronous=FULL")
        self.migrate()

    def migrate(self):
        v = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if v > len(MIGRATIONS):
            raise AppError("Database is newer than this program version.")
        for i, script in enumerate(MIGRATIONS[v:], start=v + 1):
            self.conn.executescript(f"BEGIN;{script}PRAGMA user_version={i};COMMIT;")

    @contextmanager
    def tx(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def q(self, sql, a=()):
        return self.conn.execute(sql, a).fetchall()

    def one(self, sql, a=()):
        return self.conn.execute(sql, a).fetchone()

    def run(self, sql, a=()):
        return self.conn.execute(sql, a)

    def meta(self, k, default=None):
        r = self.one("SELECT value FROM meta WHERE key=?", (k,))
        return json.loads(r["value"]) if r else default

    def set_meta(self, k, v):
        self.run("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, json.dumps(v)))

    def integrity(self) -> str:
        return self.one("PRAGMA integrity_check")[0]

    def close(self):
        try:
            self.conn.close()
        except sqlite3.Error:
            pass


# ───────────────────────────── recipients ─────────────────────────────
GRANT = {"yes", "y", "true", "1", "granted", "consent"}
DENY = {"no", "n", "false", "0", "revoked", "denied"}


class Recipients:
    def __init__(self, db: DB):
        self.db = db

    def eligible(self) -> list[str]:
        return [r["ref"] for r in self.db.q("SELECT ref FROM recipients WHERE consent='granted' AND opted_out=0 ORDER BY ref")]

    def stats(self) -> dict:
        r = self.db.one("""SELECT COUNT(*) total, SUM(consent='granted' AND opted_out=0) eligible,
                           SUM(opted_out=1) optout, SUM(consent='unknown') unknown FROM recipients""")
        return {k: (r[k] or 0) for k in r.keys()}

    def import_csv(self, text: str, default_source: str = "csv-import") -> dict:
        rd = csv.DictReader(io.StringIO(text))
        if not rd.fieldnames:
            raise AppError("Empty CSV.")
        cols = {c.strip().lower(): c for c in rd.fieldnames if c}
        key = next((cols[k] for k in ("user", "user_id", "username", "ref") if k in cols), None)
        if not key:
            raise AppError("CSV needs a 'user' column (numeric ID or @username).")
        rep = {"added": 0, "updated": 0, "malformed": [], "duplicates": [], "missing": [], "no_consent": 0}
        seen: set[str] = set()
        with self.db.tx() as c:
            for i, row in enumerate(rd, start=2):
                raw = (row.get(key) or "").strip()
                if not raw:
                    rep["missing"].append(i)
                    continue
                ref = norm_ref(raw)
                if not ref:
                    rep["malformed"].append(i)
                    continue
                if ref in seen:
                    rep["duplicates"].append(i)
                    continue
                seen.add(ref)
                cv = (row.get(cols.get("consent", ""), "") or "").strip().lower()
                consent = "granted" if cv in GRANT else "revoked" if cv in DENY else "unknown"
                if consent != "granted":
                    rep["no_consent"] += 1
                src = (row.get(cols.get("source", ""), "") or "").strip() or default_source
                ts = (row.get(cols.get("consent_ts", ""), "") or "").strip() or None
                existed = c.execute("SELECT 1 FROM recipients WHERE ref=?", (ref,)).fetchone()
                c.execute("""INSERT INTO recipients(ref,consent,consent_source,consent_ts) VALUES(?,?,?,?)
                             ON CONFLICT(ref) DO UPDATE SET consent=excluded.consent,
                             consent_source=excluded.consent_source, consent_ts=excluded.consent_ts""",
                          (ref, consent, src, ts))
                rep["updated" if existed else "added"] += 1
        return rep

    @staticmethod
    def report_text(rep: dict) -> str:
        def lines(k):
            v = rep[k]
            return f"{len(v)} (rows {', '.join(map(str, v[:10]))}{'…' if len(v) > 10 else ''})" if v else "0"
        return (f"Import finished.\nAdded: {rep['added']}  Updated: {rep['updated']}\n"
                f"Without granted consent (stored, never messaged): {rep['no_consent']}\n"
                f"Malformed: {lines('malformed')}\nDuplicates in file: {lines('duplicates')}\n"
                f"Missing user field: {lines('missing')}")

    def opt_out(self, refs: list[str]) -> int:
        n = 0
        with self.db.tx() as c:
            for r in refs:
                ref = norm_ref(r)
                if ref:
                    c.execute("""INSERT INTO recipients(ref,consent,opted_out,opted_out_ts) VALUES(?, 'revoked',1,?)
                                 ON CONFLICT(ref) DO UPDATE SET opted_out=1, opted_out_ts=excluded.opted_out_ts""", (ref, now()))
                    n += 1
        return n


# ───────────────────────────── composer ─────────────────────────────
class Composer:
    def __init__(self, db: DB, cfg: Config):
        self.db, self.cfg = db, cfg

    def draft(self) -> dict:
        return self.db.meta("draft") or {"body": "", "mode": self.cfg.get("parse_mode"), "media": None}

    def save_draft(self, d: dict):
        self.db.set_meta("draft", d)

    @staticmethod
    def plain_len(body: str, mode: str) -> int:
        if mode == "html":
            return len(tl_html.parse(body)[0])
        if mode == "markdown":
            return len(tl_md.parse(body)[0])
        return len(body)

    def validate(self, d: dict) -> list[str]:
        probs = []
        body = (d.get("body") or "").strip()
        if not body:
            probs.append("Message is empty.")
        try:
            n = self.plain_len(body, d.get("mode", "plain"))
        except Exception:
            n, _ = len(body), probs.append("Formatting could not be parsed.")
        limit = 1024 if d.get("media") else 4096
        if n > limit:
            probs.append(f"Message is {n} characters; limit is {limit}{' with media caption' if d.get('media') else ''}.")
        if d.get("media") and not (self.cfg.dir / d["media"]).exists():
            probs.append("Attached media file is missing.")
        return probs

    def templates(self):
        return self.db.q("SELECT * FROM templates ORDER BY name")

    def save_template(self, name: str, d: dict):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,20}", name):
            raise AppError("Template name: 1-20 letters, digits, _ or -.")
        if self.validate(d):
            raise AppError("Fix draft problems first: " + " ".join(self.validate(d)))
        self.db.run("""INSERT INTO templates(name,body,parse_mode,media_path,updated) VALUES(?,?,?,?,?)
                       ON CONFLICT(name) DO UPDATE SET body=excluded.body, parse_mode=excluded.parse_mode,
                       media_path=excluded.media_path, updated=excluded.updated""",
                    (name, d["body"], d["mode"], d.get("media"), now()))

    def load_template(self, name: str):
        r = self.db.one("SELECT * FROM templates WHERE name=?", (name,))
        if not r:
            raise AppError("Template not found.")
        self.save_draft({"body": r["body"], "mode": r["parse_mode"], "media": r["media_path"]})


# ───────────────────────────── errors ─────────────────────────────
@dataclass
class Outcome:
    kind: str  # ok | recipient | flood | halt | auth | network | unknown
    cls: str = ""
    wait: int = 0
    action: str = ""


RECIPIENT_ERR = {"UserPrivacyRestrictedError", "InputUserDeactivatedError", "UserIsBlockedError", "ChatWriteForbiddenError",
                 "UsernameNotOccupiedError", "UsernameInvalidError", "PeerIdInvalidError", "UserIdInvalidError"}
AUTH_ERR = {"AuthKeyUnregisteredError", "SessionRevokedError", "SessionExpiredError", "UserDeactivatedError",
            "UserDeactivatedBanError", "AuthKeyDuplicatedError", "ApiIdInvalidError", "SessionPasswordNeededError",
            "PhoneCodeInvalidError", "AccountNotReady"}


def classify(e: BaseException) -> Outcome:
    names = {c.__name__ for c in type(e).__mro__}
    if "FloodWaitError" in names:
        s = int(getattr(e, "seconds", 0) or 0)
        return Outcome("flood", "FloodWaitError", s, f"Telegram requires waiting {s}s. Job resumes automatically afterwards.")
    if "PeerFloodError" in names:
        return Outcome("halt", "PeerFloodError", 0, "Possible spam restriction. Check @SpamBot, review consent and content, then resume manually.")
    if names & AUTH_ERR:
        c = sorted(names & AUTH_ERR)[0]
        return Outcome("auth", c, 0, "Account/authentication problem. Stop and run `--login` (or `--rotate`) in the CLI.")
    if names & RECIPIENT_ERR:
        c = sorted(names & RECIPIENT_ERR)[0]
        return Outcome("recipient", c, 0, "Recipient cannot be messaged; not retried.")
    if isinstance(e, (ValueError, TypeError)):
        return Outcome("recipient", "invalid_recipient", 0, "Recipient could not be resolved (unknown to the account or bad username).")
    if "ServerError" in names:
        return Outcome("network", "ServerError", 0, "Telegram server error; delivery uncertain. Review before retrying.")
    if isinstance(e, (FileNotFoundError, PermissionError)):
        return Outcome("halt", "FileError", 0, "Media/file access problem. Fix the file or permissions, then resume.")
    if isinstance(e, (ConnectionError, TimeoutError, OSError)):
        return Outcome("network", type(e).__name__, 0, "Network problem; delivery uncertain. Review before retrying.")
    return Outcome("unknown", type(e).__name__, 0, "Unexpected error; job halted for review (see logs).")


# ───────────────────────────── jobs ─────────────────────────────
TERMINAL = {"completed", "completed_errors", "cancelled", "failed"}
TRANSITIONS = {
    "draft": {"validating", "cancelled"},
    "validating": {"awaiting_confirmation", "failed", "cancelled"},
    "awaiting_confirmation": {"running", "cancelled"},
    "running": {"paused", "waiting_telegram", "completed", "completed_errors", "cancelled", "failed"},
    "paused": {"running", "cancelled", "failed"},
    "waiting_telegram": {"running", "paused", "cancelled"},
    "completed_errors": {"running"},
}
LABEL = {"draft": "Draft", "validating": "Validating", "awaiting_confirmation": "Awaiting Confirmation", "running": "Running",
         "paused": "Paused", "waiting_telegram": "Waiting for Telegram", "completed": "Completed",
         "completed_errors": "Completed with Errors", "cancelled": "Cancelled", "failed": "Failed"}


class Jobs:
    def __init__(self, db: DB, cfg: Config, send):
        self.db, self.cfg, self.send = db, cfg, send
        self.task: asyncio.Task | None = None
        self.wake = asyncio.Event()
        self.owner = f"pid{os.getpid()}"

    # --- basics
    def new_id(self) -> str:
        y = datetime.now().year
        n = self.db.one("SELECT COUNT(*) c FROM jobs WHERE id LIKE ?", (f"JOB-{y}-%",))["c"] + 1
        return f"JOB-{y}-{n:03d}"

    def get(self, jid):
        r = self.db.one("SELECT * FROM jobs WHERE id=?", (jid,))
        if not r:
            raise AppError("Job not found.")
        return r

    def running(self) -> bool:
        return bool(self.task and not self.task.done())

    def set_status(self, jid, new, **f):
        with self.db.tx() as c:
            cur = c.execute("SELECT status FROM jobs WHERE id=?", (jid,)).fetchone()
            if not cur:
                raise AppError("Job not found.")
            if new != cur["status"] and new not in TRANSITIONS.get(cur["status"], ()):
                raise AppError(f"Invalid transition {cur['status']} -> {new}.")
            f.update(status=new, last_activity=now())
            c.execute(f"UPDATE jobs SET {','.join(k + '=?' for k in f)} WHERE id=?", (*f.values(), jid))
        log.info("[%s] status -> %s", jid, new)

    def counts(self, jid) -> dict:
        c = {"pending": 0, "sending": 0, "sent": 0, "failed": 0, "skipped": 0, "uncertain": 0}
        for r in self.db.q("SELECT state, COUNT(*) n FROM job_recipients WHERE job_id=? GROUP BY state", (jid,)):
            c[r["state"]] = r["n"]
        c["total"] = sum(c.values())
        c["processed"] = c["sent"] + c["failed"] + c["skipped"] + c["uncertain"]
        c["remaining"] = c["pending"] + c["sending"]
        c["pct"] = c["processed"] * 100 // c["total"] if c["total"] else 0
        return c

    def progress_text(self, jid) -> str:
        j, c = self.get(jid), self.counts(jid)
        t = (f"Broadcast Job: {jid}\n\nStatus: {LABEL[j['status']]}\nEligible: {c['total']}\nProcessed: {c['processed']}\n"
             f"Successful: {c['sent']}\nFailed: {c['failed']}\nSkipped: {c['skipped']}\nUncertain: {c['uncertain']}\n"
             f"Remaining: {c['remaining']}\nProgress: {c['pct']}%\n\nStarted: {j['started'] or '-'}\nLast activity: {j['last_activity'] or '-'}")
        if j["error_category"]:
            t += f"\nCurrent error: {j['error_category']}"
        if j["next_run"] and j["status"] == "waiting_telegram":
            t += f"\nTelegram wait until: {j['next_run']}"
        if j["scheduled_at"] and j["status"] == "awaiting_confirmation":
            t += f"\nScheduled for: {j['scheduled_at']} UTC"
        if j["review_required"]:
            t += "\n⚠️ Administrative review required before resuming."
        if j["note"]:
            t += f"\nNote: {j['note']}"
        return t

    def record_error(self, jid, cls, detail, action):
        self.db.run("INSERT INTO errors(ts,job_id,cls,detail,action) VALUES(?,?,?,?,?)",
                    (now(), jid, cls, Redactor.clean(str(detail))[:300], action))
        log.warning("[%s] %s: %s", jid, cls, Redactor.clean(str(detail))[:200])

    def mark(self, jid, ref, state, cls=None, retryable=0):
        with self.db.tx() as c:
            c.execute("UPDATE job_recipients SET state=?, error_class=?, retryable=?, attempted=? WHERE job_id=? AND ref=?",
                      (state, cls, retryable, now(), jid, ref))
            c.execute("UPDATE jobs SET last_activity=? WHERE id=?", (now(), jid))

    # --- lifecycle
    def create(self, draft: dict) -> str:
        probs = Composer(self.db, self.cfg).validate(draft)
        if probs:
            raise AppError(" ".join(probs))
        jid = self.new_id()
        self.db.run("INSERT INTO jobs(id,created,body,parse_mode,media_path,status,last_activity) VALUES(?,?,?,?,?,'draft',?)",
                    (jid, now(), draft["body"], draft["mode"], draft.get("media"), now()))
        self.set_status(jid, "validating")
        refs = Recipients(self.db).eligible()  # PK guarantees no duplicates; opted-out/no-consent excluded
        if not refs:
            self.set_status(jid, "failed", note="No eligible recipients (explicit consent required).", error_category="no_recipients")
            raise AppError(f"{jid}: no eligible recipients (explicit consent required).")
        with self.db.tx() as c:
            c.executemany("INSERT INTO job_recipients(job_id,ref,state) VALUES(?,?, 'pending')", [(jid, r) for r in refs])
        self.set_status(jid, "awaiting_confirmation")
        return jid

    def confirm(self, jid):
        if self.get(jid)["status"] != "awaiting_confirmation":
            raise AppError("Job is not awaiting confirmation.")
        self.db.run("UPDATE jobs SET confirmed=1 WHERE id=?", (jid,))

    def start(self, jid, ack_review=False):
        if self.running():
            raise AppError("Another job is already running.")
        j = self.get(jid)
        st = j["status"]
        if st not in ("awaiting_confirmation", "paused", "waiting_telegram", "completed_errors"):
            raise AppError(f"Cannot start a job in state '{LABEL.get(st, st)}'.")
        if st == "awaiting_confirmation" and not j["confirmed"]:
            raise AppError("Explicit confirmation required first.")
        if st == "waiting_telegram" and j["next_run"] and j["next_run"] > now():
            raise AppError(f"Telegram asked us to wait until {j['next_run']} UTC.")
        if j["review_required"] and not ack_review:
            raise AppError("Administrative review required (spam/account/auth issue).")
        if not self.db.one("SELECT 1 FROM job_recipients WHERE job_id=? AND state='pending'", (jid,)):
            raise AppError("Nothing pending to send.")
        with self.db.tx() as c:
            cur = c.execute("UPDATE jobs SET claimed_by=?, review_required=0 WHERE id=? AND (claimed_by IS NULL OR claimed_by=?)",
                            (self.owner, jid, self.owner))
            if cur.rowcount != 1:
                raise AppError("Job is claimed by another process.")
        self.task = asyncio.get_running_loop().create_task(self._run(jid))

    def pause(self, jid):
        if self.get(jid)["status"] in ("running", "waiting_telegram"):
            self.set_status(jid, "paused", note="Paused by administrator")
        self.wake.set()

    def cancel(self, jid):
        self.set_status(jid, "cancelled", note="Cancelled by administrator")
        with self.db.tx() as c:
            c.execute("UPDATE job_recipients SET state='skipped', error_class='cancelled' WHERE job_id=? AND state='pending'", (jid,))
        self.wake.set()

    def retry_failures(self, jid):
        j = self.get(jid)
        if self.running():
            raise AppError("Another job is already running.")
        if j["status"] not in ("completed_errors", "paused"):
            raise AppError("Retry is available for 'completed with errors' or paused jobs.")
        if j["review_required"]:
            raise AppError("Administrative review required first (use Resume after reviewing).")
        with self.db.tx() as c:
            n = c.execute("UPDATE job_recipients SET state='pending', error_class=NULL WHERE job_id=? AND retryable=1 AND state IN ('failed','uncertain')",
                          (jid,)).rowcount
        if n == 0:
            raise AppError("No retry-eligible failures (privacy/blocked/invalid recipients are never retried).")
        self.start(jid)

    async def stop(self, timeout=30):
        """Clean shutdown: stop new sends, let the in-flight one finish, persist."""
        if self.running():
            jid = self.task.get_name()
            try:
                if self.get(jid)["status"] == "running":
                    self.set_status(jid, "paused", note="Paused by application shutdown")
            except AppError:
                pass
            self.wake.set()
            try:
                await asyncio.wait_for(self.task, timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self.task.cancel()

    # --- the sending loop
    async def _run(self, jid):
        asyncio.current_task().set_name(jid)
        try:
            j = self.get(jid)
            self.set_status(jid, "running", started=j["started"] or now(), error_category=None, next_run=None, note=None)
            net_fail = 0
            while True:
                j = self.get(jid)
                if j["status"] != "running":
                    return
                row = self.db.one("SELECT ref FROM job_recipients WHERE job_id=? AND state='pending' ORDER BY rowid LIMIT 1", (jid,))
                if row is None:
                    c = self.counts(jid)
                    self.set_status(jid, "completed_errors" if c["failed"] + c["uncertain"] else "completed")
                    return
                ref = row["ref"]
                rec = self.db.one("SELECT consent, opted_out FROM recipients WHERE ref=?", (ref,))
                if not rec or rec["opted_out"] or rec["consent"] != "granted":
                    self.mark(jid, ref, "skipped", "ineligible")
                    continue
                self.mark(jid, ref, "sending")
                try:
                    await self.send(ref, j)
                    o = Outcome("ok")
                except Exception as e:  # CancelledError is BaseException: leaves 'sending' for recovery
                    o = classify(e)
                    err = e
                if o.kind == "ok":
                    self.mark(jid, ref, "sent")
                    self.db.run("UPDATE recipients SET last_success=?, last_error=NULL WHERE ref=?", (now(), ref))
                    net_fail = 0
                elif o.kind == "recipient":
                    self.mark(jid, ref, "failed", o.cls, 0)
                    self.db.run("UPDATE recipients SET last_error=? WHERE ref=?", (o.cls, ref))
                    self.record_error(jid, o.cls, err, o.action)
                    net_fail = 0
                elif o.kind in ("network", "unknown"):
                    self.mark(jid, ref, "uncertain", o.cls, 1)
                    self.db.run("UPDATE recipients SET last_error=? WHERE ref=?", (o.cls, ref))
                    self.record_error(jid, o.cls, err, o.action)
                    net_fail += 1
                    if o.kind == "unknown" or net_fail >= 3:
                        self.set_status(jid, "paused", review_required=1, error_category=o.cls, note=o.action)
                        return
                elif o.kind == "flood":
                    self.mark(jid, ref, "pending")  # request was rejected, nothing delivered
                    nxt = (datetime.now(timezone.utc) + timedelta(seconds=o.wait + 1)).isoformat(timespec="seconds")
                    self.record_error(jid, o.cls, f"wait {o.wait}s", o.action)
                    self.set_status(jid, "waiting_telegram", next_run=nxt, error_category=o.cls, note=o.action)
                    return
                else:  # halt / auth
                    self.mark(jid, ref, "pending")
                    self.record_error(jid, o.cls, err, o.action)
                    self.set_status(jid, "paused", review_required=1, error_category=o.cls, note=o.action)
                    return
                self.wake.clear()
                try:
                    await asyncio.wait_for(self.wake.wait(), timeout=self.cfg.get("delay_seconds"))
                except asyncio.TimeoutError:
                    pass
        except AppError as e:
            log.error("[%s] %s", jid, e)
        except Exception as e:
            log.exception("[%s] internal error", jid)
            try:
                self.set_status(jid, "paused", review_required=1, error_category="internal_error", note=f"Internal error: {type(e).__name__}")
            except Exception:
                pass
        finally:
            try:
                self.db.run("UPDATE jobs SET claimed_by=NULL WHERE id=?", (jid,))
            except sqlite3.Error:
                pass


def recover(db: DB) -> list[str]:
    """Classify interrupted work after a crash/unclean stop. Never restarts anything."""
    notes = []
    with db.tx() as c:
        n = c.execute("UPDATE job_recipients SET state='uncertain', retryable=1, error_class='interrupted' WHERE state='sending'").rowcount
        if n:
            notes.append(f"{n} delivery(ies) were in flight and are now 'uncertain'")
        for r in c.execute("SELECT id FROM jobs WHERE status='running'").fetchall():
            c.execute("UPDATE jobs SET status='paused', review_required=1, note='Interrupted (crash/unclean stop). Review, then Resume.' WHERE id=?", (r["id"],))
            notes.append(f"{r['id']} was interrupted -> paused for review")
        for r in c.execute("SELECT id FROM jobs WHERE status='validating'").fetchall():
            c.execute("UPDATE jobs SET status='failed', note='Interrupted during validation' WHERE id=?", (r["id"],))
        c.execute("UPDATE jobs SET claimed_by=NULL")
    return notes


# ───────────────────────────── reporting & backup ─────────────────────────────
def job_csv(db: DB, jid: str, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["job_id", "recipient", "state", "error_class", "retryable", "attempted_utc"])
        for r in db.q("SELECT * FROM job_recipients WHERE job_id=? ORDER BY rowid", (jid,)):
            w.writerow([jid, r["ref"], r["state"], r["error_class"] or "", r["retryable"], r["attempted"] or ""])
    return out


def errors_csv(db: DB, out: Path, jid: str | None = None) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = db.q("SELECT * FROM errors WHERE job_id=? ORDER BY id", (jid,)) if jid else db.q("SELECT * FROM errors ORDER BY id")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp_utc", "job_id", "class", "explanation", "recommended_action"])
        for r in rows:
            w.writerow([r["ts"], r["job_id"], r["cls"], r["detail"], r["action"]])
    return out


def daily_summary(db: DB) -> str:
    day = now()[:10]
    rows = db.q("SELECT state, COUNT(*) n FROM job_recipients WHERE attempted LIKE ? GROUP BY state", (day + "%",))
    d = {r["state"]: r["n"] for r in rows}
    e = db.one("SELECT COUNT(*) n FROM errors WHERE ts LIKE ?", (day + "%",))["n"]
    return f"Today (UTC {day}): sent {d.get('sent', 0)}, failed {d.get('failed', 0)}, uncertain {d.get('uncertain', 0)}, skipped {d.get('skipped', 0)}, error records {e}"


def maintenance(cfg: Config, db: DB):
    cutoff = time.time() - cfg.get("log_retention_days") * 86400
    for p in (cfg.dir / "logs").glob("*.log*"):
        if p.stat().st_mtime < cutoff:
            p.unlink(missing_ok=True)
    old = (datetime.now(timezone.utc) - timedelta(days=cfg.get("error_retention_days"))).isoformat(timespec="seconds")
    db.run("DELETE FROM errors WHERE ts<?", (old,))


class Backups:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def create(self) -> Path:
        d = self.cfg.p("backup_dir")
        d.mkdir(parents=True, exist_ok=True)
        name = d / f"backup-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.zip"
        with tempfile.TemporaryDirectory() as t:
            tmpdb = Path(t) / "app.db"
            src, dst = sqlite3.connect(self.cfg.p("db_path")), sqlite3.connect(tmpdb)
            src.backup(dst)
            dst.close()
            src.close()
            with zipfile.ZipFile(name, "w", zipfile.ZIP_DEFLATED) as z:
                z.write(tmpdb, "app.db")
                z.write(self.cfg.path, "config.json")
                if self.cfg.p("vault_path").exists():
                    z.write(self.cfg.p("vault_path"), "vault.enc")
        self.validate(name)
        try:
            os.chmod(name, 0o600)
        except OSError:
            pass
        for old in sorted(d.glob("backup-*.zip"))[:-self.cfg.get("backup_keep")]:
            old.unlink(missing_ok=True)
        return name

    @staticmethod
    def validate(path: Path):
        try:
            with zipfile.ZipFile(path) as z:
                if z.testzip():
                    raise AppError("Backup archive is corrupted.")
                if not {"app.db", "config.json"} <= set(z.namelist()):
                    raise AppError("Backup is missing app.db or config.json.")
                json.loads(z.read("config.json"))
                with tempfile.TemporaryDirectory() as t:
                    z.extract("app.db", t)
                    con = sqlite3.connect(Path(t) / "app.db")
                    ok = con.execute("PRAGMA integrity_check").fetchone()[0]
                    ver = con.execute("PRAGMA user_version").fetchone()[0]
                    con.close()
        except (zipfile.BadZipFile, json.JSONDecodeError, sqlite3.Error) as e:
            raise AppError(f"Backup invalid: {type(e).__name__}") from None
        if ok != "ok":
            raise AppError("Backup database failed integrity check.")
        if ver > len(MIGRATIONS):
            raise AppError("Backup was made by a newer program version.")

    def restore(self, path: Path):
        path = Path(path)
        self.validate(path)
        if self.cfg.p("db_path").exists():
            self.create()  # safety copy of current state
        with zipfile.ZipFile(path) as z:
            newcfg = Config(self.cfg.dir)
            newcfg.v.update(json.loads(z.read("config.json")))
            atomic_write(newcfg.p("db_path"), z.read("app.db"))
            Path(str(newcfg.p("db_path")) + "-journal").unlink(missing_ok=True)
            if "vault.enc" in z.namelist():
                atomic_write(newcfg.p("vault_path"), z.read("vault.enc"))
            atomic_write(newcfg.path, z.read("config.json"))


# ───────────────────────────── application ─────────────────────────────
class App:
    def __init__(self, cfg: Config, passphrase: str | None = None):
        self.cfg, self.passphrase = cfg, passphrase
        self.db = self.jobs = self.user = self.bot = self.dash = self.lock = self.vault = None
        self.user_ok = False
        self.sec: dict = {}
        self.sched_task = None
        self.stop_event: asyncio.Event | None = None

    def request_shutdown(self):
        if self.stop_event:
            self.stop_event.set()

    def abs_media(self, rel):
        return str(self.cfg.dir / rel)

    async def send(self, ref: str, job):
        if not self.user_ok:
            raise type("AccountNotReady", (Exception,), {})("user account is not authorized")
        kw = {"parse_mode": {"plain": None, "markdown": "md", "html": "html"}[job["parse_mode"]]}
        target = int(ref) if ref.isdigit() else ref
        if job["media_path"]:
            coro = self.user.send_file(target, self.abs_media(job["media_path"]), caption=job["body"], **kw)
        else:
            coro = self.user.send_message(target, job["body"], link_preview=False, **kw)
        await asyncio.wait_for(coro, 60)

    def save_vault_if_changed(self):
        changed = False
        for key, client in (("session", self.user), ("bot_session", self.bot)):
            if client is not None:
                s = client.session.save()
                if s and s != self.sec.get(key):
                    self.sec[key], changed = s, True
        if changed:
            self.vault.save(self.passphrase, self.sec)

    async def start_user(self):
        self.user = TelegramClient(StringSession(self.sec.get("session", "")), int(self.sec["api_id"]), self.sec["api_hash"])
        try:
            await self.user.connect()
            self.user_ok = await self.user.is_user_authorized()
        except Exception as e:
            log.error("User client failed to connect: %s", type(e).__name__)
        if not self.user_ok:
            log.warning("User account NOT AUTHORIZED - run `--login`. Sending is disabled.")
        db = self.db

        @self.user.on(events.NewMessage(incoming=True, func=lambda e: e.is_private))
        async def _optout(ev):  # recipients can unsubscribe by replying STOP
            if (ev.raw_text or "").strip().lower() not in {"stop", "unsubscribe", "/stop"}:
                return
            s = await ev.get_sender()
            ids = [str(ev.sender_id)] + (["@" + s.username.lower()] if getattr(s, "username", None) else [])
            Recipients(db).opt_out(ids)
            log.info("Opt-out recorded for %s", ids[0])
            await ev.respond("You have been unsubscribed and will not receive further messages.")

    async def start_bot(self):
        self.bot = TelegramClient(StringSession(self.sec.get("bot_session", "")), int(self.sec["api_id"]), self.sec["api_hash"])
        self.bot.parse_mode = None
        await self.bot.start(bot_token=self.sec["bot_token"])
        self.dash = Dashboard(self)
        self.dash.attach(self.bot)
        me = await self.bot.get_me()
        log.info("Dashboard bot ready: @%s - open it in Telegram and send /start", me.username)
        self.save_vault_if_changed()

    async def scheduler(self):
        last_maint = 0.0
        while not self.stop_event.is_set():
            try:
                if not self.jobs.running() and self.user_ok:
                    due = self.db.one("SELECT id FROM jobs WHERE status='waiting_telegram' AND review_required=0 AND next_run<=? ORDER BY created LIMIT 1", (now(),))
                    kind = "resume after Telegram wait"
                    if not due:
                        due = self.db.one("SELECT id FROM jobs WHERE status='awaiting_confirmation' AND confirmed=1 AND scheduled_at<=? ORDER BY scheduled_at LIMIT 1", (now(),))
                        kind = "scheduled start"
                    if due:
                        log.info("[%s] %s", due["id"], kind)
                        try:
                            self.jobs.start(due["id"])
                        except AppError as e:
                            self.db.run("UPDATE jobs SET scheduled_at=NULL, note=? WHERE id=?", (f"Auto-start failed: {e}", due["id"]))
                if time.monotonic() - last_maint > 86400:
                    maintenance(self.cfg, self.db)
                    last_maint = time.monotonic()
            except Exception:
                log.exception("scheduler error")
            try:
                await asyncio.wait_for(self.stop_event.wait(), 5)
            except asyncio.TimeoutError:
                pass

    async def run(self):
        self.stop_event = asyncio.Event()
        self.lock = InstanceLock(self.cfg.dir / ".instance.lock")
        self.lock.acquire()
        try:
            for w in harden(self.cfg):
                print("security:", w)
            setup_logging(self.cfg)
            self.vault = Vault(self.cfg.p("vault_path"))
            if not self.vault.exists():
                raise AppError("Vault missing. Run --setup.")
            self.passphrase = self.passphrase or get_passphrase()
            self.sec = self.vault.load(self.passphrase)
            Redactor.secrets |= {str(self.sec.get(k, "")) for k in ("bot_token", "api_hash", "session", "bot_session")}
            self.db = DB(self.cfg.p("db_path"))
            prev = self.db.meta("last_shutdown")
            if prev and not prev.get("clean"):
                log.warning("Previous run did not shut down cleanly (%s).", prev.get("ts"))
            self.db.set_meta("last_shutdown", {"clean": False, "ts": now()})
            for n in recover(self.db):
                log.warning("Recovery: %s", n)
            maintenance(self.cfg, self.db)
            self.jobs = Jobs(self.db, self.cfg, self.send)
            await self.start_user()
            await self.start_bot()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, self.stop_event.set)
                except (NotImplementedError, RuntimeError, ValueError):
                    pass
            self.sched_task = asyncio.create_task(self.scheduler())
            log.info("Running. Stop with Ctrl+C or the dashboard's Shutdown button.")
            await self.stop_event.wait()
        finally:
            await self.shutdown()
            self.lock.release()

    async def shutdown(self):
        log.info("Shutting down…")
        if self.sched_task:
            self.sched_task.cancel()
        if self.dash:
            self.dash.cancel_live()
        if self.jobs:
            await self.jobs.stop()
        if self.db:
            try:
                self.save_vault_if_changed()
            except Exception:
                log.exception("could not persist session")
            self.db.set_meta("last_shutdown", {"clean": True, "ts": now()})
            if self.cfg.get("backup_auto"):
                try:
                    log.info("Auto-backup: %s", Backups(self.cfg).create().name)
                except Exception as e:
                    log.error("Auto-backup failed: %s", type(e).__name__)
        for c in (self.bot, self.user):
            if c:
                try:
                    await c.disconnect()
                except Exception:
                    pass
        if self.db:
            self.db.close()


# ───────────────────────────── bot dashboard ─────────────────────────────
MENU = [("📡 Account", "acct"), ("⚙️ Configure", "cfg"), ("✍️ Composer", "comp"), ("👥 Recipients", "rec"),
        ("📦 Jobs", "jobs"), ("📈 Live Progress", "live"), ("🧯 Error Reports", "err"), ("🗂 Templates", "tpl"),
        ("🕒 Scheduling", "sch"), ("🔧 System", "sys"), ("💾 Backup", "bak"), ("🩺 Help", "help"), ("⏻ Shutdown", "shut")]
CFG_KEYS = {"delay_seconds": ("Delay between messages (s)", V.delay), "parse_mode": ("Default format", V.mode),
            "test_recipient": ("Test recipient", V.optref)}
SYS_KEYS = {"log_level": ("Log level", V.level), "log_retention_days": ("Log retention (days)", V.posint(1, 3650)),
            "error_retention_days": ("Error record retention (days)", V.posint(1, 3650)),
            "backup_keep": ("Backups to keep", V.posint(1, 100)), "live_refresh_seconds": ("Live refresh (s)", V.posint(5, 300))}


class Dashboard:
    def __init__(self, app):
        self.app = app
        self.mode: dict[int, tuple] = {}
        self.confirms: dict = {}
        self.live: dict[int, asyncio.Task] = {}

    # --- plumbing
    def is_admin(self, uid) -> bool:
        return uid in self.app.cfg.get("admins")

    def attach(self, bot):
        bot.add_event_handler(self.on_message, events.NewMessage(incoming=True, func=lambda e: e.is_private))
        bot.add_event_handler(self.on_cb, events.CallbackQuery())

    def cancel_live(self):
        for t in self.live.values():
            t.cancel()

    @property
    def db(self):
        return self.app.db

    @property
    def jobs(self):
        return self.app.jobs

    async def show(self, ev, text, rows=None, menu=True):
        rows = list(rows or []) + ([[Button.inline("⬅️ Menu", "menu")]] if menu else [])
        text = text[:4000]
        if isinstance(ev, events.CallbackQuery.Event):
            try:
                await ev.edit(text, buttons=rows)
            except errors.MessageNotModifiedError:
                await ev.answer()
        else:
            await ev.respond(text, buttons=rows)

    async def ask_confirm(self, ev, text, action):
        if len(self.confirms) > 50:
            self.confirms.clear()
        tok = pysecrets.token_hex(4)
        self.confirms[tok] = action
        await self.show(ev, "⚠️ Please confirm\n\n" + text, [[Button.inline("✅ Confirm", "cf:y" + tok), Button.inline("✖️ Cancel", "cf:n" + tok)]], menu=False)

    async def on_cb(self, ev):
        if not self.is_admin(ev.sender_id):
            log.warning("Unauthorized callback from user id %s", ev.sender_id)
            await ev.answer("Not authorized.", alert=True)
            return
        cmd, _, arg = ev.data.decode(errors="replace").partition(":")
        fn = getattr(self, "v_" + cmd, None)
        try:
            if not fn:
                raise AppError("Unknown action.")
            await fn(ev, arg)
        except AppError as e:
            await ev.answer(str(e)[:190], alert=True)
        except Exception:
            log.exception("dashboard error")
            await ev.answer("Internal error - see logs.", alert=True)

    async def on_message(self, ev):
        uid = ev.sender_id
        if not self.is_admin(uid):
            log.warning("Ignored message from unauthorized user id %s", uid)
            return
        text = (ev.raw_text or "").strip()
        try:
            if text in ("/start", "/menu", "/help") or (text == "/cancel"):
                self.mode.pop(uid, None)
                return await self.v_menu(ev, "")
            if text.lower().startswith("/optout"):
                n = Recipients(self.db).opt_out(text.split()[1:])
                return await ev.respond(f"Opted out {n} recipient(s). They are excluded from all future jobs.")
            m = self.mode.pop(uid, None)
            if not m:
                return await self.v_menu(ev, "")
            await getattr(self, "m_" + m[0])(ev, text, *m[1:])
        except AppError as e:
            await ev.respond(f"⚠️ {e}")
        except Exception:
            log.exception("dashboard message error")
            await ev.respond("Internal error - see logs.")

    # --- menu & simple pages
    async def v_menu(self, ev, arg):
        rows = [[Button.inline(MENU[i][0], MENU[i][1])] + ([Button.inline(MENU[i + 1][0], MENU[i + 1][1])] if i + 1 < len(MENU) else [])
                for i in range(0, len(MENU), 2)]
        await self.show(ev, f"Broadcast Manager v{VERSION}\nChoose a section.", rows, menu=False)

    async def v_acct(self, ev, arg):
        a = self.app
        if arg == "re":
            if not a.user.is_connected():
                await a.user.connect()
            a.user_ok = await a.user.is_user_authorized()
        info = "not authorized (run --login in the CLI)"
        if a.user and a.user.is_connected() and a.user_ok:
            me = await a.user.get_me()
            info = f"{me.first_name or ''} (@{me.username or '-'})"
        txt = f"Account status\nConnected: {bool(a.user and a.user.is_connected())}\nAuthorized: {a.user_ok}\nIdentity: {info}\nAdmins allowed: {len(self.app.cfg.get('admins'))}"
        await self.show(ev, txt, [[Button.inline("🔄 Reconnect", "acct:re"), Button.inline("⛔ Disconnect", "acct:dc")]] if arg != "dc" else [])
        if arg == "dc":
            async def go(e):
                for j in self.db.q("SELECT id FROM jobs WHERE status IN ('running','waiting_telegram')"):
                    self.jobs.pause(j["id"])
                await a.user.disconnect()
                a.user_ok = False
                await self.show(e, "Account disconnected; running jobs were paused. Use Reconnect to resume access.")
            await self.ask_confirm(ev, "Disconnect the user account? Running jobs will be paused.", go)

    async def _settings(self, ev, arg, keys, prefix, title):
        if arg in keys:
            self.mode[ev.sender_id] = ("set", arg, prefix)
            return await self.show(ev, f"Send the new value for “{keys[arg][0]}”.\nCurrent: {self.app.cfg.get(arg) or '-'}\n/cancel to abort.")
        lines = "\n".join(f"{lbl}: {self.app.cfg.get(k) or '-'}" for k, (lbl, _) in keys.items())
        await self.show(ev, f"{title}\n\n{lines}", [[Button.inline(f"✏️ {lbl}", f"{prefix}:{k}")] for k, (lbl, _) in keys.items()])

    async def v_cfg(self, ev, arg):
        await self._settings(ev, arg, CFG_KEYS, "cfg", "Message settings")

    async def v_sys(self, ev, arg):
        await self._settings(ev, arg, SYS_KEYS, "sys", f"System settings (data dir: {self.app.cfg.dir})")

    async def m_set(self, ev, text, key, prefix):
        keys = CFG_KEYS if prefix == "cfg" else SYS_KEYS
        val = keys[key][1](text)
        self.app.cfg.v[key] = val
        self.app.cfg.save()
        if key == "log_level":
            logging.getLogger().setLevel(val)
        await self._settings(ev, "", keys, prefix, "Saved ✓")

    # --- composer
    async def v_comp(self, ev, arg):
        comp, d = Composer(self.db, self.app.cfg), Composer(self.db, self.app.cfg).draft()
        if arg == "body":
            self.mode[ev.sender_id] = ("compose_body",)
            return await self.show(ev, "Send the message text now (type markup literally if using markdown/html). /cancel to abort.")
        if arg == "mode":
            d["mode"] = {"plain": "markdown", "markdown": "html", "html": "plain"}[d["mode"]]
            comp.save_draft(d)
        if arg == "media":
            self.mode[ev.sender_id] = ("compose_media",)
            return await self.show(ev, "Send one photo/document now. It will be stored in the data folder. /cancel to abort.")
        if arg == "clrmedia":
            d["media"] = None
            comp.save_draft(d)
        if arg == "tpl":
            self.mode[ev.sender_id] = ("save_tpl",)
            return await self.show(ev, "Send a template name (letters/digits/_/-, max 20).")
        if arg == "preview":
            probs = comp.validate(d)
            await self.app.bot.send_message(ev.chat_id, "👁 Preview below (exactly how it will look)" + (f"\n⚠️ {' '.join(probs)}" if probs else ""))
            if d["body"]:
                pm = {"plain": None, "markdown": "md", "html": "html"}[d["mode"]]
                if d.get("media"):
                    await self.app.bot.send_file(ev.chat_id, self.app.abs_media(d["media"]), caption=d["body"], parse_mode=pm)
                else:
                    await self.app.bot.send_message(ev.chat_id, d["body"], parse_mode=pm)
            return await ev.answer()
        if arg == "test":
            tr, probs = self.app.cfg.get("test_recipient"), comp.validate(d)
            if not tr:
                raise AppError("Set a test recipient in Configure first.")
            if probs:
                raise AppError(" ".join(probs))

            async def go(e):
                await self.app.send(tr, {"body": d["body"], "parse_mode": d["mode"], "media_path": d.get("media")})
                await self.show(e, f"Test message delivered to {tr}.")
            return await self.ask_confirm(ev, f"Send this draft ONCE to the test recipient {tr}?", go)
        if arg == "job":
            probs = comp.validate(d)
            if probs:
                raise AppError(" ".join(probs))
            r = Recipients(self.db).stats()

            async def go(e):
                jid = self.jobs.create(d)
                await self.v_job(e, jid)
            return await self.ask_confirm(ev, f"Create a job from the current draft for {r['eligible']} consented, non-opted-out recipient(s)? (Nothing is sent yet.)", go)
        probs = comp.validate(d)
        txt = (f"Composer draft\nFormat: {d['mode']}\nMedia: {d.get('media') or 'none'}\nLength: {len(d['body'])} chars\n"
               f"Status: {'✅ valid' if not probs else '⚠️ ' + ' '.join(probs)}\n\n{d['body'][:600] or '(empty)'}")
        rows = [[Button.inline("✏️ Text", "comp:body"), Button.inline("🔤 Format", "comp:mode")],
                [Button.inline("📎 Media", "comp:media"), Button.inline("🗑 Clear media", "comp:clrmedia")],
                [Button.inline("👁 Preview", "comp:preview"), Button.inline("🧪 Test send", "comp:test")],
                [Button.inline("💾 Save template", "comp:tpl"), Button.inline("🚀 Create job", "comp:job")]]
        await self.show(ev, txt, rows)

    async def m_compose_body(self, ev, text):
        comp = Composer(self.db, self.app.cfg)
        d = comp.draft()
        d["body"] = text
        comp.save_draft(d)
        await self.v_comp(ev, "")

    async def m_compose_media(self, ev, text):
        if not ev.message.media or not ev.message.file:
            raise AppError("That was not a file. Open Composer > Media to try again.")
        if ev.message.file.size > 50_000_000:
            raise AppError("File too large (50 MB max).")
        ext = (ev.message.file.ext or "")
        rel = f"media/{pysecrets.token_hex(6)}{ext}"
        (self.app.cfg.dir / "media").mkdir(parents=True, exist_ok=True)
        await ev.download_media(file=self.app.abs_media(rel))
        comp = Composer(self.db, self.app.cfg)
        d = comp.draft()
        d["media"] = rel
        comp.save_draft(d)
        await self.v_comp(ev, "")

    async def m_save_tpl(self, ev, text):
        comp = Composer(self.db, self.app.cfg)
        comp.save_template(text, comp.draft())
        await self.show(ev, f"Template “{text}” saved ✓", [[Button.inline("🗂 Templates", "tpl")]])

    async def v_tpl(self, ev, arg):
        comp = Composer(self.db, self.app.cfg)
        act, _, name = arg.partition(":")
        if act == "use":
            comp.load_template(name)
            return await self.v_comp(ev, "")
        if act == "del":
            async def go(e):
                self.db.run("DELETE FROM templates WHERE name=?", (name,))
                await self.v_tpl(e, "")
            return await self.ask_confirm(ev, f"Delete template “{name}”?", go)
        t = comp.templates()
        rows = [[Button.inline(f"📥 {r['name']}", f"tpl:use:{r['name']}"), Button.inline("🗑", f"tpl:del:{r['name']}")] for r in t]
        await self.show(ev, "Templates (tap to load into the draft)" if t else "No templates yet. Save one from Composer.", rows)

    # --- recipients
    async def v_rec(self, ev, arg):
        if arg == "imp":
            self.mode[ev.sender_id] = ("import_csv",)
            return await self.show(ev, "Upload a CSV file now.\nColumns: user (ID or @username), consent (yes/no), source, consent_ts.\nOnly rows with consent=yes can ever be messaged. /cancel to abort.")
        if arg == "opt":
            self.mode[ev.sender_id] = ("optout",)
            return await self.show(ev, "Send one or more IDs/@usernames to opt out (space-separated).")
        s = Recipients(self.db).stats()
        await self.show(ev, f"Recipients\nTotal records: {s['total']}\nEligible (consent granted, not opted out): {s['eligible']}\nOpted out: {s['optout']}\nConsent unknown/missing: {s['unknown']}\n\nOpt-out: /optout <id or @user>, or the recipient replies STOP.",
                        [[Button.inline("📥 Import CSV", "rec:imp"), Button.inline("🚫 Opt out", "rec:opt")]])

    async def m_import_csv(self, ev, text):
        f = ev.message.file
        if not f:
            raise AppError("Please upload a CSV file. Open Recipients > Import to retry.")
        if f.size > 5_000_000:
            raise AppError("CSV too large (5 MB max).")
        data = await ev.download_media(file=bytes)
        rep = Recipients(self.db).import_csv(data.decode("utf-8-sig", errors="replace"), f"csv:{f.name or 'upload'}")
        await self.show(ev, Recipients.report_text(rep), [[Button.inline("👥 Recipients", "rec")]])

    async def m_optout(self, ev, text):
        n = Recipients(self.db).opt_out(text.split())
        await self.show(ev, f"Opted out {n} recipient(s).", [[Button.inline("👥 Recipients", "rec")]])

    # --- jobs
    def _job_buttons(self, jid):
        st = self.jobs.get(jid)["status"]
        rows = []
        if st == "awaiting_confirmation":
            rows.append([Button.inline("▶️ Start now", f"jact:start:{jid}"), Button.inline("🕒 Schedule", f"jact:sched:{jid}")])
        if st in ("running", "waiting_telegram"):
            rows.append([Button.inline("⏸ Pause", f"jact:pause:{jid}"), Button.inline("📈 Live", f"live:{jid}")])
        if st == "paused":
            rows.append([Button.inline("▶️ Resume", f"jact:resume:{jid}")])
        if st in ("completed_errors", "paused"):
            rows.append([Button.inline("🔁 Retry eligible failures", f"jact:retry:{jid}")])
        if st not in TERMINAL:
            rows.append([Button.inline("🛑 Cancel job", f"jact:cancel:{jid}")])
        rows.append([Button.inline("📄 Export report", f"jact:report:{jid}"), Button.inline("🔄 Refresh", f"job:{jid}")])
        rows.append([Button.inline("📦 Jobs", "jobs")])
        return rows

    async def v_jobs(self, ev, arg):
        rows = []
        for j in self.db.q("SELECT id,status FROM jobs ORDER BY created DESC, id DESC LIMIT 8"):
            rows.append([Button.inline(f"{j['id']} · {LABEL[j['status']]} · {self.jobs.counts(j['id'])['pct']}%", f"job:{j['id']}")])
        await self.show(ev, "Broadcast jobs" if rows else "No jobs yet. Create one from Composer.", rows)

    async def v_job(self, ev, arg):
        j = self.jobs.get(arg)
        c = self.jobs.counts(arg)
        extra = ""
        if j["status"] == "awaiting_confirmation":
            est = int(c["total"] * self.app.cfg.get("delay_seconds"))
            extra = (f"\n\nPreview ({j['parse_mode']}):\n{j['body'][:400]}\n\nWorkload: {c['total']} recipients × {self.app.cfg.get('delay_seconds')}s ≈ {est // 60} min "
                     "(Telegram may impose waits; no quota is assumed).")
        errs = self.db.q("SELECT cls, COUNT(*) n FROM errors WHERE job_id=? GROUP BY cls", (arg,))
        if errs:
            extra += "\n\nErrors: " + ", ".join(f"{e['cls']}×{e['n']}" for e in errs)
        await self.show(ev, self.jobs.progress_text(arg) + extra, self._job_buttons(arg), menu=False)

    async def v_jact(self, ev, arg):
        act, _, jid = arg.partition(":")
        j = self.jobs.get(jid)
        if act == "pause":
            self.jobs.pause(jid)
            return await self.v_job(ev, jid)
        if act == "report":
            p = job_csv(self.db, jid, self.app.cfg.dir / "reports" / f"{jid}.csv")
            await self.app.bot.send_file(ev.chat_id, str(p), caption=f"Report for {jid}\n" + daily_summary(self.db))
            return await ev.answer("Report sent.")
        if act == "sched":
            self.mode[ev.sender_id] = ("schedule", jid)
            return await self.show(ev, "Send start time in UTC as YYYY-MM-DD HH:MM (e.g. 2026-11-02 14:30). /cancel to abort.")
        c = self.jobs.counts(jid)
        if act == "start":
            async def go(e):
                self.jobs.confirm(jid)
                self.jobs.start(jid)
                await self.v_job(e, jid)
            return await self.ask_confirm(ev, f"START {jid} now?\n{c['total']} consented recipients will receive your message from your personal account. This cannot be undone for messages already sent.", go)
        if act == "resume":
            async def go(e):
                self.jobs.start(jid, ack_review=True)
                await self.v_job(e, jid)
            warn = "\n⚠️ This job needed review (" + str(j['error_category']) + "). Only resume if you have addressed it." if j["review_required"] else ""
            return await self.ask_confirm(ev, f"Resume {jid}? {c['remaining']} recipients remain. 'Uncertain' deliveries are NOT re-sent.{warn}", go)
        if act == "retry":
            async def go(e):
                self.jobs.retry_failures(jid)
                await self.v_job(e, jid)
            return await self.ask_confirm(ev, f"Retry eligible failures for {jid}? {c['uncertain']} uncertain delivery(ies) may ALREADY have been delivered and could be duplicated. Privacy/blocked/invalid recipients are never retried.", go)
        if act == "cancel":
            async def go(e):
                self.jobs.cancel(jid)
                await self.v_job(e, jid)
            return await self.ask_confirm(ev, f"Cancel {jid}? Remaining {c['remaining']} recipients will be skipped.", go)
        raise AppError("Unknown job action.")

    async def m_schedule(self, ev, text, jid):
        try:
            when = datetime.strptime(text, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
        except ValueError:
            raise AppError("Format must be YYYY-MM-DD HH:MM (UTC).") from None
        if when <= datetime.now(timezone.utc):
            raise AppError("Time must be in the future.")
        iso = when.isoformat(timespec="seconds")

        async def go(e):
            self.jobs.confirm(jid)
            self.db.run("UPDATE jobs SET scheduled_at=? WHERE id=?", (iso, jid))
            await self.v_job(e, jid)
        await self.ask_confirm(ev, f"Schedule {jid} to start automatically at {iso} UTC? Your confirmation applies to that run.", go)

    async def v_sch(self, ev, arg):
        rows = [[Button.inline(f"{j['id']} · {j['scheduled_at'] or 'not scheduled'}", f"job:{j['id']}")]
                for j in self.db.q("SELECT id, scheduled_at FROM jobs WHERE status='awaiting_confirmation' ORDER BY created DESC LIMIT 8")]
        await self.show(ev, "Scheduling: open a job awaiting confirmation and tap Schedule.\nTimes are UTC. The app must be running at that time." if rows else "No jobs awaiting confirmation. Create one from Composer first.", rows)

    # --- progress, errors
    def _active(self):
        r = self.db.one("SELECT id FROM jobs WHERE status IN ('running','waiting_telegram','paused') ORDER BY created DESC LIMIT 1")
        return r["id"] if r else None

    async def v_live(self, ev, arg):
        jid = arg or self._active()
        if not jid:
            return await self.show(ev, "No active job.")
        old = self.live.pop(ev.chat_id, None)
        if old:
            old.cancel()
        await self.show(ev, self.jobs.progress_text(jid) + "\n\n(auto-refreshing)", [[Button.inline("📋 Details", f"job:{jid}")]])
        self.live[ev.chat_id] = asyncio.create_task(self._live_loop(ev.chat_id, ev.message_id, jid))

    async def _live_loop(self, chat, mid, jid):
        end, last = time.monotonic() + 900, None
        try:
            while time.monotonic() < end:
                await asyncio.sleep(self.app.cfg.get("live_refresh_seconds"))
                txt = self.jobs.progress_text(jid) + "\n\n(auto-refreshing)"
                if txt != last:
                    last = txt
                    try:
                        await self.app.bot.edit_message(chat, mid, txt, buttons=[[Button.inline("📋 Details", f"job:{jid}")], [Button.inline("⬅️ Menu", "menu")]])
                    except errors.MessageNotModifiedError:
                        pass
                if self.jobs.get(jid)["status"] in TERMINAL:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.warning("live view stopped: %s", type(e).__name__)

    async def v_err(self, ev, arg):
        if arg == "csv":
            p = errors_csv(self.db, self.app.cfg.dir / "reports" / "errors.csv")
            await self.app.bot.send_file(ev.chat_id, str(p), caption="Error report")
            return await ev.answer("Sent.")
        rows = self.db.q("SELECT * FROM errors ORDER BY id DESC LIMIT 8")
        body = "\n\n".join(f"{r['ts']} {r['job_id']}\n{r['cls']}: {r['detail']}\n→ {r['action']}" for r in rows) or "No errors recorded."
        await self.show(ev, daily_summary(self.db) + "\n\n" + body, [[Button.inline("📄 Export CSV", "err:csv")]])

    # --- system
    async def v_bak(self, ev, arg):
        if arg == "make":
            p = Backups(self.app.cfg).create()
            await ev.answer("Backup created.")
        names = [p.name for p in sorted(self.app.cfg.p("backup_dir").glob("backup-*.zip"))[-5:]] if self.app.cfg.p("backup_dir").exists() else []
        await self.show(ev, "Backups (validated on creation)\n" + ("\n".join(names) or "none yet") +
                        "\n\nRestore is CLI-only (stop the app, then: --restore FILE.zip) so the live database is never replaced under a running process.",
                        [[Button.inline("💾 Back up now", "bak:make")]])

    async def v_help(self, ev, arg):
        a, cfg = self.app, self.app.cfg
        unc = self.db.one("SELECT COUNT(*) n FROM job_recipients WHERE state='uncertain'")["n"]
        lock = self.db.one("PRAGMA user_version")[0]
        txt = (f"Diagnostics\nVersion {VERSION} | Python {sys.version.split()[0]}\nDB integrity: {self.db.integrity()} | schema v{lock}\n"
               f"User account authorized: {a.user_ok}\nUncertain deliveries: {unc}\nData dir: {cfg.dir}\n"
               f"Last shutdown: {(self.db.meta('last_shutdown') or {}).get('ts', '-')}\n\n"
               "Commands: /start /menu /optout <id> /cancel\nLogin codes/2FA are never requested here; use the CLI (--login).")
        await self.show(ev, txt)

    async def v_shut(self, ev, arg):
        async def go(e):
            await self.show(e, "Shutting down. Running jobs are paused and state is saved.", menu=False)
            self.app.request_shutdown()
        await self.ask_confirm(ev, "Shut the application down? Running jobs will be paused (not lost).", go)

    async def v_cf(self, ev, arg):
        act = self.confirms.pop(arg[1:], None)
        if arg[:1] != "y" or act is None:
            if arg[:1] == "y":
                await ev.answer("That confirmation expired.", alert=True)
                return
            return await self.v_menu(ev, "")
        await act(ev)


# ───────────────────────────── CLI ─────────────────────────────
def ask(prompt, parse=lambda s: s, default=None, secret=False):
    while True:
        shown = prompt + (f" [{default}]" if default not in (None, "") else "") + ": "
        raw = (getpass.getpass(shown) if secret else input(shown)).strip()
        if not raw and default is not None:
            raw = str(default)
        try:
            return parse(raw)
        except ValueError as e:
            print(f"  ✗ {e}")


def provision(data_dir, a: dict, passphrase: str) -> Config:
    """Create data dir, config.json, encrypted vault and database from validated answers."""
    cfg = Config(data_dir)
    os.makedirs(cfg.dir, mode=0o700, exist_ok=True)
    for k in DEFAULTS:
        if k in a:
            cfg.v[k] = a[k]
    cfg.save()
    Vault(cfg.p("vault_path")).save(passphrase, {k: a[k] for k in ("bot_token", "api_id", "api_hash", "phone")})
    DB(cfg.p("db_path")).close()
    harden(cfg)
    return cfg


def setup_wizard(data_dir):
    print(f"\n=== Telegram Broadcast Manager setup ===\nData directory: {Path(data_dir).resolve()}  (change with --data-dir)\n")
    if (Path(data_dir) / "config.json").exists() and input("Existing configuration found. Overwrite settings and vault (database is kept)? [y/N]: ").strip().lower() != "y":
        return None
    a = {}
    a["bot_token"] = ask("Bot token from @BotFather (hidden)", V.token, secret=True)
    print(f"  ✓ accepted ({mask(a['bot_token'])})")
    a["api_id"] = ask("Telegram API ID (my.telegram.org)", V.api_id)
    a["api_hash"] = ask("Telegram API hash (hidden)", V.api_hash, secret=True)
    print(f"  ✓ accepted ({mask(a['api_hash'])})")
    a["phone"] = ask("Phone number of the sending Telegram account", V.phone)
    a["admins"] = ask("Authorized administrator numeric Telegram user ID(s), comma-separated", V.admins)
    a["log_level"] = ask("Log level (DEBUG/INFO/WARNING/ERROR)", V.level, "INFO")
    a["delay_seconds"] = ask("Fixed seconds between messages", V.delay, 3)
    a["parse_mode"] = ask("Default message format (plain/markdown/html)", V.mode, "plain")
    a["test_recipient"] = ask("Test recipient ID/@username (blank to skip)", V.optref, "")
    a["db_path"] = ask("Database file (relative to data dir)", V.path, "app.db")
    a["vault_path"] = ask("Encrypted secrets + session file", V.path, "vault.enc")
    a["backup_dir"] = ask("Backup directory", V.path, "backups")
    a["backup_keep"] = ask("Backups to keep", V.posint(1, 100), 10)
    a["backup_auto"] = ask("Auto-backup on clean shutdown? (y/n)", V.yn, "y")
    print("\nThe vault passphrase encrypts your token, API hash and Telegram session. It is NOT stored anywhere.\n"
          "Back it up in a password manager (never in this repo). If lost, you must re-run setup.\n")
    pw = get_passphrase(confirm=True)
    cfg = provision(data_dir, a, pw)
    print(f"\n✓ Setup saved. Bot token {mask(a['bot_token'])}, API hash {mask(a['api_hash'])} stored encrypted in {cfg.p('vault_path')}.")
    return cfg, pw


async def cli_login(cfg: Config, pw: str):
    v = Vault(cfg.p("vault_path"))
    s = v.load(pw)
    Redactor.secrets |= {str(s.get(k, "")) for k in ("bot_token", "api_hash", "session")}
    client = TelegramClient(StringSession(s.get("session", "")), int(s["api_id"]), s["api_hash"])
    await client.connect()
    try:
        if await client.is_user_authorized():
            me = await client.get_me()
            print(f"Already logged in as {me.first_name} (@{me.username or '-'}).")
            return
        phone = s.get("phone") or ask("Phone number", V.phone)
        await client.send_code_request(phone)
        for _ in range(3):
            code = getpass.getpass("Login code sent by Telegram (hidden): ").strip()
            try:
                await client.sign_in(phone, code)
                break
            except errors.SessionPasswordNeededError:
                for _ in range(3):
                    try:
                        await client.sign_in(password=getpass.getpass("Two-factor password (hidden): "))
                        break
                    except errors.PasswordHashInvalidError:
                        print("  ✗ Wrong password.")
                else:
                    raise AppError("Two-factor authentication failed.")
                break
            except errors.PhoneCodeInvalidError:
                print("  ✗ Invalid code.")
        else:
            raise AppError("Too many invalid codes.")
        s["session"] = client.session.save()
        v.save(pw, s)
        me = await client.get_me()
        print(f"✓ Logged in as {me.first_name}. Session saved (encrypted).")
    except errors.RPCError as e:
        raise AppError(f"Telegram refused the login: {type(e).__name__}") from None
    finally:
        await client.disconnect()


def rotate(cfg: Config):
    pw = get_passphrase()
    v = Vault(cfg.p("vault_path"))
    s = v.load(pw)
    c = input("Rotate: [1] bot token  [2] API ID/hash (+ new login)  [3] vault passphrase  > ").strip()
    if c == "1":
        s["bot_token"] = ask("New bot token (hidden)", V.token, secret=True)
        s.pop("bot_session", None)
        print("Now also run /revoke in @BotFather for the OLD token.")
    elif c == "2":
        s["api_id"] = ask("New API ID", V.api_id)
        s["api_hash"] = ask("New API hash (hidden)", V.api_hash, secret=True)
        s.pop("session", None)
        s.pop("bot_session", None)
        print("Session cleared. Run --login next.")
    elif c == "3":
        pw = get_passphrase(confirm=True) if not os.environ.get("TGM_PASSPHRASE") else sys.exit("Unset TGM_PASSPHRASE first.")
    else:
        return print("Nothing changed.")
    v.save(pw, s)
    print("✓ Rotated.")


def status(cfg: Config):
    print(f"Telegram Broadcast Manager v{VERSION}\nData dir: {cfg.dir.resolve()}\nAdmins: {cfg.get('admins')}\n"
          f"Log level: {cfg.get('log_level')} | delay: {cfg.get('delay_seconds')}s\n"
          f"Vault: {'present' if cfg.p('vault_path').exists() else 'MISSING'} ({cfg.p('vault_path')})")
    if cfg.p("db_path").exists():
        db = DB(cfg.p("db_path"))
        print(f"Database: integrity {db.integrity()}, last shutdown {db.meta('last_shutdown')}")
        for r in db.q("SELECT status, COUNT(*) n FROM jobs GROUP BY status"):
            print(f"  jobs {LABEL[r['status']]}: {r['n']}")
        print("Recipients:", Recipients(db).stats())
        db.close()
    for w in harden(cfg):
        print("security:", w)


INIT_FILES = {
    "requirements.txt": "telethon>=1.36\ncryptography>=42\n",
    ".gitignore": """# Python / env
__pycache__/
*.pyc
.venv/
venv/
.env
.env.*
# Secrets and sessions: never commit
*.session
*.session-journal
*.key
*.pem
# Runtime artefacts
data/.instance.lock
data/logs/
data/backups/
data/reports/
data/*.tmp
*.db-journal
# Tracked ON PURPOSE for multi-device use: data/config.json, data/vault.enc (encrypted),
# data/app.db, data/media/.  To keep recipient data out of git, uncomment:
# data/app.db
""",
}


def init_files():
    for name, content in INIT_FILES.items():
        p = Path(name)
        if p.exists():
            print(f"skip {name} (exists)")
        else:
            p.write_text(content, encoding="utf-8")
            print(f"wrote {name}")
    if not Path("README.md").exists():
        Path("README.md").write_text("# Telegram Broadcast Manager\n\n```\n" + (__doc__ or "") + "\n```\n", encoding="utf-8")
        print("wrote README.md")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Telegram Broadcast Manager (see file header for full docs)")
    ap.add_argument("--data-dir", default=os.environ.get("TGM_DATA", "data"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--setup", action="store_true")
    g.add_argument("--status", action="store_true")
    g.add_argument("--backup", action="store_true")
    g.add_argument("--restore", metavar="ZIP")
    g.add_argument("--login", action="store_true")
    g.add_argument("--rotate", action="store_true")
    g.add_argument("--init-files", action="store_true")
    g.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.selftest:
            suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
            return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
        if args.init_files:
            return init_files() or 0
        cfg_path = Path(args.data_dir) / "config.json"
        pw = None
        if args.setup or not cfg_path.exists():
            res = setup_wizard(args.data_dir)
            if res is None:
                return 0
            cfg, pw = res
            if input("Log in the Telegram user account now (code/2FA typed here)? [Y/n]: ").strip().lower() in ("", "y", "yes"):
                asyncio.run(cli_login(cfg, pw))
            if input("Start the application now? [Y/n]: ").strip().lower() not in ("", "y", "yes"):
                print(f"Start later with: python {Path(sys.argv[0]).name}")
                return 0
            args = ap.parse_args([])  # fall through to run
        cfg = Config(args.data_dir).load()
        if args.status:
            status(cfg)
        elif args.backup:
            print("Backup written:", Backups(cfg).create())
        elif args.restore:
            lock = InstanceLock(cfg.dir / ".instance.lock")
            lock.acquire()
            try:
                Backups(cfg).restore(Path(args.restore))
            finally:
                lock.release()
            print("✓ Restored (previous state was backed up first). Start the app normally.")
        elif args.login:
            setup_logging(cfg)
            asyncio.run(cli_login(cfg, get_passphrase()))
        elif args.rotate:
            rotate(cfg)
        else:
            asyncio.run(App(cfg, pw).run())
        return 0
    except AppError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


# ───────────────────────────── tests (python telegram_manager.py --selftest) ─────────────────────────────
def _exc(name, **attrs):
    return type(name, (Exception,), attrs)()


ANSWERS = {"bot_token": "123456789:" + "A" * 35, "api_id": 12345, "api_hash": "a" * 32, "phone": "+491701234567",
           "admins": [42], "delay_seconds": 1.0, "backup_keep": 3}
PASS = "correct horse battery staple"


class FakeSender:
    def __init__(self, fail=None):
        self.sent, self.fail = [], fail or {}

    async def __call__(self, ref, job):
        if ref in self.fail:
            raise self.fail[ref]
        self.sent.append(ref)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = provision(self.tmp.name, ANSWERS, PASS)
        self.cfg.v["delay_seconds"] = 0
        self.db = DB(self.cfg.p("db_path"))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def make_job(self, sender, n=4, consent="yes"):
        csv_text = "user,consent\n" + "\n".join(f"{1000 + i},{consent}" for i in range(n))
        Recipients(self.db).import_csv(csv_text)
        jobs = Jobs(self.db, self.cfg, sender)
        jid = jobs.create({"body": "hello", "mode": "plain", "media": None})
        jobs.confirm(jid)
        return jobs, jid


class TestSetupConfigSecurity(Base):
    def test_first_run_persists_and_reloads(self):
        cfg2 = Config(self.tmp.name).load()
        self.assertEqual(cfg2.get("admins"), [42])
        self.assertTrue(cfg2.p("db_path").exists())
        self.assertNotIn(ANSWERS["bot_token"], cfg2.path.read_text())  # secrets not in plain config
        s = Vault(cfg2.p("vault_path")).load(PASS)
        self.assertEqual(s["api_id"], 12345)

    def test_vault_wrong_passphrase_and_no_plaintext(self):
        v = Vault(self.cfg.p("vault_path"))
        with self.assertRaises(AppError):
            v.load("wrong passphrase!!")
        self.assertNotIn(ANSWERS["api_hash"].encode(), v.path.read_bytes())

    def test_validators(self):
        for bad, fn in (("x", V.token), ("0", V.api_id), ("zz", V.api_hash), ("123", V.phone), ("a,b", V.admins)):
            with self.assertRaises(ValueError):
                fn(bad)
        self.assertEqual(V.phone("+49 170 1234567"), "+491701234567")

    def test_redaction(self):
        Redactor.secrets.add("supersecretvalue")
        t = Redactor.clean(f"tok {ANSWERS['bot_token']} hash {'b' * 32} supersecretvalue")
        self.assertNotIn(ANSWERS["bot_token"], t)
        self.assertNotIn("b" * 32, t)
        self.assertNotIn("supersecretvalue", t)
        self.assertEqual(mask(ANSWERS["bot_token"]), "…" + ANSWERS["bot_token"][-4:])

    def test_unauthorized_admin(self):
        d = Dashboard(type("A", (), {"cfg": self.cfg})())
        self.assertTrue(d.is_admin(42))
        self.assertFalse(d.is_admin(43))

    def test_instance_lock(self):
        a, b = InstanceLock(Path(self.tmp.name) / "l"), InstanceLock(Path(self.tmp.name) / "l")
        a.acquire()
        if os.name != "nt":
            with self.assertRaises(AppError):
                b.acquire()
        a.release()


class TestDatabase(Base):
    def test_rollback(self):
        with self.assertRaises(RuntimeError):
            with self.db.tx() as c:
                c.execute("INSERT INTO recipients(ref) VALUES('111')")
                raise RuntimeError
        self.assertIsNone(self.db.one("SELECT 1 FROM recipients WHERE ref='111'"))

    def test_migration_version_and_integrity(self):
        self.assertEqual(self.db.one("PRAGMA user_version")[0], len(MIGRATIONS))
        self.assertEqual(self.db.integrity(), "ok")


class TestRecipients(Base):
    def test_import_validation_and_duplicates(self):
        rep = Recipients(self.db).import_csv("user,consent\n1001,yes\n1001,yes\nbad!,yes\n,yes\n@alice_x,no\n")
        self.assertEqual((rep["added"], len(rep["duplicates"]), len(rep["malformed"]), len(rep["missing"])), (2, 1, 1, 1))
        self.assertEqual(Recipients(self.db).eligible(), ["1001"])  # no-consent never eligible

    def test_opt_out_enforced_and_survives_reimport(self):
        r = Recipients(self.db)
        r.import_csv("user,consent\n1001,yes\n1002,yes\n")
        r.opt_out(["1001"])
        r.import_csv("user,consent\n1001,yes\n")
        self.assertEqual(r.eligible(), ["1002"])


class TestJobs(Base):
    def test_full_run_no_duplicates_and_csv(self):
        fs = FakeSender()
        jobs, jid = self.make_job(fs)
        asyncio.run(jobs._run(jid))
        self.assertEqual(jobs.get(jid)["status"], "completed")
        self.assertEqual(sorted(fs.sent), sorted(set(fs.sent)))
        self.assertEqual(jobs.counts(jid)["sent"], 4)
        self.assertIn("1000", job_csv(self.db, jid, Path(self.tmp.name) / "r.csv").read_text())

    def test_invalid_transition_and_unconfirmed_start(self):
        jobs, jid = self.make_job(FakeSender())
        with self.assertRaises(AppError):
            jobs.set_status(jid, "completed")

        async def go():
            self.db.run("UPDATE jobs SET confirmed=0 WHERE id=?", (jid,))
            with self.assertRaises(AppError):
                jobs.start(jid)
        asyncio.run(go())

    def test_no_consent_no_job(self):
        Recipients(self.db).import_csv("user,consent\n1001,no\n")
        with self.assertRaises(AppError):
            Jobs(self.db, self.cfg, FakeSender()).create({"body": "x", "mode": "plain", "media": None})

    def test_opt_out_mid_job_skipped(self):
        fs = FakeSender()
        jobs, jid = self.make_job(fs)
        Recipients(self.db).opt_out(["1002"])
        asyncio.run(jobs._run(jid))
        self.assertNotIn("1002", fs.sent)
        self.assertEqual(jobs.counts(jid)["skipped"], 1)

    def test_flood_wait(self):
        fs = FakeSender({"1001": _exc("FloodWaitError", seconds=30)})
        jobs, jid = self.make_job(fs)
        asyncio.run(jobs._run(jid))
        j = jobs.get(jid)
        self.assertEqual(j["status"], "waiting_telegram")
        self.assertTrue(j["next_run"] > now())
        c = jobs.counts(jid)
        self.assertEqual((c["sent"], c["pending"], c["failed"]), (1, 3, 0))
        self.assertEqual(self.db.one("SELECT cls FROM errors")["cls"], "FloodWaitError")

        async def early():
            with self.assertRaises(AppError):
                jobs.start(jid)
        asyncio.run(early())

    def test_peer_flood_requires_review(self):
        jobs, jid = self.make_job(FakeSender({"1001": _exc("PeerFloodError")}))
        asyncio.run(jobs._run(jid))
        j = jobs.get(jid)
        self.assertEqual((j["status"], j["review_required"]), ("paused", 1))

        async def go():
            with self.assertRaises(AppError):
                jobs.start(jid)
        asyncio.run(go())

    def test_network_failures_uncertain_and_bounded(self):
        fail = {f"{1000 + i}": ConnectionError("x") for i in range(4)}
        jobs, jid = self.make_job(FakeSender(fail))
        asyncio.run(jobs._run(jid))
        c = jobs.get(jid)
        self.assertEqual((c["status"], c["review_required"]), ("paused", 1))
        self.assertEqual(jobs.counts(jid)["uncertain"], 3)

    def test_recipient_errors_not_retried(self):
        fs = FakeSender({"1000": _exc("UserPrivacyRestrictedError"), "1001": _exc("UserIsBlockedError")})
        jobs, jid = self.make_job(fs)
        asyncio.run(jobs._run(jid))
        self.assertEqual(jobs.get(jid)["status"], "completed_errors")

        async def go():
            with self.assertRaises(AppError):
                jobs.retry_failures(jid)
        asyncio.run(go())

    def test_classification(self):
        self.assertEqual(classify(_exc("AuthKeyUnregisteredError")).kind, "auth")
        self.assertEqual(classify(_exc("ServerError")).kind, "network")
        self.assertEqual(classify(TimeoutError()).kind, "network")
        self.assertEqual(classify(ValueError("no entity")).cls, "invalid_recipient")

    def test_crash_recovery_never_resends(self):
        fs = FakeSender()
        jobs, jid = self.make_job(fs)
        self.db.run("UPDATE jobs SET status='running' WHERE id=?", (jid,))
        jobs.mark(jid, "1000", "sent")
        jobs.mark(jid, "1001", "sending")  # simulated crash mid-request
        notes = recover(self.db)
        self.assertTrue(notes)
        j = jobs.get(jid)
        self.assertEqual((j["status"], j["review_required"]), ("paused", 1))
        self.assertEqual(self.db.one("SELECT state FROM job_recipients WHERE ref='1001'")["state"], "uncertain")

        async def go():
            with self.assertRaises(AppError):
                jobs.start(jid)  # no silent auto-resume
            jobs.start(jid, ack_review=True)
            await jobs.task
        asyncio.run(go())
        self.assertEqual(sorted(fs.sent), ["1002", "1003"])  # sent + uncertain not re-sent
        self.assertEqual(jobs.get(jid)["status"], "completed_errors")


class TestBackup(Base):
    def test_backup_restore_roundtrip_and_validation(self):
        Recipients(self.db).import_csv("user,consent\n1001,yes\n")
        z = Backups(self.cfg).create()
        Backups.validate(z)
        self.db.run("DELETE FROM recipients")
        self.db.close()
        Backups(self.cfg).restore(z)
        self.db = DB(self.cfg.p("db_path"))
        self.assertEqual(Recipients(self.db).eligible(), ["1001"])
        bad = Path(self.tmp.name) / "bad.zip"
        bad.write_bytes(b"not a zip")
        with self.assertRaises(AppError):
            Backups.validate(bad)


if __name__ == "__main__":
    sys.exit(main())
