"""Zscaler Cloud NSS log store: parsing what a feed pushes, and keeping it under a hard size cap.

Logs are written to segment files (one SQLite database each) in LW_NSS_DIR. Each segment holds the
events plus an hourly roll-up (events, bytes, blocked, threats per user and app) that the activity
dashboard reads, so a dashboard never scans raw events. When the segments together pass the size cap,
or the disk's free space drops below the floor, the oldest segment is deleted whole: retention is by
size, not age, and the roll-ups go with the events they summarise.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import re
import shutil
import sqlite3
import threading
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

log = logging.getLogger("linkwatch.nss")

GB = 1000 ** 3
DEFAULT_MAX_GB = 120
DEFAULT_MIN_FREE_GB = 10
FEEDS = {"web": "Web", "fw": "Firewall", "dns": "DNS", "tunnel": "Tunnel", "other": "Other"}
SEGMENT_RE = re.compile(r"^seg-(\d{8}T\d{6})-(\d{6})\.db$")
MAX_BODY = 64 * 1024 * 1024          # bytes on the wire
MAX_INFLATED = 256 * 1024 * 1024     # bytes after gunzip

SCHEMA = """
CREATE TABLE IF NOT EXISTS ev(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, feed TEXT, user TEXT, dept TEXT, loc TEXT, app TEXT, cat TEXT,
  host TEXT, action TEXT, blocked INTEGER, threat TEXT, cip TEXT, sip TEXT, bytes INTEGER, raw BLOB);
CREATE INDEX IF NOT EXISTS ev_ts ON ev(ts);
CREATE INDEX IF NOT EXISTS ev_user ON ev(user, ts);
CREATE TABLE IF NOT EXISTS roll(
  hour INTEGER, feed TEXT, user TEXT, app TEXT, blocked INTEGER, n INTEGER, bytes INTEGER, threats INTEGER,
  PRIMARY KEY(hour, feed, user, app, blocked)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER);
"""


# ------------------------------------------------------------------ parsing
def decode_body(body: bytes, encoding: str | None) -> bytes:
    """Undo Content-Encoding: gzip (Cloud NSS sends it when the feed sets that header), bounded."""
    if (encoding or "").lower().strip() in ("gzip", "x-gzip") or body[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(body, MAX_INFLATED + 1)
        if len(out) > MAX_INFLATED or d.unconsumed_tail:
            raise ValueError("body is too large once decompressed")
        return out
    return body


def parse_records(body: bytes) -> list[dict]:
    """A JSON array, one object, newline-separated objects or objects back to back. Splunk-style
    {"sourcetype": ..., "event": {...}} wrappers are unwrapped and the sourcetype kept."""
    text = body.decode("utf-8", "replace").strip().lstrip("﻿")
    if not text:
        return []
    try:
        items: list = [json.loads(text)]
    except ValueError:
        items, dec, i, n = [], json.JSONDecoder(), 0, len(text)
        while i < n:
            while i < n and text[i] in " \t\r\n,":
                i += 1
            if i >= n:
                break
            try:
                obj, i = dec.raw_decode(text, i)
            except ValueError as e:
                raise ValueError(f"not JSON at character {i}: {e.msg}") from None
            items.append(obj)
    out: list[dict] = []
    stack = list(reversed(items))
    while stack:
        it = stack.pop()
        if isinstance(it, list):
            stack.extend(reversed(it))
        elif isinstance(it, dict):
            ev = it.get("event")
            if isinstance(ev, dict):
                rec = dict(ev)
                if it.get("sourcetype") and "sourcetype" not in rec:
                    rec["sourcetype"] = it["sourcetype"]
                out.append(rec)
            else:
                out.append(it)
    return out


_NONE = {"", "none", "na", "n/a", "null", "-", "not available", "unknown"}
_BLOCK_WORDS = ("block", "drop", "deny", "denied", "reset", "reject", "quarantine")


def _first(rec: dict, *keys: str) -> str:
    for k in keys:
        v = rec.get(k)
        if v is not None and str(v).strip().lower() not in _NONE:
            return str(v).strip()
    return ""


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S %Z",
               "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S")


def _ts(rec: dict, now: int) -> int:
    for k in ("epochtime", "epoch", "eventtime_epoch", "timestamp"):
        v = rec.get(k)
        if v not in (None, ""):
            t = _int(v)
            if t > 10 ** 12:      # milliseconds
                t //= 1000
            if 946684800 < t < now + 86400:
                return t
    for k in ("datetime", "time", "eventtime", "date"):
        v = rec.get(k)
        if not isinstance(v, str) or not v.strip():
            continue
        s = v.strip()
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())
        except ValueError:
            pass
        for fmt in _TS_FORMATS:
            try:
                return int(datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp())
            except ValueError:
                continue
    return now


def detect_feed(rec: dict, hint: str | None = None) -> str:
    if hint in FEEDS:
        return hint
    st = str(rec.get("sourcetype") or rec.get("feed") or "").lower()
    for key, words in (("fw", ("-fw", "firewall")), ("dns", ("dns",)), ("tunnel", ("tunnel",)), ("web", ("web",))):
        if any(w in st for w in words):
            return key
    if any(k in rec for k in ("dns_req", "reqaction", "dns_reqtype", "reqtype")):
        return "dns"
    if any(k in rec for k in ("csip", "cdip", "nwapp", "nwsvc", "cdport")):
        return "fw"
    if any(k in rec for k in ("url", "eurl", "urlcategory", "urlcat", "appname", "useragent")):
        return "web"
    if any(k in rec for k in ("tunneltype", "tuntype", "vpncredentialname")):
        return "tunnel"
    return "other"


def normalize(rec: dict, hint: str | None = None, now: int | None = None) -> dict[str, Any]:
    """Map one record onto the columns the store indexes. Accepts the field names of Zscaler's
    default Splunk/JSON templates and the raw NSS variable names, so most feed formats just work."""
    now = now or int(time.time())
    feed = detect_feed(rec, hint)
    user = _first(rec, "user", "login", "elogin", "username", "suser", "ologin")
    dept = _first(rec, "department", "dept", "edepartment", "edept")
    loc = _first(rec, "location", "locationname", "elocation", "elocationname")
    url = _first(rec, "url", "eurl")
    host = _first(rec, "hostname", "host", "ehost", "dns_req", "req", "ereq")
    if not host and url:
        try:
            host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
        except ValueError:
            host = ""
    if feed == "fw" and not host:
        dip, dport = _first(rec, "cdip", "sdip", "destip", "dstip"), _first(rec, "cdport", "sdport", "dport")
        host = f"{dip}:{dport}" if dip and dport else dip
    if feed == "fw":
        app = _first(rec, "nwapp", "appname", "app", "nwsvc", "proto")
    elif feed == "dns":
        app = _first(rec, "dnsapp", "appname", "app", "category", "dnsappcat")
    else:
        app = _first(rec, "appname", "app", "application", "cloudapp", "urlcategory", "urlcat")
    cat = _first(rec, "urlcategory", "urlcat", "category", "ipcat", "dnsappcat", "urlsupercategory", "appclass")
    action = _first(rec, "action", "reqaction", "resaction", "dnsaction")
    acts = " ".join(_first(rec, k) for k in ("action", "reqaction", "resaction", "dnsaction")).lower()
    blocked = 1 if any(w in acts for w in _BLOCK_WORDS) else 0
    if feed == "dns" and blocked:
        action = next((_first(rec, k) for k in ("reqaction", "resaction", "action") if any(
            w in _first(rec, k).lower() for w in _BLOCK_WORDS)), action)
    threat = _first(rec, "threatname", "threatcategory", "threatcat", "malwarecat", "malwareclass", "threatclass")
    total = _int(rec.get("transactionsize") or rec.get("totalsize"))
    if not total:
        total = sum(_int(rec.get(k)) for k in ("inbytes", "outbytes")) or sum(
            _int(rec.get(k)) for k in ("requestsize", "responsesize", "reqsize", "respsize"))
    return {
        "ts": _ts(rec, now), "feed": feed, "user": user[:255], "dept": dept[:255], "loc": loc[:255],
        "app": (app or cat or "")[:255], "cat": cat[:255], "host": host[:512], "action": action[:64],
        "blocked": blocked, "threat": threat[:255],
        "cip": _first(rec, "ClientIP", "clientip", "cip", "csip", "clt_sip", "srcip", "sip_client")[:64],
        "sip": _first(rec, "serverip", "sip", "cdip", "srv_dip", "dstip", "destip")[:64],
        "bytes": max(total, 0),
    }


# ------------------------------------------------------------------ storage
@dataclass
class Segment:
    path: Path
    min_ts: int | None = None
    max_ts: int | None = None

    @property
    def name(self) -> str:
        return self.path.name

    def size(self) -> int:
        n = 0
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                n += os.stat(str(self.path) + suffix).st_size
            except OSError:
                pass
        return n


@dataclass
class Stats:
    accepted: int = 0
    batches: int = 0
    rejected: int = 0
    pruned_segments: int = 0
    pruned_bytes: int = 0
    last_batch: float | None = None
    last_error: str | None = None
    last_error_at: float | None = None
    by_feed: Counter = field(default_factory=Counter)


class NssStore:
    def __init__(self, root: str | os.PathLike, max_bytes: int = DEFAULT_MAX_GB * GB, min_free: int = DEFAULT_MIN_FREE_GB * GB):
        self.root = Path(root)
        self.max_bytes = max_bytes
        self.min_free = min_free
        self.lock = threading.RLock()
        self.stats = Stats()
        self.segments: list[Segment] = []
        self._conn: sqlite3.Connection | None = None
        self._seq = 0
        self.error: str | None = None
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            probe = self.root / ".write-test"
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as e:
            self.error = f"Cannot write to {self.root}: {e.strerror or e}"
            log.error(self.error)
            return
        self._load()

    # segment bookkeeping
    @property
    def segment_bytes(self) -> int:
        """Roll to a new segment at about 1% of the cap, so the oldest data goes in small slices."""
        return max(256 * 1024, min(GB, self.max_bytes // 100))

    def _load(self) -> None:
        for p in sorted(self.root.iterdir()):
            m = SEGMENT_RE.match(p.name)
            if not m:
                continue
            self._seq = max(self._seq, int(m.group(2)))
            seg = Segment(p)
            try:
                with self._ro(p) as c:
                    meta = dict(c.execute("SELECT k, v FROM meta"))
                seg.min_ts, seg.max_ts = meta.get("min_ts"), meta.get("max_ts")
            except sqlite3.Error as e:
                log.warning("NSS segment %s unreadable (%s); it still counts towards the cap", p.name, e)
            self.segments.append(seg)

    @staticmethod
    def _ro(p: Path) -> sqlite3.Connection:
        c = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5, check_same_thread=False)
        return c

    def _open_new(self) -> None:
        self._close_current()
        self._seq += 1
        name = f"seg-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{self._seq:06d}.db"
        seg = Segment(self.root / name)
        c = sqlite3.connect(str(seg.path), timeout=10, check_same_thread=False)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.executescript(SCHEMA)
        c.commit()
        self.segments.append(seg)
        self._conn = c

    def _current(self) -> sqlite3.Connection:
        if self._conn is None:
            last = self.segments[-1] if self.segments else None
            if last is not None and last.size() < self.segment_bytes:
                c = sqlite3.connect(str(last.path), timeout=10, check_same_thread=False)
                try:
                    c.execute("PRAGMA journal_mode=WAL")
                    c.executescript(SCHEMA)
                    self._conn = c
                except sqlite3.Error:
                    c.close()
            if self._conn is None:
                self._open_new()
        return self._conn

    def _close_current(self) -> None:
        if self._conn is not None:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    def used_bytes(self) -> int:
        return sum(s.size() for s in self.segments)

    def disk_free(self) -> int | None:
        try:
            return shutil.disk_usage(self.root).free
        except OSError:
            return None

    def enforce(self, incoming: int = 0) -> None:
        """Delete the oldest segments until the store (plus what is about to be written) fits the cap
        and the disk keeps its free-space floor. The segment being written is closed and dropped too
        if it alone is over the cap."""
        with self.lock:
            while self.segments:
                used = self.used_bytes()
                free = self.disk_free()
                over_cap = used + incoming > self.max_bytes
                low_disk = free is not None and free < self.min_free and len(self.segments) > 1
                if not (over_cap or low_disk):
                    break
                oldest = self.segments[0]
                if len(self.segments) == 1 or (self._conn is not None and oldest is self.segments[-1]):
                    self._close_current()
                size = oldest.size()
                for suffix in ("", "-wal", "-shm", "-journal"):
                    try:
                        os.unlink(str(oldest.path) + suffix)
                    except FileNotFoundError:
                        pass
                self.segments.pop(0)
                self.stats.pruned_segments += 1
                self.stats.pruned_bytes += size
                log.info("NSS store: removed oldest segment %s (%d bytes) to stay under the cap", oldest.name, size)

    def write(self, rows: list[dict], raws: list[dict]) -> int:
        if self.error:
            raise OSError(self.error)
        if not rows:
            return 0
        packed = [zlib.compress(json.dumps(r, separators=(",", ":"), default=str).encode(), 6) for r in raws]
        estimate = sum(len(p) for p in packed) + 200 * len(rows)
        with self.lock:
            self.enforce(incoming=estimate)
            free = self.disk_free()
            if free is not None and free < min(self.min_free, GB) // 2:
                raise OSError(f"only {free // (1000 ** 2)} MB free on the log disk")
            c = self._current()
            seg = self.segments[-1]
            roll: dict[tuple, list[int]] = defaultdict(lambda: [0, 0, 0])
            cols = ("ts", "feed", "user", "dept", "loc", "app", "cat", "host", "action", "blocked", "threat", "cip", "sip", "bytes")
            c.executemany(f"INSERT INTO ev({','.join(cols)}, raw) VALUES ({','.join('?' * (len(cols) + 1))})",
                          [tuple(r[k] for k in cols) + (p,) for r, p in zip(rows, packed)])
            for r in rows:
                agg = roll[(r["ts"] // 3600 * 3600, r["feed"], r["user"], r["app"], r["blocked"])]
                agg[0] += 1
                agg[1] += r["bytes"]
                agg[2] += 1 if r["threat"] else 0
            c.executemany("INSERT INTO roll VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(hour, feed, user, app, blocked) DO UPDATE SET "
                          "n = n + excluded.n, bytes = bytes + excluded.bytes, threats = threats + excluded.threats",
                          [k + tuple(v) for k, v in roll.items()])
            lo, hi = min(r["ts"] for r in rows), max(r["ts"] for r in rows)
            seg.min_ts = lo if seg.min_ts is None else min(seg.min_ts, lo)
            seg.max_ts = hi if seg.max_ts is None else max(seg.max_ts, hi)
            c.executemany("INSERT INTO meta VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                          [("min_ts", seg.min_ts), ("max_ts", seg.max_ts)])
            c.commit()
            if seg.size() >= self.segment_bytes:
                self._open_new()
            self.enforce()
            self.stats.accepted += len(rows)
            self.stats.batches += 1
            self.stats.last_batch = time.time()
            self.stats.by_feed.update(r["feed"] for r in rows)
        return len(rows)

    def ingest(self, body: bytes, encoding: str | None = None, feed_hint: str | None = None) -> int:
        try:
            records = parse_records(decode_body(body, encoding))
        except (ValueError, OSError, zlib.error, EOFError, gzip.BadGzipFile) as e:
            self.note_error(f"Could not read a batch: {e}")
            raise ValueError(str(e)) from None
        now = int(time.time())
        rows = [normalize(r, feed_hint, now) for r in records]
        return self.write(rows, records)

    def note_error(self, msg: str) -> None:
        self.stats.rejected += 1
        self.stats.last_error, self.stats.last_error_at = msg[:300], time.time()

    def clear(self) -> None:
        with self.lock:
            self._close_current()
            for seg in self.segments:
                for suffix in ("", "-wal", "-shm", "-journal"):
                    try:
                        os.unlink(str(seg.path) + suffix)
                    except FileNotFoundError:
                        pass
            self.segments = []

    # ------------------------------------------------------------------ reading
    def _segments_since(self, since: int | None) -> list[Segment]:
        with self.lock:
            segs = list(self.segments)
        return [s for s in segs if since is None or s.max_ts is None or s.max_ts >= since]

    def _query(self, seg: Segment, sql: str, args: Iterable = ()) -> list[tuple]:
        if self._conn is not None and self.segments and seg is self.segments[-1]:
            with self.lock:
                try:
                    return self._conn.execute(sql, tuple(args)).fetchall()
                except sqlite3.Error:
                    return []
        try:
            c = self._ro(seg.path)
            try:
                return c.execute(sql, tuple(args)).fetchall()
            finally:
                c.close()
        except sqlite3.Error:
            return []      # deleted by the cap mid-query, or still being created

    def oldest_ts(self) -> int | None:
        vals = [s.min_ts for s in self._segments_since(None) if s.min_ts is not None]
        return min(vals) if vals else None

    def newest_ts(self) -> int | None:
        vals = [s.max_ts for s in self._segments_since(None) if s.max_ts is not None]
        return max(vals) if vals else None

    def summary(self, since: int | None, user: str | None = None, top: int = 10) -> dict:
        """Totals and top lists for the activity dashboard, from the hourly roll-ups."""
        hour = since // 3600 * 3600 if since else None
        where, args = [], []
        if hour is not None:
            where.append("hour >= ?")
            args.append(hour)
        if user is not None:
            where.append("user = ?")
            args.append(user)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        users: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
        apps: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
        feeds: Counter = Counter()
        hours: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        blocked_pairs: Counter = Counter()
        for seg in self._segments_since(since):
            for u, a, f, h, b, n, by, th in self._query(
                    seg, f"SELECT user, app, feed, hour, blocked, SUM(n), SUM(bytes), SUM(threats) FROM roll {w} "
                    "GROUP BY user, app, feed, hour, blocked", args):
                for d, k in ((users, u), (apps, a)):
                    d[k][0] += n
                    d[k][1] += by or 0
                    d[k][2] += n if b else 0
                    d[k][3] += th or 0
                feeds[f] += n
                hours[h][0] += n
                hours[h][1] += n if b else 0
                if b:
                    blocked_pairs[(u, a)] += n
        tot = [sum(v[i] for v in users.values()) for i in range(4)]

        def rank(d, idx, n=top):
            return [(k, *v) for k, v in sorted(d.items(), key=lambda kv: -kv[1][idx]) if v[idx]][:n]
        return {
            "events": tot[0], "bytes": tot[1], "blocked": tot[2], "threats": tot[3],
            "users": len([u for u in users if u]), "apps": len([a for a in apps if a]),
            "top_users": rank(users, 0), "top_users_bytes": rank(users, 1), "top_blocked_users": rank(users, 2),
            "top_threat_users": rank(users, 3, 5), "top_apps": rank(apps, 0), "top_apps_bytes": rank(apps, 1),
            "top_blocked_apps": rank(apps, 2), "feeds": feeds.most_common(),
            "blocked_pairs": [(u, a, n) for (u, a), n in blocked_pairs.most_common(top)],
            "hours": sorted(hours.items()),
        }

    def events(self, *, since: int | None = None, before: int | None = None, user: str | None = None,
               feed: str | None = None, blocked: bool = False, q: str | None = None, limit: int = 100) -> list[dict]:
        """Newest events first across segments, filtered; stops early once older segments can't add to the page."""
        where, args = [], []
        if since:
            where.append("ts >= ?"); args.append(since)
        if before:
            where.append("ts < ?"); args.append(before)
        if user is not None:
            where.append("user = ?"); args.append(user)
        if feed:
            where.append("feed = ?"); args.append(feed)
        if blocked:
            where.append("blocked = 1")
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(host LIKE ? ESCAPE '\\' OR app LIKE ? ESCAPE '\\' OR cat LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' "
                         "OR action LIKE ? ESCAPE '\\' OR threat LIKE ? ESCAPE '\\' OR cip LIKE ? ESCAPE '\\')")
            args.extend([like] * 7)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        cols = "id, ts, feed, user, dept, loc, app, cat, host, action, blocked, threat, cip, sip, bytes"
        out: list[dict] = []
        segs = sorted(self._segments_since(since), key=lambda s: (s.max_ts or 0), reverse=True)
        for seg in segs:
            if len(out) >= limit and seg.max_ts is not None and seg.max_ts < out[limit - 1]["ts"]:
                break
            for row in self._query(seg, f"SELECT {cols} FROM ev {w} ORDER BY ts DESC LIMIT ?", args + [limit]):
                d = dict(zip(cols.split(", "), row))
                d["seg"] = seg.name
                out.append(d)
            out.sort(key=lambda d: (d["ts"], d["id"]), reverse=True)
            del out[limit:]
        return out

    def event(self, seg_name: str, eid: int) -> dict | None:
        if not SEGMENT_RE.match(seg_name):
            return None
        seg = next((s for s in self._segments_since(None) if s.name == seg_name), None)
        if seg is None:
            return None
        rows = self._query(seg, "SELECT id, ts, feed, user, dept, loc, app, cat, host, action, blocked, threat, cip, sip, bytes, raw "
                                "FROM ev WHERE id = ?", (eid,))
        if not rows:
            return None
        cols = "id ts feed user dept loc app cat host action blocked threat cip sip bytes".split()
        d = dict(zip(cols, rows[0][:-1]))
        try:
            d["raw"] = json.loads(zlib.decompress(rows[0][-1]))
        except (zlib.error, ValueError, TypeError):
            d["raw"] = None
        d["seg"] = seg_name
        return d

    def info(self) -> dict:
        with self.lock:
            segs = list(self.segments)
        used = sum(s.size() for s in segs)
        return {"dir": str(self.root), "error": self.error, "used": used, "max": self.max_bytes, "min_free": self.min_free,
                "free": self.disk_free(), "segments": len(segs), "segment_bytes": self.segment_bytes,
                "oldest": self.oldest_ts(), "newest": self.newest_ts(), "stats": self.stats,
                "pct": round(100 * used / self.max_bytes, 1) if self.max_bytes else 0}
