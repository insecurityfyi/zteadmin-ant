"""MIB files: compile vendor MIBs with pysmi and turn object names into numeric OIDs.

Pollers never load MIBs; they only ever see numeric OIDs. MIBs are used here, on the server, so people can pick
``ACME-MIB::acmeCpuLoad`` from a search box instead of typing ``1.3.6.1.4.1.99999.1.1``, and so a custom OID gets
sensible defaults (gauge or counter, units, the names of enumerated states) from the MIB's own definition.

The standard MIBs most vendor MIBs import (SNMPv2-SMI, SNMPv2-TC, IF-MIB, SNMP-FRAMEWORK-MIB, INET-ADDRESS-MIB and
friends) ship in ``mibs/``; anything else a vendor MIB imports has to be uploaded too.
"""
from __future__ import annotations

import json
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

BUNDLED = Path(__file__).parent / "mibs"
MODULE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s+DEFINITIONS\s*(?:[A-Z]+\s+TAGS\s*)?::=\s*BEGIN", re.M)
NUMERIC_RE = re.compile(r"^\.?\d+(\.\d+)+$")
NAME_RE = re.compile(r"^(?:(?P<mod>[A-Za-z][A-Za-z0-9-]*)::)?(?P<name>[A-Za-z][A-Za-z0-9-]*)(?P<suffix>(\.\d+)*)$")
MAX_MIB_BYTES = 4 * 2**20
_lock = threading.Lock()
_bundled: list[dict[str, Any]] | None = None

COUNTERS = ("Counter32", "Counter64", "Counter", "ZeroBasedCounter32", "ZeroBasedCounter64")
TEXTS = ("OCTET STRING", "OctetString", "DisplayString", "SnmpAdminString", "PhysAddress", "MacAddress", "IpAddress",
         "OBJECT IDENTIFIER", "ObjectIdentifier", "DateAndTime", "InetAddress")
UNITS = {"percent": "%", "percentage": "%", "%": "%", "seconds": "s", "second": "s", "milliseconds": "ms",
         "millisecond": "ms", "bytes": "B", "octets": "B", "bits": "b", "celsius": "°C", "degrees celsius": "°C",
         "degrees": "°C", "watts": "W", "volts": "V", "millivolts": "mV", "amperes": "A", "milliamps": "mA", "rpm": "rpm",
         "minutes": "min", "kilobytes": "KB", "megabytes": "MB", "packets": "pkts"}


class MibError(ValueError):
    pass


def module_names(text: str) -> list[str]:
    """The module names a MIB file defines (usually one)."""
    return MODULE_RE.findall(text or "")


def _objects(js: str, tcs: dict[str, dict]) -> list[dict[str, Any]]:
    """The OID-carrying definitions of one compiled module, flattened for search and for the custom OID form."""
    out = []
    for name, v in json.loads(js).items():
        if not isinstance(v, dict) or "oid" not in v:
            continue
        cls = v.get("class")
        if cls not in ("objecttype", "objectidentity", "moduleidentity"):
            continue
        syn = dict(v.get("syntax") or {})
        tc = tcs.get(str(syn.get("type") or ""))
        base, enum = syn.get("type"), (syn.get("constraints") or {}).get("enumeration")
        if tc:                                   # a textual convention: use its base type and its enumeration
            base = (tc.get("type") or {}).get("type") or base
            enum = enum or ((tc.get("type") or {}).get("constraints") or {}).get("enumeration")
        out.append({"name": name, "oid": v["oid"], "node": v.get("nodetype") or ("object" if cls != "objecttype" else "scalar"),
                    "type": syn.get("type"), "base": base, "units": v.get("units"), "access": v.get("maxaccess"),
                    "states": {str(n): str(label) for label, n in enum.items()} if isinstance(enum, dict) else None,
                    "descr": " ".join(str(v.get("description") or "").split())[:500] or None})
    return sorted(out, key=lambda o: [int(x) for x in o["oid"].split(".")])


def compile_modules(texts: dict[str, str], wanted: list[str]) -> tuple[dict[str, list[dict]], dict[str, str]]:
    """Compile ``wanted`` modules. ``texts`` maps module names to MIB source; the bundled MIBs fill in imports.

    Returns ``({module: objects}, {module: problem})``.
    """
    from pysmi.codegen import JsonCodeGen
    from pysmi.compiler import MibCompiler
    from pysmi.parser import SmiStarParser
    from pysmi.reader import FileReader
    from pysmi.writer import CallbackWriter

    compiled: dict[str, str] = {}
    with _lock, tempfile.TemporaryDirectory() as tmp:
        for name, text in texts.items():
            (Path(tmp) / name).write_text(text, encoding="utf-8")
        compiler = MibCompiler(SmiStarParser(), JsonCodeGen(),
                               CallbackWriter(lambda n, data, cbCtx=None: compiled.__setitem__(n, data)))
        compiler.add_sources(FileReader(tmp, recursive=False), FileReader(str(BUNDLED), recursive=False))
        status = compiler.compile(*wanted, noDeps=False, rebuild=True, genTexts=True)
    tcs: dict[str, dict] = {}
    for js in compiled.values():
        for name, v in json.loads(js).items():
            if isinstance(v, dict) and v.get("class") == "textualconvention":
                tcs[name] = v
    missing = sorted(m for m, st in status.items() if str(st) == "missing")
    good, bad = {}, {}
    for m in wanted:
        st = status.get(m)
        if m in compiled:
            good[m] = _objects(compiled[m], tcs)
        elif missing:
            bad[m] = "It imports MIBs that are not uploaded yet: " + ", ".join(missing) + ". Upload those too."
        else:
            err = getattr(st, "error", None)
            bad[m] = f"Could not compile it: {err or st or 'unknown error'}"[:2000]
    return good, bad


def bundled_objects() -> list[dict[str, Any]]:
    """Every object in the bundled standard MIBs, compiled once per process."""
    global _bundled
    if _bundled is None:
        names = sorted(p.stem for p in BUNDLED.glob("*.txt"))
        good, _ = compile_modules({}, names)
        # SMIv2 MIBs before the SMIv1 RFC1213-MIB they replace, so tcpRetransSegs is TCP-MIB's (a Counter32)
        order = sorted(good, key=lambda m: (m.startswith("RFC"), m))
        _bundled = [{**o, "module": m} for m in order for o in good[m]]
    return _bundled


def all_objects(s) -> list[dict[str, Any]]:
    """Uploaded MIBs first (a vendor's own definition wins), then the bundled ones."""
    from sqlalchemy import select
    from .models import MibModule
    out = []
    for name, objs in s.execute(select(MibModule.name, MibModule.objects).order_by(MibModule.name)):
        out += [{**o, "module": name} for o in objs or []]
    return out + bundled_objects()


def search(s, q: str, limit: int = 40) -> list[dict[str, Any]]:
    """Objects whose name, module, OID or description matches; readable leaves (scalars and columns) first."""
    q = (q or "").strip()
    if not q:
        return []
    ql = q.lower().lstrip(".")
    mod, _, name_q = ql.rpartition("::")
    hits, seen = [], set()
    for o in all_objects(s):
        if (o["name"], o["oid"]) in seen:
            continue
        seen.add((o["name"], o["oid"]))
        if mod and o["module"].lower() != mod:
            continue
        name = o["name"].lower()
        if name == name_q or o["oid"] == ql:
            rank = 0
        elif name.startswith(name_q):
            rank = 1
        elif name_q in name or (ql[0].isdigit() and o["oid"].startswith(ql)):
            rank = 2
        elif len(name_q) >= 4 and name_q in (o.get("descr") or "").lower():
            rank = 4
        else:
            continue
        if o["node"] not in ("scalar", "column"):
            rank += 1
        hits.append((rank, len(o["name"]), o))
    hits.sort(key=lambda h: (h[0], h[1]))
    return [h[2] for h in hits[:limit]]


def find(s, text: str) -> tuple[str, dict[str, Any] | None]:
    """Turn ``1.3.6...``, ``name``, ``name.0`` or ``MODULE::name.idx`` into (numeric OID, the MIB object or None)."""
    text = (text or "").strip()
    if not text:
        raise MibError("Enter an OID or a MIB object name.")
    if NUMERIC_RE.match(text):
        oid = text.lstrip(".")
        objs = all_objects(s)
        exact = next((o for o in objs if o["oid"] == oid), None)
        if exact:
            return oid, exact
        parent = max((o for o in objs if oid.startswith(o["oid"] + ".") and o["node"] in ("scalar", "column")),
                     key=lambda o: len(o["oid"]), default=None)
        return oid, parent
    m = NAME_RE.match(text)
    if not m:
        raise MibError(f"“{text}” is neither a numeric OID nor a MIB object name.")
    mod, name, suffix = m.group("mod"), m.group("name"), m.group("suffix") or ""
    for o in all_objects(s):
        if o["name"] == name and (not mod or o["module"] == mod):
            return o["oid"] + suffix, o
    where = f" in {mod}" if mod else ""
    raise MibError(f"No object called {name}{where} in the uploaded or standard MIBs. Upload the MIB that defines it, "
                   "or enter the numeric OID.")


def suggest(o: dict[str, Any] | None) -> dict[str, Any]:
    """Form defaults for a MIB object: how to poll it, what kind of value it is, and its unit."""
    if not o:
        return {}
    base = str(o.get("base") or o.get("type") or "")
    out: dict[str, Any] = {"mode": "walk" if o.get("node") == "column" else "get", "mib_name": f"{o.get('module')}::{o['name']}"}
    if o.get("states"):
        out["value_type"], out["states"] = "state", o["states"]
    elif base in COUNTERS:
        out["value_type"] = "counter"
    elif base in TEXTS or o.get("type") in TEXTS:
        out["value_type"] = "text"
    else:
        out["value_type"] = "gauge"
    if base == "TimeTicks":
        out["scale"], out["unit"] = 0.01, "s"
    units = str(o.get("units") or "").strip()
    if units and "unit" not in out:
        out["unit"] = UNITS.get(units.lower(), units[:16])
    if out["value_type"] == "counter" and out.get("unit") in ("B", "b", "pkts", None, ""):
        out["unit"] = (out.get("unit") or "") + "/s"
    return out


def store(s, filename: str, raw: bytes) -> list[str]:
    """Save an uploaded MIB file, then (re)compile it and every earlier upload that was waiting on an import.

    Returns the module names it defined. Raises MibError for a file that is not a MIB.
    """
    from sqlalchemy import select
    from .models import MibModule, utcnow
    if len(raw) > MAX_MIB_BYTES:
        raise MibError("That file is larger than 4 MB; it is probably not a MIB.")
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
    names = module_names(text)
    if not names:
        raise MibError(f"{filename} does not look like a MIB: no “NAME DEFINITIONS ::= BEGIN” line.")
    rows = {m.name: m for m in s.scalars(select(MibModule))}
    for name in names:
        row = rows.get(name)
        if row is None:
            row = rows[name] = MibModule(name=name[:120], text=text)
            s.add(row)
        row.text, row.filename, row.uploaded_at = text, filename[:255], utcnow()
    recompile(s, [n for n in rows if n in names or rows[n].error])
    return names


def recompile(s, names: list[str] | None = None) -> None:
    from sqlalchemy import select
    from .models import MibModule
    rows = {m.name: m for m in s.scalars(select(MibModule))}
    wanted = [n for n in (names if names is not None else list(rows)) if n in rows]
    if not wanted:
        return
    good, bad = compile_modules({n: r.text for n, r in rows.items()}, wanted)
    for n in wanted:
        rows[n].objects = good.get(n)
        rows[n].error = bad.get(n) if n not in good else None
    s.flush()
