"""The Guacamole protocol, just enough to talk to guacd and relay it to guacamole-common-js.

An instruction is ``<len>.<value>,<len>.<value>,...;`` where the first element is the opcode and each length
counts Unicode code points (not bytes)."""
from __future__ import annotations

import codecs


def encode(*elements: object) -> str:
    parts = []
    for e in elements:
        s = str(e)
        parts.append(f"{len(s)}.{s}")
    return ",".join(parts) + ";"


class ProtocolError(Exception):
    pass


class Parser:
    """Incremental parser: feed bytes (or text) and get back whole instructions, raw and split."""

    MAX_BUFFER = 8 * 2**20

    def __init__(self) -> None:
        self._dec = codecs.getincrementaldecoder("utf-8")("strict")
        self._buf = ""
        self._pos = 0          # where the next unparsed instruction starts in _buf

    def feed(self, data: bytes | str) -> list[tuple[str, list[str]]]:
        self._buf += self._dec.decode(data) if isinstance(data, (bytes, bytearray)) else data
        out: list[tuple[str, list[str]]] = []
        buf = self._buf
        while True:
            start = i = self._pos
            elements: list[str] = []
            complete = False
            while True:
                dot = buf.find(".", i)
                if dot < 0:
                    break
                length_s = buf[i:dot]
                if not length_s.isdigit():
                    raise ProtocolError(f"bad element length {length_s[:10]!r}")
                end = dot + 1 + int(length_s)
                if end >= len(buf):
                    break
                elements.append(buf[dot + 1:end])
                term = buf[end]
                if term == ";":
                    complete = True
                    i = end + 1
                    break
                if term != ",":
                    raise ProtocolError("bad element terminator")
                i = end + 1
            if not complete:
                break
            out.append((buf[start:i], elements))
            self._pos = i
        if self._pos:
            self._buf = buf[self._pos:]
            self._pos = 0
        if len(self._buf) > self.MAX_BUFFER:
            raise ProtocolError("instruction too long")
        return out
