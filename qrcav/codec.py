"""
Canonical binary codec.

Every protocol message (handshake flights, consensus messages, certificates,
application payloads) is encoded with this one function, for two reasons:

1. Signatures need a *canonical* byte string. Two parties that encode the same
   logical message must produce identical bytes, or a signature made by one
   will not verify for the other. Dictionaries are therefore encoded with keys
   sorted.
2. On-wire size is a headline measurement of this project, so the encoding is
   compact binary (a small subset of CBOR's ideas), not JSON or base64.

Supported types: None, bool, int (signed, 64-bit), float, bytes, str, list,
tuple (encoded as list), dict with str keys.
"""

from __future__ import annotations

import struct

_NONE, _FALSE, _TRUE, _INT, _FLOAT, _BYTES, _STR, _LIST, _DICT = range(9)

MAX_DEPTH = 32
MAX_LEN = 16 * 1024 * 1024


class CodecError(ValueError):
    """Malformed or non-canonical input."""


def _uvarint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_uvarint(buf: memoryview, i: int) -> tuple[int, int]:
    shift = 0
    n = 0
    while True:
        if i >= len(buf):
            raise CodecError("truncated varint")
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, i
        shift += 7
        if shift > 63:
            raise CodecError("varint too long")


def _enc(obj, out: bytearray, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CodecError("nesting too deep")
    if obj is None:
        out.append(_NONE)
    elif obj is True:
        out.append(_TRUE)
    elif obj is False:
        out.append(_FALSE)
    elif isinstance(obj, int):
        out.append(_INT)
        out += struct.pack(">q", obj)
    elif isinstance(obj, float):
        out.append(_FLOAT)
        out += struct.pack(">d", obj)
    elif isinstance(obj, (bytes, bytearray, memoryview)):
        b = bytes(obj)
        out.append(_BYTES)
        out += _uvarint(len(b))
        out += b
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        out.append(_STR)
        out += _uvarint(len(b))
        out += b
    elif isinstance(obj, (list, tuple)):
        out.append(_LIST)
        out += _uvarint(len(obj))
        for item in obj:
            _enc(item, out, depth + 1)
    elif isinstance(obj, dict):
        out.append(_DICT)
        out += _uvarint(len(obj))
        for k in sorted(obj):
            if not isinstance(k, str):
                raise CodecError("dict keys must be str")
            kb = k.encode("utf-8")
            out += _uvarint(len(kb))
            out += kb
            _enc(obj[k], out, depth + 1)
    else:
        raise CodecError(f"unsupported type {type(obj).__name__}")


def encode(obj) -> bytes:
    """Encode an object to canonical bytes."""
    out = bytearray()
    _enc(obj, out, 0)
    return bytes(out)


def _dec(buf: memoryview, i: int, depth: int):
    if depth > MAX_DEPTH:
        raise CodecError("nesting too deep")
    if i >= len(buf):
        raise CodecError("truncated")
    t = buf[i]
    i += 1
    if t == _NONE:
        return None, i
    if t == _TRUE:
        return True, i
    if t == _FALSE:
        return False, i
    if t == _INT:
        if i + 8 > len(buf):
            raise CodecError("truncated int")
        return struct.unpack(">q", buf[i:i + 8])[0], i + 8
    if t == _FLOAT:
        if i + 8 > len(buf):
            raise CodecError("truncated float")
        return struct.unpack(">d", buf[i:i + 8])[0], i + 8
    if t in (_BYTES, _STR):
        n, i = _read_uvarint(buf, i)
        if n > MAX_LEN or i + n > len(buf):
            raise CodecError("bad length")
        raw = bytes(buf[i:i + n])
        return (raw if t == _BYTES else raw.decode("utf-8")), i + n
    if t == _LIST:
        n, i = _read_uvarint(buf, i)
        if n > MAX_LEN:
            raise CodecError("bad length")
        items = []
        for _ in range(n):
            v, i = _dec(buf, i, depth + 1)
            items.append(v)
        return items, i
    if t == _DICT:
        n, i = _read_uvarint(buf, i)
        if n > MAX_LEN:
            raise CodecError("bad length")
        d = {}
        prev = None
        for _ in range(n):
            kl, i = _read_uvarint(buf, i)
            if i + kl > len(buf):
                raise CodecError("bad key")
            k = bytes(buf[i:i + kl]).decode("utf-8")
            i += kl
            if prev is not None and k <= prev:
                raise CodecError("non-canonical key order")
            prev = k
            d[k], i = _dec(buf, i, depth + 1)
        return d, i
    raise CodecError(f"unknown tag {t}")


def decode(data: bytes):
    """Decode canonical bytes. Rejects trailing data and non-canonical maps."""
    buf = memoryview(data)
    obj, i = _dec(buf, 0, 0)
    if i != len(buf):
        raise CodecError("trailing bytes")
    return obj


def decode_dict(data: bytes, *required: str) -> dict:
    """Decode and require a dict containing the given keys."""
    obj = decode(data)
    if not isinstance(obj, dict):
        raise CodecError("expected a map")
    for k in required:
        if k not in obj:
            raise CodecError(f"missing field {k!r}")
    return obj
