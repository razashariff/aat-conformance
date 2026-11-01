"""RFC 8785 JSON Canonicalization Scheme, written from the RFC text.

Kept separate from any third-party JCS library so the conformance verifier has
its own canonicalizer; the corpus generator cross-checks every record against
an independent library (rfc8785) before a vector is written.
"""
from decimal import Decimal

MAX_SAFE = 2 ** 53


class JCSError(ValueError):
    pass


def _num(x) -> str:
    if isinstance(x, bool):
        raise JCSError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > MAX_SAFE:
            raise JCSError("integer outside the IEEE 754 exact range (I-JSON)")
        return str(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise JCSError("NaN/Infinity are not JSON")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # shortest round-trip digits (Python repr == ECMAScript's choice of digits)
    d = Decimal(repr(abs(x))).normalize()
    t = d.as_tuple()
    digits = "".join(map(str, t.digits))
    k = len(digits)
    n = t.exponent + k            # value = 0.digits * 10^n
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e > 0 else "-") + str(abs(e))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _str(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JCSError("lone surrogate in string")
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _ser(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, (int, float)):
        out.append(_num(v))
    elif isinstance(v, str):
        out.append(_str(v))
    elif isinstance(v, list):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _ser(x, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda k: k.encode("utf-16-be"))):
            if not isinstance(k, str):
                raise JCSError("object key is not a string")
            if i:
                out.append(",")
            out.append(_str(k))
            out.append(":")
            _ser(v[k], out)
        out.append("}")
    else:
        raise JCSError("unsupported type %r" % type(v))


def canonicalize(v) -> bytes:
    out = []
    _ser(v, out)
    return "".join(out).encode("utf-8")
