#!/usr/bin/env python3
"""Generate the AAT -09 conformance corpus into vectors/.

Every vector declares its expected verdict BY HAND, from the draft text. The
verifier in aatc/ is never consulted while writing a vector; run.py compares
the two afterwards. Keys are derived from fixed seeds (TEST ONLY), UUIDs from a
fixed RNG, and ES256 signing is deterministic (RFC 6979), so the corpus
regenerates byte-identically except for ML-DSA signatures (hedged by default).
"""
import copy, hashlib, json, os, random, shutil, uuid
from datetime import datetime, timedelta, timezone

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, utils

from aatc.jcs import canonicalize
from aatc.verify import b64u, thumbprint, record_hash, signed_bytes_hash, leaf_hash, node, merkle_root

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "vectors")
rng = random.Random(20261101)


def uid():
    b = bytearray(rng.getrandbits(8) for _ in range(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def hx(label):
    return hashlib.sha256(label.encode()).hexdigest()


# ---------------- keys (TEST ONLY, derived from public seeds) ----------------
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class Key:
    def __init__(self, name, alg):
        self.name, self.alg = name, alg
        seed = hashlib.sha256(("aat-conformance-test-key/" + name).encode()).digest()
        self.seed = seed.hex()
        if alg == "ES256":
            self.priv = ec.derive_private_key(int.from_bytes(seed, "big") % (N_P256 - 1) + 1, ec.SECP256R1())
            n = self.priv.public_key().public_numbers()
            self.jwk = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
        elif alg == "Ed25519":
            self.priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}
        else:
            self.priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
            raw = self.priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.jwk = {"kty": "AKP", "alg": "ML-DSA-65", "pub": b64u(raw)}
        self.kid = thumbprint(self.jwk)

    def sign_hash(self, h, alg=None):
        alg = alg or self.alg
        if alg == "ES256":
            der = self.priv.sign(h, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))
            r, s = utils.decode_dss_signature(der)
            return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return b64u(self.priv.sign(h))


K = {n: Key(n, a) for n, a in [("agent", "ES256"), ("agent2", "Ed25519"), ("recorder", "ES256"),
                                ("pq-recorder", "ML-DSA-65"), ("classical", "ES256"), ("deleter", "ES256"),
                                ("rogue", "ES256")]}
PUBLISHED = ["agent", "agent2", "recorder", "pq-recorder", "classical", "deleter"]   # "rogue" is deliberately unpublished

AGENT, AGENT2 = "urn:agent:payment-bot.example", "urn:agent:research-bot.example"
RECORDER, PQREC = "urn:gateway:recorder.example", "urn:gateway:pq-recorder.example"
AGENT_KIDS = {AGENT: K["agent"].kid, AGENT2: K["agent2"].kid}
PRINCIPAL = {"principal_type": "human", "principal_id": "urn:user:role:treasury-approver", "authority_ref": None}
T0 = datetime(2026, 11, 1, 9, 0, 0, tzinfo=timezone.utc)


def ts(sec, fmt="ms"):
    t = T0 + timedelta(seconds=sec)
    if fmt == "us":
        return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


# ---------------- record + session builders ----------------
def rec(sid, n, at, detail, outcome="success", phase="post_execution", agent=AGENT, trust="L1", **extra):
    r = {"record_id": uid(), "timestamp": ts(n), "agent_id": agent, "principal": copy.deepcopy(PRINCIPAL),
         "agent_version": "2.1.0", "session_id": sid, "action_type": at, "action_detail": detail,
         "outcome": outcome, "trust_level": trust, "parent_record_id": None, "prev_hash": None, "record_phase": phase}
    r.update(extra)
    return r


def genesis(sid, agent=AGENT, trust="L1", **detail):
    d = {"event": "session_start", "new_state": "active", "trigger": "scheduled",
         "config_hash": hx("config"), "recording_mode": "self", "enabled_tools": ["balance_query", "payment_transfer"]}
    d.update(detail)
    return rec(sid, 0, "lifecycle", d, phase="concurrent", agent=agent, trust=trust)


def close(sid, n, agent=AGENT, trust="L1"):
    return rec(sid, n, "lifecycle", {"event": "session_end", "session_hash": None, "record_count": 0, "duration_ms": n * 1000},
               phase="post_execution", agent=agent, trust=trust)


def base(agent=AGENT, trust="L1", with_close=True, **gd):
    sid = uid()
    g = genesis(sid, agent, trust, **gd)
    d = rec(sid, 1, "decision", {"decision_type": "approve", "policy_ref": "pol-7", "confidence": 0.92},
            phase="pre_execution", agent=agent, trust=trust)
    c = rec(sid, 2, "tool_call", {"tool_name": "balance_query", "tool_server": "https://tools.example/mcp",
                                  "parameters_hash": hx("params")}, agent=agent, trust=trust)
    rp = rec(sid, 3, "tool_response", {"tool_name": "balance_query", "response_hash": hx("resp"),
                                       "parent_call_id": c["record_id"], "response_size": 512}, agent=agent, trust=trust)
    out = [g, d, c, rp]
    if with_close:
        out.append(close(sid, 4, agent, trust))
    return out


def is_close(r):
    return r.get("action_type") == "lifecycle" and isinstance(r.get("action_detail"), dict) and r["action_detail"].get("event") == "session_end" \
        and "session_hash" in r["action_detail"]


def finalize(recs, signer=None, edit=None, tomb_next=None):
    """Chain (6.1), fill the close record's session_hash (8.3), sign (6.2). Each step runs in order, so
    edit(i, r) can plant a defect that the chain and signatures then faithfully cover.
    signer(i, r) -> (Key, sig_alg or None to omit, extra) or None."""
    for i, r in enumerate(recs):
        if i > 0:
            r["parent_record_id"] = recs[i - 1].get("record_id")
            prev = recs[i - 1]
            r["prev_hash"] = prev["tombstone_hash"] if prev.get("_tomb") else record_hash(prev).hex()
        if is_close(r):
            r["action_detail"]["record_count"] = len(recs)
            r["action_detail"]["session_hash"] = hashlib.sha256(b"".join(bytes.fromhex(x.get("prev_hash") or "") for x in recs[1:i + 1])).hexdigest()
        if edit:
            edit(i, r)
        if signer:
            s = signer(i, r)
            if s:
                key, alg = s[0], s[1]
                r.pop("signature", None)
                if alg:
                    r["sig_alg"] = alg
                r["signer_kid"] = key.kid
                r["signature"] = key.sign_hash(signed_bytes_hash(_strip(r)), alg or "ES256")
    for r in recs:
        r.pop("_tomb", None)
    return recs


def _strip(r):
    return {k: v for k, v in r.items() if not k.startswith("_")}


def sign_all(key, alg="ES256"):
    return lambda i, r: (key, alg)


# ---------------- writer ----------------
VECTORS = []


def dump_line(r, style="python"):
    if style == "jcs":
        return canonicalize(r).decode("utf-8")
    if style == "pretty-reverse":
        def rev(o):
            if isinstance(o, dict):
                return {k: rev(o[k]) for k in sorted(o, reverse=True)}
            if isinstance(o, list):
                return [rev(x) for x in o]
            return o
        return json.dumps(rev(r), ensure_ascii=True, separators=(" , ", " : "))
    return json.dumps(r, ensure_ascii=False)


def V(vid, title, sections, verdict, completeness=None, recs=None, raw=None, errors=(), warnings=(), merkle="absent",
      options=None, normative=True, note=None, style="python"):
    if completeness is None:
        completeness = "complete" if verdict == "accept" else "n/a"
    d = os.path.join(OUT, vid)
    os.makedirs(d)
    if raw is None:
        lines = []
        for r in recs:
            r = _strip(r)
            try:
                assert canonicalize(r) == rfc8785.dumps(r), vid
            except Exception as e:      # deliberately non-I-JSON content is written by the vector itself
                if not isinstance(e, AssertionError) and verdict == "accept":
                    raise
            lines.append(dump_line(r, style))
        raw = ("\n".join(lines) + "\n").encode("utf-8")
    with open(os.path.join(d, "trail.jsonl"), "wb") as f:
        f.write(raw)
    ctx = {"keyset": "../../keys/public.json", "agent_kids": AGENT_KIDS, "options": options or {}}
    with open(os.path.join(d, "context.json"), "w") as f:
        json.dump(ctx, f, indent=2)
    meta = {"id": vid, "title": title, "spec": "draft-sharif-agent-audit-trail-09", "sections": list(sections),
            "normative": normative,
            "expected": {"verdict": verdict, "completeness": completeness, "merkle": merkle,
                         "errors_include": list(errors), "warnings_include": list(warnings)}}
    if note:
        meta["note"] = note
    with open(os.path.join(d, "vector.json"), "w") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    VECTORS.append(meta)


def at(recs, i):
    return recs[i]


# =====================================================================
def build():
    # ---------- 0xx  valid baselines ----------
    V("001-valid-minimal-unsigned", "Complete unsigned session", ["6.1", "6.3", "8.1", "8.3"], "accept", recs=finalize(base()))
    V("002-valid-es256-self-signed", "Every record ES256-signed by the agent", ["6.2", "6.3"], "accept",
      recs=finalize(base(), signer=sign_all(K["agent"])))
    V("003-valid-no-close-inconclusive", "No close record: integrity passes, completeness is inconclusive", ["6.3"], "accept",
      "inconclusive", recs=finalize(base(with_close=False)))
    s = base(with_close=False, heartbeat_interval_s=30)
    sid = s[0]["session_id"]
    for k, r in enumerate(s[1:], 1):
        r["timestamp"] = ts(k * 30)
    s += [rec(sid, 120, "lifecycle", {"event": "heartbeat"}, phase="concurrent"), close(sid, 150)]
    V("004-valid-heartbeats", "Declared heartbeat cadence, honoured", ["8.4", "6.3"], "accept", recs=finalize(s))
    V("005-valid-noncanonical-storage", "Stored lines are not canonical (reordered keys, spacing, \\u escapes); hashes use JCS",
      ["6.1", "10.1", "10.4"], "accept", recs=finalize(base()), style="pretty-reverse")
    s = base()
    for k, r in enumerate(s):
        t = T0 + timedelta(seconds=k)
        r["timestamp"] = (t + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000+01:00")
    V("006-valid-utc-offset-timestamps", "RFC 3339 timestamps with a +01:00 offset", ["3.1"], "accept", recs=finalize(s))
    s = base()
    for k, r in enumerate(s):
        r["timestamp"] = ts(k, "us")
    V("007-valid-microsecond-timestamps", "Microsecond precision", ["3.1"], "accept", recs=finalize(s))
    s = base()
    for r in s:
        r["timestamp"] = ts(0)
    V("008-valid-equal-timestamps", "Equal timestamps are non-decreasing", ["3.3", "8.2"], "accept", recs=finalize(s))
    s = base()
    for k, r in enumerate(s):
        r["sequence_number"] = k
    V("009-valid-sequence-numbers", "sequence_number 0..n, gap-free", ["3.2", "3.3"], "accept", recs=finalize(s))
    s = base()
    sid = s[0]["session_id"]
    dl = rec(sid, 2, "delegation", {"delegate_agent_id": AGENT2, "delegate_trust_level": "L2", "task_description_hash": hx("task"),
                                    "constraints": ["read_only"], "timeout_ms": 30000}, phase="pre_execution")
    s.insert(2, dl)
    for r in s[3:]:
        r["principal"]["authority_ref"] = dl["record_id"]
    for k, r in enumerate(s):
        r["timestamp"] = ts(k)
    V("010-valid-authority-ref", "authority_ref links to a delegation record", ["3.1", "7.4"], "accept", recs=finalize(s))
    s = base()
    s[2]["action_detail"]["x_vendor_trace"] = {"span": "abc", "depth": 3}
    V("011-valid-unknown-detail-fields", "Unknown action_detail fields are carried and hashed", ["3.1"], "accept", recs=finalize(s))
    sid = uid()
    s = [genesis(sid),
         rec(sid, 1, "decision", {"decision_type": "route", "reasoning_hash": hx("why")}, outcome="escalated", phase="pre_execution"),
         rec(sid, 2, "escalation", {"escalation_reason": "policy_requires_human", "escalation_target": "urn:role:ops-oncall",
                                    "context_hash": hx("ctx"), "urgency": "high"}, outcome="escalated", phase="pre_execution"),
         rec(sid, 3, "lifecycle", {"event": "pause", "trigger": "manual"}),
         rec(sid, 4, "lifecycle", {"event": "resume", "trigger": "manual"}),
         rec(sid, 5, "delegation", {"delegate_agent_id": AGENT2, "delegate_trust_level": "L1", "task_description_hash": hx("t2")},
             phase="pre_execution"),
         rec(sid, 6, "error", {"error_code": "UPSTREAM_503", "error_message": "tool server unavailable", "error_category": "external",
                               "recoverable": True, "stack_hash": hx("stack")}, outcome="failure"),
         close(sid, 7)]
    V("012-valid-all-action-types", "Every registered action type", ["7"], "accept", recs=finalize(s))
    s = base()
    s[1].update(outcome="denied", deny_reasons=["INSUFFICIENT_TRUST_LEVEL", "ACME_LIMIT_EXCEEDED"])
    V("013-valid-denied-pre-execution", "Denied decision recorded pre-execution with reason codes", ["4.2", "3.2"], "accept", recs=finalize(s))
    s = base()
    s[2].update(outcome="denied")
    V("014-valid-tool-call-denied-post", "tool_call denied may be post_execution (4.2 restricts only decision/delegation)", ["4.2"], "accept",
      recs=finalize(s))
    s = base()
    for k, r in enumerate(s):
        r["nonce"] = hx("nonce%d" % k)[:32]
    V("015-valid-nonces", "Unique nonces of 128 bits", ["3.2", "14.5"], "accept", recs=finalize(s))
    s = base()
    for r in s:
        del r["principal"]
    V("016-valid-mixed-revision-no-principal", "Archive predating -07: absent principal is 'not recorded'", ["3.1"], "accept",
      recs=finalize(s), options={"mixed_revision": True}, warnings=["W_PRINCIPAL_NOT_RECORDED"])
    s = base()
    s[2].update(risk_score=0.35, model_id="example-model-2026-10", input_hash=hx("in"), output_hash=hx("out"), latency_ms=182,
                cost_estimate={"amount": 0.0042, "currency": "GBP", "breakdown": {"tokens": 0.004, "compute": 0.0002}},
                sanctions_check={"provider": "urn:provider:screening.example", "checked_at": ts(2), "result": "clear", "list_version": "2026-10-31"},
                jurisdiction="GB", human_override={"operator_id": "urn:role:supervisor", "reason": "manual check", "original_action": {"tool_name": "x"}},
                external_timestamp={"tsa_url": "https://tsa.example", "token": "MIIB", "anchored_at": ts(2)},
                content_fingerprint=hx("content"))
    V("017-valid-optional-fields", "All optional fields of 3.2, well-formed", ["3.2"], "accept", recs=finalize(s))
    s = base()
    s[0]["prior_generation_tail"] = {"prev_generation_id": "urn:uuid:" + uid(), "tail_record_hash": hx("tail"), "tail_signer_kid": K["recorder"].kid}
    V("018-valid-prior-generation-tail", "Genesis continues a prior recording generation", ["3.2", "8.1"], "accept", recs=finalize(s))

    # ---------- 02x  canonicalization (RFC 8785) ----------
    s = base()
    s[2]["action_detail"]["numbers"] = [1e21, 1e-7, 0.000001, 5e-324, 1.2345678901234568e+20, -0.0, 100.0, 0.1, 1.5e300, -2.5]
    V("020-jcs-number-serialization", "ECMAScript number serialization (1e+21, 1e-7, -0, 100.0 -> 100)", ["6.1"], "accept", recs=finalize(s))
    s = base()
    s[2]["action_detail"]["labels"] = {"z": 1, "é": 2, "€": 3, "\U0001F600": 4, "דּ": 5, "a": 6}
    V("021-jcs-utf16-key-order", "Keys sort by UTF-16 code units, not code points (U+1F600 before U+FB33)", ["6.1"], "accept", recs=finalize(s))
    s = base()
    s[2]["action_detail"]["text"] = "line\nbreak\ttab\u0001\u001f\"quote\\back/slash\u007f "
    V("022-jcs-string-escaping", "Control characters, quotes, backslash, DEL, U+2028", ["6.1"], "accept", recs=finalize(s))
    s = base()
    s[2]["action_detail"]["note"] = "café 中文 العربية"
    V("023-jcs-non-ascii", "Non-ASCII stored as \\u escapes, canonical form is raw UTF-8", ["6.1"], "accept", recs=finalize(s),
      style="pretty-reverse")
    s = base()
    s[2]["action_detail"]["big"] = 9007199254740991
    V("024-jcs-max-safe-integer", "2^53-1 is exact", ["6.1"], "accept", recs=finalize(s))
    s = finalize(base())
    lines = [dump_line(r) for r in s]
    lines[2] = lines[2].replace('"tool_name": "balance_query"', '"tool_name": "balance_query", "big": 9007199254740993', 1)
    V("025-jcs-integer-beyond-ijson", "Integer above 2^53 cannot be canonicalized (I-JSON)", ["6.1"], "reject",
      raw=("\n".join(lines) + "\n").encode(), errors=["E_NOT_IJSON"])
    lines = [dump_line(r) for r in finalize(base())]
    lines[2] = lines[2].replace('"outcome": "success"', '"outcome": "success", "outcome": "failure"', 1)
    V("026-duplicate-json-key", "Duplicate member names are not I-JSON", ["6.1", "10.1"], "reject",
      raw=("\n".join(lines) + "\n").encode(), errors=["E_DUPLICATE_KEY"])
    lines = [dump_line(r) for r in finalize(base())]
    lines[2] = lines[2].replace('"tool_name": "balance_query"', '"tool_name": "bal\\ud800ance"', 1)
    V("027-lone-surrogate", "A lone surrogate is not a Unicode string", ["3.3", "6.1"], "reject",
      raw=("\n".join(lines) + "\n").encode(), errors=["E_NOT_IJSON"])
    raw = ("\n".join(dump_line(r) for r in finalize(base())) + "\n").encode()
    raw = raw.replace(b"balance_query", b"balance_\xff\xfequery", 1)
    V("028-invalid-utf8", "Invalid UTF-8 bytes", ["3.3", "10.1"], "reject", raw=raw, errors=["E_UTF8"])
    raw = b"\xef\xbb\xbf" + ("\n".join(dump_line(r) for r in finalize(base())) + "\n").encode()
    V("029-bom-tolerated", "UTF-8 BOM (SHOULD NOT) is tolerated with a warning", ["10.1"], "accept", raw=raw, warnings=["W_BOM"])
    lines = [dump_line(r) for r in finalize(base())]
    lines[2] = lines[2][:-5]
    V("030-truncated-json-line", "A line that is not valid JSON", ["10.1"], "reject", raw=("\n".join(lines) + "\n").encode(), errors=["E_JSONL"])
    lines = [dump_line(r) for r in finalize(base())]
    lines.insert(2, "")
    V("031-blank-interior-line", "Empty line inside the trail", ["10.1"], "reject", raw=("\n".join(lines) + "\n").encode(), errors=["E_JSONL"])
    lines = [dump_line(r) for r in finalize(base())]
    lines[2] = "[" + lines[2] + "]"
    V("032-line-not-object", "A line that is a JSON array", ["10.1"], "reject", raw=("\n".join(lines) + "\n").encode(), errors=["E_JSONL"])

    # ---------- 04x  mandatory fields ----------
    for f in ["record_id", "timestamp", "agent_id", "principal", "agent_version", "session_id", "action_type", "action_detail",
              "outcome", "trust_level", "parent_record_id", "prev_hash", "record_phase"]:
        s = finalize(base(), edit=lambda i, r, f=f: r.pop(f) if i == 2 else None)
        V("04%s-missing-%s" % ("abcdefghijklm"["record_id timestamp agent_id principal agent_version session_id action_type action_detail outcome trust_level parent_record_id prev_hash record_phase".split().index(f)], f.replace("_", "-")),
          "Mandatory field '%s' absent" % f, ["3.1"], "reject", recs=s, errors=["E_MISSING_" + f.upper()])

    def bad(vid, title, sections, field_edit, err, idx=2):
        s = finalize(base(), edit=lambda i, r: field_edit(r) if i == idx else None)
        V(vid, title, sections, "reject", recs=s, errors=[err])

    bad("050-record-id-not-uuid", "record_id is not a UUID", ["3.1"], lambda r: r.update(record_id="rec-0002"), "E_RECORD_ID")
    bad("051-record-id-uuid-v1", "record_id is a UUID but version 1", ["3.1"], lambda r: r.update(record_id="6ba7b810-9dad-11d1-80b4-00c04fd430c8"), "E_RECORD_ID")
    bad("052-timestamp-no-offset", "Timestamp without UTC offset", ["3.1"], lambda r: r.update(timestamp="2026-11-01T09:00:02.000"), "E_TIMESTAMP")
    bad("053-timestamp-impossible-date", "Timestamp on 30 February", ["3.1"], lambda r: r.update(timestamp="2026-02-30T09:00:02.000Z"), "E_TIMESTAMP")
    bad("054-agent-id-not-uri", "agent_id is not a URI", ["3.1"], lambda r: r.update(agent_id="payment bot"), "E_AGENT_ID")
    bad("055-agent-version-not-semver", "agent_version is not SemVer", ["3.1"], lambda r: r.update(agent_version="v2"), "E_AGENT_VERSION")
    bad("056-action-type-unregistered", "action_type not in the registry", ["3.1", "15.1"], lambda r: r.update(action_type="tool_invoke"), "E_ACTION_TYPE")
    bad("057-outcome-unregistered", "outcome not in the registry", ["3.1", "15.2"], lambda r: r.update(outcome="ok"), "E_OUTCOME")
    bad("058-trust-level-unknown", "trust_level L5", ["3.1"], lambda r: r.update(trust_level="L5"), "E_TRUST_LEVEL")
    bad("059-record-phase-unknown", "record_phase 'after'", ["3.1"], lambda r: r.update(record_phase="after"), "E_RECORD_PHASE")
    bad("060-action-detail-array", "action_detail is an array", ["3.1"], lambda r: r.update(action_detail=["balance_query"]), "E_ACTION_DETAIL")
    bad("061-action-detail-empty", "action_detail is {}", ["3.3"], lambda r: r.update(action_detail={}), "E_ACTION_DETAIL_EMPTY")
    bad("062-principal-type-unknown", "principal_type 'robot'", ["3.1"], lambda r: r["principal"].update(principal_type="robot"), "E_PRINCIPAL_TYPE")
    bad("063-principal-id-not-uri", "principal_id is not a URI", ["3.1"], lambda r: r["principal"].update(principal_id="bob"), "E_PRINCIPAL_ID")
    bad("064-authority-ref-absent", "authority_ref key missing (must be present, null allowed)", ["3.1"], lambda r: r["principal"].pop("authority_ref"), "E_AUTHORITY_REF")
    bad("065-principal-not-object", "principal is a string", ["3.1"], lambda r: r.update(principal="urn:user:x"), "E_PRINCIPAL")
    bad("066-session-id-not-uuid", "session_id is not a UUID", ["3.1"], lambda r: r.update(session_id="sess-1"), "E_SESSION_ID")

    def bad_post(vid, title, sections, field_edit, err, idx=2):
        s = finalize(base())
        field_edit(s[idx])
        V(vid, title, sections, "reject", recs=s, errors=[err])

    bad_post("067-prev-hash-uppercase", "prev_hash in uppercase hex", ["3.1"], lambda r: r.update(prev_hash=r["prev_hash"].upper()), "E_PREV_HASH_FORMAT")
    bad_post("068-prev-hash-63-chars", "prev_hash one character short", ["3.1"], lambda r: r.update(prev_hash=r["prev_hash"][:63]), "E_PREV_HASH_FORMAT")

    # ---------- 07x  field constraints ----------
    s = base()
    s[2]["action_detail"]["blob"] = "A" * (257 * 1024)
    V("070-record-over-256kb", "Record larger than 256 KB MUST be rejected", ["3.3"], "reject", recs=finalize(s), errors=["E_SIZE"])
    s = base()
    s[2]["action_detail"]["blob"] = "A" * (100 * 1024)
    V("071-record-over-64kb", "Record over 64 KB (SHOULD NOT) is accepted with a warning", ["3.3"], "accept", recs=finalize(s), warnings=["W_SIZE"])
    s = base()
    s[2]["timestamp"] = ts(0) .replace("09:00:00", "08:59:59")
    V("072-timestamp-backdated", "Record N+1 earlier than record N", ["3.3", "8.2"], "reject", recs=finalize(s), errors=["E_TIMESTAMP_BACKDATED"])
    s = base()
    s[2]["timestamp"] = "2026-11-01T10:00:00.500+02:00"     # = 08:00:00.5Z, looks later as a string
    V("073-timestamp-backdated-via-offset", "Later as text, earlier in UTC", ["3.3"], "reject", recs=finalize(s), errors=["E_TIMESTAMP_BACKDATED"])
    s = base()
    s[2]["action_detail"]["aat_priority"] = 1
    V("074-reserved-aat-prefix", "action_detail field with the reserved aat_ prefix", ["3.3"], "reject", recs=finalize(s), errors=["E_RESERVED_PREFIX"])
    s = base()
    for k, r in enumerate(s):
        r["sequence_number"] = k + 1
    V("075-sequence-starts-at-1", "Genesis sequence_number must be 0", ["3.3"], "reject", recs=finalize(s), errors=["E_SEQUENCE_GAP"])
    s = base()
    for k, r in enumerate(s):
        r["sequence_number"] = k if k < 3 else k + 1
    V("076-sequence-gap", "sequence_number skips a value", ["3.3", "6.3"], "reject", recs=finalize(s), errors=["E_SEQUENCE_GAP"])
    s = base()
    for k, r in enumerate(s):
        if k != 3:
            r["sequence_number"] = k
    V("077-sequence-partial", "sequence_number on some records only", ["3.3"], "reject", recs=finalize(s), errors=["E_SEQUENCE_PARTIAL"])
    s = base()
    s[2]["prior_generation_tail"] = {"prev_generation_id": "urn:uuid:" + uid(), "tail_record_hash": hx("tail")}
    V("078-prior-generation-tail-not-genesis", "prior_generation_tail outside the genesis record", ["3.3"], "reject", recs=finalize(s),
      errors=["E_PRIOR_GENERATION_TAIL_NOT_GENESIS"])
    s = finalize(base(), signer=lambda i, r: (K["agent"], "ES256"))
    del s[2]["signer_kid"]
    s2 = finalize(s)          # re-chain so only the missing kid is wrong
    V("079-signature-without-signer-kid", "signature present, signer_kid absent", ["3.2", "3.3"], "reject", recs=s2, errors=["E_SIGNER_KID_MISSING"])
    s = base()
    s[3]["record_id"] = s[2]["record_id"]
    s[3]["action_detail"]["parent_call_id"] = s[2]["record_id"]
    V("080-duplicate-record-id", "Two records share a record_id", ["3.1"], "reject", recs=finalize(s), errors=["E_DUPLICATE_RECORD_ID"])
    s = base()
    s[2]["session_id"] = uid()
    V("081-session-id-mismatch", "One record carries a different session_id", ["3.1"], "reject", recs=finalize(s), errors=["E_SESSION_MISMATCH"])
    for vid, title, upd, err in [
        ("082-risk-score-out-of-range", "risk_score 1.5", {"risk_score": 1.5}, "E_RISK_SCORE"),
        ("083-input-hash-uppercase", "input_hash not lowercase hex", {"input_hash": hx("in").upper()}, "E_INPUT_HASH"),
        ("084-nonce-too-short", "nonce under 128 bits", {"nonce": "abcdef0123"}, "E_NONCE_FORMAT"),
        ("085-jurisdiction-lowercase", "jurisdiction 'gb'", {"jurisdiction": "gb"}, "E_JURISDICTION"),
        ("086-external-timestamp-incomplete", "external_timestamp without token", {"external_timestamp": {"tsa_url": "https://tsa.example", "anchored_at": ts(2)}}, "E_EXTERNAL_TIMESTAMP"),
        ("087-content-fingerprint-malformed", "content_fingerprint not 64 hex", {"content_fingerprint": "abc"}, "E_CONTENT_FINGERPRINT"),
        ("088-trust-assignment-no-classifier", "trust_assignment missing classifier_id", {"trust_assignment": {"policy_version": "3", "downgraded": False}}, "E_TRUST_ASSIGNMENT"),
        ("089-sanctions-result-unknown", "sanctions_check result 'pass'", {"sanctions_check": {"provider": "x", "result": "pass"}}, "E_SANCTIONS_CHECK"),
        ("090-deny-reasons-not-strings", "deny_reasons contains a number", {"deny_reasons": [1]}, "E_DENY_REASONS"),
    ]:
        s = base()
        s[2].update(upd)
        V(vid, title, ["3.2"], "reject", recs=finalize(s), errors=[err])
    s = base()
    s[2]["nonce"] = s[1]["nonce"] = hx("n")[:32]
    V("091-nonce-reused", "Same nonce on two records", ["3.2", "6.3", "14.5"], "reject", recs=finalize(s), errors=["E_NONCE_REUSED"])

    # ---------- 10x  action types ----------
    req = [("tool_call", 2, "tool_name"), ("tool_call", 2, "parameters_hash"), ("tool_response", 3, "tool_name"),
           ("tool_response", 3, "response_hash"), ("tool_response", 3, "parent_call_id"), ("decision", 1, "decision_type")]
    for n, (atype, idx, f) in enumerate(req):
        s = base()
        del s[idx]["action_detail"][f]
        V("1%02d-%s-missing-%s" % (n, atype.replace("_", "-"), f.replace("_", "-")), "%s without %s" % (atype, f), ["7"], "reject",
          recs=finalize(s), errors=["E_DETAIL_MISSING_" + f.upper()])
    others = {"delegation": {"delegate_agent_id": AGENT2, "delegate_trust_level": "L2", "task_description_hash": hx("t")},
              "escalation": {"escalation_reason": "risk_score_exceeded", "escalation_target": "urn:role:ops"},
              "error": {"error_code": "E1", "error_message": "m", "error_category": "internal", "recoverable": False}}
    n = len(req)
    for atype, det in others.items():
        for f in det:
            s = base()
            d = dict(det); del d[f]
            s[2] = rec(s[0]["session_id"], 2, atype, d, outcome="success", phase="pre_execution")
            s[3]["action_detail"]["parent_call_id"] = s[2]["record_id"]
            s[3] = rec(s[0]["session_id"], 3, "decision", {"decision_type": "classify"})
            V("1%02d-%s-missing-%s" % (n, atype, f.replace("_", "-")), "%s without %s" % (atype, f), ["7"], "reject",
              recs=finalize(s), errors=["E_DETAIL_MISSING_" + f.upper()])
            n += 1
    s = base(); s[0]["action_detail"].pop("event")
    V("1%02d-lifecycle-missing-event" % n, "lifecycle without event", ["7.7"], "reject", recs=finalize(s), errors=["E_DETAIL_MISSING_EVENT"]); n += 1
    for vid, atype, det, err in [
        ("error-category-unknown", "error", {"error_code": "E1", "error_message": "m", "error_category": "disk", "recoverable": True}, "E_ERROR_CATEGORY"),
        ("error-recoverable-not-boolean", "error", {"error_code": "E1", "error_message": "m", "error_category": "internal", "recoverable": "yes"}, "E_RECOVERABLE"),
        ("escalation-urgency-unknown", "escalation", {"escalation_reason": "x", "escalation_target": "urn:role:ops", "urgency": "urgent"}, "E_URGENCY"),
        ("delegation-trust-level-unknown", "delegation", {"delegate_agent_id": AGENT2, "delegate_trust_level": "L9", "task_description_hash": hx("t")}, "E_DELEGATE_TRUST_LEVEL"),
        ("lifecycle-event-unknown", "lifecycle", {"event": "reboot"}, "E_LIFECYCLE_EVENT"),
        ("decision-confidence-out-of-range", "decision", {"decision_type": "approve", "confidence": 1.2}, "E_CONFIDENCE"),
    ]:
        s = base()
        s[2] = rec(s[0]["session_id"], 2, atype, det, phase="pre_execution")
        s[3] = rec(s[0]["session_id"], 3, "decision", {"decision_type": "classify"})
        V("1%02d-%s" % (n, vid), vid.replace("-", " "), ["7"], "reject", recs=finalize(s), errors=[err]); n += 1
    s = base()
    s[3]["action_detail"]["parent_call_id"] = uid()
    V("1%02d-tool-response-orphan" % n, "tool_response.parent_call_id names no tool_call in the session", ["7.2"], "reject",
      recs=finalize(s), errors=["E_PARENT_CALL_UNKNOWN"])

    # ---------- 13x  pre-execution recording (4.2) ----------
    for vid, at_, oc, ph in [("130-decision-denied-post-execution", "decision", "denied", "post_execution"),
                             ("131-decision-escalated-post-execution", "decision", "escalated", "post_execution"),
                             ("132-decision-denied-concurrent", "decision", "denied", "concurrent")]:
        s = base()
        s[1].update(outcome=oc, record_phase=ph)
        V(vid, "%s %s recorded as %s" % (at_, oc, ph), ["4.2"], "reject", recs=finalize(s), errors=["E_PHASE_PRE_EXECUTION_REQUIRED"])
    s = base()
    s[1] = rec(s[0]["session_id"], 1, "delegation", {"delegate_agent_id": AGENT2, "delegate_trust_level": "L2", "task_description_hash": hx("t")},
               outcome="denied", phase="post_execution")
    V("133-delegation-denied-post-execution", "delegation denied recorded after the fact", ["4.2"], "reject", recs=finalize(s), errors=["E_PHASE_PRE_EXECUTION_REQUIRED"])

    # ---------- 14x  session structure (8) ----------
    def gen_edit(vid, title, fn, err):
        s = base()
        fn(s[0])
        V(vid, title, ["8.1"], "reject", recs=finalize(s), errors=[err])
    gen_edit("140-genesis-not-lifecycle", "First record is a decision", lambda g: g.update(action_type="decision", action_detail={"decision_type": "start"}), "E_GENESIS_NOT_SESSION_START")
    gen_edit("141-genesis-event-resume", "First record is a resume", lambda g: g["action_detail"].update(event="resume"), "E_GENESIS_NOT_SESSION_START")
    gen_edit("142-genesis-phase-post", "Genesis record_phase post_execution", lambda g: g.update(record_phase="post_execution"), "E_GENESIS_PHASE")
    s = finalize(base(), edit=lambda i, r: r.update(parent_record_id=uid()) if i == 0 else None)
    V("143-genesis-parent-not-null", "Genesis has a parent_record_id", ["8.1", "6.3"], "reject", recs=s, errors=["E_GENESIS_PARENT"])
    s = finalize(base(), edit=lambda i, r: r.update(prev_hash=hx("x")) if i == 0 else None)
    V("144-genesis-prev-hash-not-null", "Genesis has a prev_hash", ["8.1", "6.3"], "reject", recs=s, errors=["E_GENESIS_PREV_HASH"])
    s = finalize(base(), edit=lambda i, r: r.update(record_phase="concurrent") if i == 4 else None)
    V("145-close-phase-concurrent", "Close record not post_execution", ["8.3"], "reject", recs=s, errors=["E_CLOSE_PHASE"])
    s = finalize(base(), edit=lambda i, r: r["action_detail"].pop("session_hash") if i == 4 else None)
    V("146-close-without-session-hash", "Close record lacks session_hash", ["8.3"], "reject", recs=s, errors=["E_CLOSE_SESSION_HASH_MISSING"])

    def hexcat(i, r):
        if i == 4:
            r["action_detail"]["session_hash"] = hashlib.sha256("".join(x["prev_hash"] for x in S146[1:5]).encode()).hexdigest()
    S146 = base()
    s = finalize(S146, edit=hexcat)
    V("147-session-hash-over-hex-text", "session_hash computed over hex text instead of raw digests", ["8.3"], "reject", recs=s, errors=["E_SESSION_HASH"])
    s = base(); s.insert(2, close(s[0]["session_id"], 2))
    for k, r in enumerate(s):
        r["timestamp"] = ts(k)
    V("148-close-not-last", "session_end record in the middle", ["8.3"], "reject", recs=finalize(s), errors=["E_CLOSE_NOT_LAST"])
    s = base(); s.insert(2, genesis(s[0]["session_id"]))
    s[2]["record_phase"] = "concurrent"
    for k, r in enumerate(s):
        r["timestamp"] = ts(k)
    V("149-second-session-start", "session_start after genesis", ["8.1"], "reject", recs=finalize(s), errors=["E_SESSION_START_NOT_GENESIS"])
    s = base(); S_ids = [r["record_id"] for r in s]
    s = finalize(s, edit=lambda i, r: r.update(parent_record_id=S_ids[1]) if i == 3 else None)
    V("150-branch-parent-mismatch", "Two records claim the same parent (branch)", ["8.2", "6.3"], "reject", recs=s, errors=["E_PARENT_MISMATCH"])
    s = finalize(base(), edit=lambda i, r: r.update(parent_record_id=None) if i == 2 else None)
    V("151-parent-null-after-genesis", "Non-genesis record with null parent", ["3.1", "8.2"], "reject", recs=s, errors=["E_PARENT_NULL"])

    # ---------- 16x  tampering and absence ----------
    s = finalize(base()); s[2]["outcome"] = "failure"
    V("160-tamper-field-edit", "One field edited after chaining", ["6.3"], "reject", recs=s, errors=["E_CHAIN_BROKEN"])
    s = finalize(base()); del s[2]
    V("161-tamper-delete-interior", "Interior record removed", ["6.3", "8.2"], "reject", recs=s, errors=["E_CHAIN_BROKEN", "E_PARENT_MISMATCH"])
    s = finalize(base()); s[1], s[2] = s[2], s[1]
    V("162-tamper-reorder", "Two records swapped", ["6.3"], "reject", recs=s, errors=["E_CHAIN_BROKEN"])
    s = finalize(base())
    forged = rec(s[0]["session_id"], 2, "decision", {"decision_type": "approve"}, phase="pre_execution")
    forged["timestamp"] = s[2]["timestamp"]; forged["parent_record_id"] = s[2]["record_id"]; forged["prev_hash"] = record_hash(s[2]).hex()
    s.insert(3, forged)
    V("163-tamper-insert", "Forged record inserted with a correct back-link", ["6.3"], "reject", recs=s, errors=["E_CHAIN_BROKEN"])

    s = base()
    def nj(i, r):
        if i > 0:
            r["prev_hash"] = hashlib.sha256(json.dumps(s[i - 1], sort_keys=True).encode()).hexdigest()
    s = finalize(s, edit=nj)
    V("164-chain-without-jcs", "prev_hash over json.dumps(sort_keys) instead of JCS", ["6.1"], "reject", recs=s, errors=["E_CHAIN_BROKEN"])
    s = base()
    def nosig(i, r):
        if i > 0:
            p = {k: v for k, v in s[i - 1].items() if k not in ("signature",)}
            r["prev_hash"] = record_hash(p).hex()
    s = finalize(s, signer=sign_all(K["agent"]), edit=nosig)
    V("165-chain-excludes-prev-signature", "prev_hash computed without the previous record's signature", ["6.2", "6.1"], "reject", recs=s,
      errors=["E_CHAIN_BROKEN"])
    s = finalize(base())
    s = s[:-1]
    V("166-tail-truncated", "Close record removed: chain intact, completeness inconclusive", ["6.3"], "accept", "inconclusive", recs=s)
    full = finalize(base(with_close=False) + [])
    anchor = {"record_count": 4, "record_hash": record_hash(full[3]).hex()}
    V("167-shorter-than-anchored-head", "Presented chain shorter than the externally anchored head", ["6.3", "6.4"], "accept", "gaps",
      recs=full[:3], options={"anchored_head": anchor}, warnings=["W_SHORTER_THAN_ANCHOR"])
    other = finalize(base(with_close=False))
    V("168-anchored-head-mismatch", "Same length as the anchored head, different content", ["6.3", "6.4"], "reject", recs=other,
      options={"anchored_head": anchor}, errors=["E_ANCHOR_MISMATCH"])
    s = base(with_close=False, heartbeat_interval_s=30)
    for k, r in enumerate(s[1:], 1):
        r["timestamp"] = ts(k * 30)
    s[3]["timestamp"] = ts(600)
    V("169-heartbeat-silence", "Ten minutes of silence against a 30 s heartbeat", ["8.4", "6.3"], "accept", "gaps", recs=finalize(s),
      warnings=["W_HEARTBEAT_GAP"])
    s = finalize(base()); s[2]["outcome"] = "failure"; s = finalize(s)
    V("170-unsigned-rewrite-undetectable", "Unsigned chain recomputed after an edit: integrity checks cannot see it", ["6.3", "14.1"],
      "accept", recs=s, note="Expected accept. Demonstrates why signatures (6.2) or an external anchor (6.4) are needed.")
    s = finalize(base(), signer=sign_all(K["agent"])); s[2]["outcome"] = "failure"
    s = finalize(s, signer=lambda i, r: (K["rogue"], "ES256") if i >= 2 else (K["agent"], "ES256"))
    V("171-signed-rewrite-unknown-key", "Signed chain rewritten and re-signed with an unpublished key", ["6.3"], "reject", recs=s,
      errors=["E_SIGNER_KID_UNKNOWN"])
    s = finalize(base(), signer=sign_all(K["agent"])); s[2]["outcome"] = "failure"
    s = finalize(s, signer=lambda i, r: None)
    V("172-signed-rewrite-stale-signatures", "Signed chain rechained after an edit, old signatures kept", ["6.3"], "reject", recs=s,
      errors=["E_SIGNATURE_INVALID"])

    # ---------- 18x  signatures ----------
    ind = lambda key, alg: (lambda i, r: (key, alg))
    s = base(trust="L2", recording_mode="independent", recording_component_id=RECORDER)
    for r in s:
        r["recording_component"] = RECORDER
    V("180-valid-independent-es256", "Independent recorder signs with its own ES256 key", ["5.2", "6.2"], "accept", recs=finalize(s, signer=ind(K["recorder"], "ES256")))
    V("181-valid-ed25519-self", "Agent signs with Ed25519", ["6.2"], "accept", recs=finalize(base(agent=AGENT2), signer=ind(K["agent2"], "Ed25519")))
    s = base(trust="L3", recording_mode="independent", recording_component_id=PQREC)
    for r in s:
        r["recording_component"] = PQREC
    V("182-valid-ml-dsa-65", "Independent recorder signs with ML-DSA-65", ["6.2"], "accept", recs=finalize(s, signer=ind(K["pq-recorder"], "ML-DSA-65")))

    def hybrid(bad_classical=False, same=False, no_kid=False):
        s = base(trust="L3", recording_mode="independent", recording_component_id=PQREC)
        for r in s:
            r["recording_component"] = PQREC
        def sg(i, r):
            r["sig_alg"] = "ML-DSA-65"; r["signer_kid"] = K["pq-recorder"].kid
            if not no_kid:
                r["signer_kid_classical"] = (K["pq-recorder"] if same else K["classical"]).kid
            h = signed_bytes_hash(r)
            r["signature"] = K["pq-recorder"].sign_hash(h, "ML-DSA-65")
            c = K["classical"].sign_hash(h, "ES256")
            if bad_classical:
                c = c[:-4] + ("AAAA" if not c.endswith("AAAA") else "BBBB")
            r["signature_classical"] = c
        return finalize(s, edit=sg)
    V("183-valid-hybrid", "ML-DSA-65 + ES256 hybrid, distinct keys", ["6.2"], "accept", recs=hybrid())
    V("184-hybrid-classical-fails", "Hybrid: classical signature invalid (verifier MAY check it; record still verifies)", ["6.2", "6.3"], "accept",
      recs=hybrid(bad_classical=True), warnings=["W_HYBRID_CLASSICAL_FAILED"])
    V("185-hybrid-same-key", "Hybrid: both kids name the same key", ["6.2"], "reject", recs=hybrid(same=True), errors=["E_HYBRID_SAME_KEY"])
    V("186-hybrid-classical-without-kid", "signature_classical without signer_kid_classical", ["3.2"], "reject", recs=hybrid(no_kid=True),
      errors=["E_SIGNER_KID_CLASSICAL_MISSING"])
    V("187-valid-sig-alg-absent", "signature without sig_alg: ES256 assumed", ["3.2", "6.2"], "accept", recs=finalize(base(), signer=ind(K["agent"], None)))
    s = finalize(base(), signer=sign_all(K["agent"]))
    sig = s[2]["signature"]; s[2]["signature"] = sig[:10] + ("A" if sig[10] != "A" else "B") + sig[11:]
    s = finalize(s, signer=lambda i, r: None)
    V("188-es256-bad-signature", "ES256 signature altered", ["6.3"], "reject", recs=s, errors=["E_SIGNATURE_INVALID"])

    def der_sig(i, r):
        r["sig_alg"] = "ES256"; r["signer_kid"] = K["agent"].kid
        r["signature"] = b64u(K["agent"].priv.sign(signed_bytes_hash(r), ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True)))
    V("189-es256-der-encoding", "ES256 signature DER-encoded instead of r||s", ["6.2"], "reject", recs=finalize(base(), edit=der_sig),
      errors=["E_SIGNATURE_INVALID"])

    def sign_with_batch(i, r):
        r["batch"] = {"epoch_id": uid(), "merkle_root": hx("r"), "leaf_index": 0}
        r["sig_alg"] = "ES256"; r["signer_kid"] = K["agent"].kid
        r["signature"] = K["agent"].sign_hash(hashlib.sha256(canonicalize({k: v for k, v in r.items() if k != "signature"})).digest())
        del r["batch"]
    V("190-signature-covers-batch", "Signature computed over a 'batch' object, which is excluded from the signed message", ["6.2"], "reject",
      recs=finalize(base(), edit=sign_with_batch), errors=["E_SIGNATURE_INVALID"])
    s = finalize(base(), signer=sign_all(K["agent"])); s[2]["sig_alg"] = "Ed25519"; s = finalize(s, signer=lambda i, r: None)
    V("191-sig-alg-altered", "sig_alg changed after signing", ["6.2"], "reject", recs=s, errors=["E_SIGNATURE_INVALID"])
    s = finalize(base(), signer=lambda i, r: (K["agent"], "ES256"))
    s[2]["signer_kid"] = K["classical"].kid; s = finalize(s, signer=lambda i, r: None)
    V("192-signer-kid-wrong-key", "signer_kid names a different published key", ["6.3"], "reject", recs=s, errors=["E_SIGNATURE_INVALID"])
    V("193-signer-kid-unknown", "Signed by a key that is not published", ["6.3"], "reject", recs=finalize(base(), signer=sign_all(K["rogue"])),
      errors=["E_SIGNER_KID_UNKNOWN"])
    s = finalize(base(), signer=sign_all(K["agent"])); s[2]["sig_alg"] = "RS256"; s = finalize(s)
    V("194-sig-alg-unregistered", "sig_alg RS256", ["3.2", "15.3"], "reject", recs=s, errors=["E_SIG_ALG"])

    def ed_on_ec(i, r):
        r["sig_alg"] = "Ed25519"; r["signer_kid"] = K["agent"].kid
        r["signature"] = K["agent"].sign_hash(signed_bytes_hash(r), "ES256")
    V("195-sig-alg-key-type-mismatch", "sig_alg Ed25519 with a P-256 key", ["6.3"], "reject", recs=finalize(base(), edit=ed_on_ec),
      errors=["E_SIGNATURE_INVALID"])

    def double_hash(i, r):
        r["sig_alg"] = "ES256"; r["signer_kid"] = K["agent"].kid
        der = K["agent"].priv.sign(signed_bytes_hash(r), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        a, b = utils.decode_dss_signature(der); r["signature"] = b64u(a.to_bytes(32, "big") + b.to_bytes(32, "big"))
    V("196-es256-double-hash", "ES256 over SHA-256(SHA-256(JCS)) instead of SHA-256(JCS)", ["6.2"], "reject", recs=finalize(base(), edit=double_hash),
      errors=["E_SIGNATURE_INVALID"], note="6.2 step 4a: the 32-byte hash is the ECDSA digest. This equals standard ES256 over the canonical bytes.")

    def raw_msg(alg, key, agent):
        def f(i, r):
            r["sig_alg"] = alg; r["signer_kid"] = key.kid
            r["signature"] = b64u(key.priv.sign(canonicalize({k: v for k, v in r.items() if k != "signature"})))
        return f
    V("197-ed25519-over-canonical-bytes", "Ed25519 over the canonical bytes instead of their 32-byte hash", ["6.2"], "reject",
      recs=finalize(base(agent=AGENT2), edit=raw_msg("Ed25519", K["agent2"], AGENT2)), errors=["E_SIGNATURE_INVALID"])
    s = base(trust="L3", recording_mode="independent", recording_component_id=PQREC)
    for r in s:
        r["recording_component"] = PQREC
    V("198-ml-dsa-over-canonical-bytes", "ML-DSA-65 over the canonical bytes instead of their 32-byte hash", ["6.2"], "reject",
      recs=finalize(s, edit=raw_msg("ML-DSA-65", K["pq-recorder"], AGENT)), errors=["E_SIGNATURE_INVALID"])

    # ---------- 20x  recording independence (5) ----------
    s = base(trust="L2", recording_mode="independent", recording_component_id=RECORDER)
    for r in s:
        r["recording_component"] = RECORDER
    V("200-recorder-uses-agent-key", "Independent recorder signs with the agent's key", ["5.2"], "reject",
      recs=finalize(s, signer=ind(K["agent"], "ES256")), errors=["E_RECORDER_KEY_NOT_INDEPENDENT"])
    V("201-recorder-undeclared", "Signed by a non-agent key with no recording_component", ["3.2", "5.2"], "reject",
      recs=finalize(base(trust="L2"), signer=ind(K["recorder"], "ES256")), errors=["E_RECORDING_COMPONENT_UNDECLARED"])
    s = base()
    for r in s:
        r["recording_component"] = AGENT
    V("202-valid-self-recording-declared", "recording_component equals agent_id (self-recording)", ["5.1"], "accept",
      recs=finalize(s, signer=sign_all(K["agent"])))
    s = base()
    s[2]["action_detail"].update(tool_name="payment_transfer", amount_minor=125000, currency="GBP")
    s[2]["trust_assignment"] = {"classifier_id": "urn:classifier:policy-engine.example", "policy_version": "2026.10", "policy_digest": hx("policy"), "downgraded": True}
    s[3]["action_detail"]["tool_name"] = "payment_transfer"
    V("203-valid-attributable-downgrade", "Payment at L1 with an attributable downgrade", ["5.3"], "accept", recs=finalize(s))
    s = base(trust="L3")
    s[2]["trust_assignment"] = {"classifier_id": "urn:classifier:x", "policy_version": "1", "downgraded": True}
    V("204-downgrade-flag-inconsistent", "downgraded=true while trust_level is L3 (not below the L2 default)", ["5.3", "3.2"], "reject",
      recs=finalize(s), errors=["E_DOWNGRADE_INCONSISTENT"])
    s = base()
    s[2]["trust_assignment"] = {"classifier_id": "urn:classifier:x", "downgraded": True}
    V("205-downgrade-missing-policy-version", "trust_assignment without policy_version", ["5.3"], "reject", recs=finalize(s), errors=["E_TRUST_ASSIGNMENT"])
    s = base()
    s[2]["action_detail"].update(tool_name="payment_transfer", amount_minor=125000, currency="GBP")
    s[3]["action_detail"]["tool_name"] = "payment_transfer"
    V("206-informative-silent-downgrade", "Payment at L1 with no trust_assignment", ["5.3"], "accept", recs=finalize(s), normative=False,
      note="5.3 forbids this, but -09 gives no machine-readable marker of a 'consequential' action, so a generic verifier cannot detect it. See SPEC-NOTES.md.")

    # ---------- 21x  Merkle batch anchoring (6.4) ----------
    def batched(sizes, tamper=None, nodomain=False, attest=None, mode=None):
        s = base(trust="L3", recording_mode=mode or "independent", recording_component_id=RECORDER)
        sid = s[0]["session_id"]
        total = sum(sizes)
        while len(s) < total:
            s.insert(-1, rec(sid, len(s), "decision", {"decision_type": "classify", "n": len(s)}, trust="L3"))
        for k, r in enumerate(s):
            r["timestamp"] = ts(k); r["recording_component"] = RECORDER
        s = finalize(s, signer=ind(K["recorder"], "ES256"))
        start = 0
        for sz in sizes:
            ep = uid()
            members = s[start:start + sz]
            leaves = [(hashlib.sha256(canonicalize(r)).digest() if nodomain else leaf_hash(r)) for r in members]
            if nodomain:
                lvl = list(leaves)
                while len(lvl) > 1:
                    nx = [hashlib.sha256(lvl[j] + lvl[j + 1]).digest() for j in range(0, len(lvl) - 1, 2)]
                    if len(lvl) % 2:
                        nx.append(lvl[-1])
                    lvl = nx
                root = lvl[0]
            else:
                root = merkle_root(leaves)
            for li, r in enumerate(members):
                r["batch"] = {"epoch_id": ep, "merkle_root": root.hex(), "leaf_index": li, "inclusion_proof": _proof(leaves, li)}
            start += sz
        if tamper:
            tamper(s)
        return s
    V("210-valid-merkle-odd-epoch", "Five-leaf epoch (odd node promotion) with inclusion proofs", ["6.4"], "accept", recs=batched([5]), merkle="pass")
    V("211-valid-merkle-even-epoch", "Six-leaf epoch", ["6.4"], "accept", recs=batched([6]), merkle="pass")
    V("212-valid-merkle-two-epochs", "Two epochs (3 + 3)", ["6.4"], "accept", recs=batched([3, 3]), merkle="pass")
    V("213-valid-merkle-single-leaf-epochs", "Epochs of one leaf: root equals the leaf hash", ["6.4"], "accept", recs=batched([1, 4]), merkle="pass")
    V("214-merkle-bad-proof", "Inclusion proof sibling altered: chain valid, Merkle check fails", ["6.4"], "accept",
      recs=batched([5], tamper=lambda s: s[2]["batch"]["inclusion_proof"][0].update(hash=hx("evil"))), merkle="fail")
    V("215-merkle-no-domain-separation", "Root built without the 0x00/0x01 prefixes of RFC 6962", ["6.4"], "accept",
      recs=batched([4], nodomain=True), merkle="fail")
    V("216-merkle-leaf-index-swapped", "batch.leaf_index values swapped after the fact", ["6.4"], "accept",
      recs=batched([4], tamper=lambda s: (s[0]["batch"].update(leaf_index=1), s[1]["batch"].update(leaf_index=0))), merkle="fail",
      note="Batch is detached (6.4): the chain and signatures still verify; only Merkle inclusion fails.")
    V("217-merkle-root-disagreement", "Records of one epoch carry different roots", ["6.4"], "accept",
      recs=batched([4], tamper=lambda s: s[3]["batch"].update(merkle_root=hx("other"))), merkle="fail")

    # ---------- 22x  hardware-attested recording (5.4) ----------
    s = base(trust="L3", recording_mode="independent", recording_component_id=RECORDER)
    for r in s:
        r["recording_component"] = RECORDER
    def att_mid(i, r):
        if i == 2:
            r["platform_attestation"] = {"format": "ear", "result": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln", "bound_value": record_hash(S220[1]).hex()}
    S220 = s
    V("221-valid-attestation-bound-to-preceding", "Attestation in a later record, bound to the preceding record_hash", ["5.4", "3.2"], "accept",
      recs=finalize(s, signer=ind(K["recorder"], "ES256"), edit=att_mid))
    s = base(trust="L3", recording_mode="independent", recording_component_id=RECORDER)
    for r in s:
        r["recording_component"] = RECORDER
    S220 = s
    def att_bad(i, r):
        if i == 2:
            r["platform_attestation"] = {"format": "ear", "result": "eyJhbGciOiJFUzI1NiJ9.e30.c2ln", "bound_value": hx("unrelated")}
    V("222-attestation-unbound", "Attestation bound_value does not match the chain head", ["5.4", "14.6"], "reject",
      recs=finalize(s, signer=ind(K["recorder"], "ES256"), edit=att_bad), errors=["E_ATTESTATION_UNBOUND"])
    s = base(trust="L3", recording_mode="hardware-attested", recording_component_id=RECORDER)
    for r in s:
        r["recording_component"] = RECORDER
    V("223-hardware-attested-without-attestation", "recording_mode hardware-attested, no platform_attestation", ["5.4"], "reject",
      recs=finalize(s, signer=ind(K["recorder"], "ES256")), errors=["E_ATTESTATION_MISSING"])
    s = base(trust="L3", recording_mode="independent", recording_component_id=RECORDER)
    for r in s:
        r["recording_component"] = RECORDER
    S220 = s
    def att_fmt(i, r):
        if i == 2:
            r["platform_attestation"] = {"format": "tpm-quote", "result": "x", "bound_value": record_hash(S220[1]).hex()}
    V("224-attestation-format-unknown", "platform_attestation format 'tpm-quote'", ["3.2"], "reject",
      recs=finalize(s, signer=ind(K["recorder"], "ES256"), edit=att_fmt), errors=["E_PLATFORM_ATTESTATION"])
    s = base(trust="L3", recording_mode="independent", recording_component_id=RECORDER)
    for r in s:
        r["recording_component"] = RECORDER
    s[0]["platform_attestation"] = {"format": "ear", "result": "e30", "bound_value": hx("anything")}
    V("225-informative-attestation-genesis-unbatched", "Attestation in an un-batched genesis: no preceding record to bind to", ["5.4"], "accept",
      recs=finalize(s, signer=ind(K["recorder"], "ES256")), normative=False, warnings=["W_ATTESTATION_BINDING_UNDEFINED"],
      note="3.2 recommends the genesis record, but bound_value is defined as the record_hash of the PRECEDING record. See SPEC-NOTES.md.")

    # ---------- 23x  tombstones (9.3) ----------
    def tomb_session(signed, tomb_key="deleter", copy_sig=False, unsigned_tomb=False, drop_hash=False, wrong_hash=False, outcome="success"):
        s = base()
        signer = sign_all(K["agent"]) if signed else None
        s = finalize(s, signer=signer)
        orig = s[2]
        t = {k: orig[k] for k in ("record_id", "timestamp", "parent_record_id", "prev_hash", "agent_id", "principal", "agent_version",
                                  "session_id", "trust_level", "record_phase")}
        t.update(action_type="lifecycle", outcome=outcome,
                 action_detail={"event": "record_deleted", "deletion_reason": "gdpr_art17", "deleted_at": ts(3), "original_action_type": "tool_call"})
        if not drop_hash:
            t["tombstone_hash"] = hx("wrong") if wrong_hash else record_hash(orig).hex()
        if signed and not unsigned_tomb:
            if copy_sig:
                t.update(sig_alg=orig["sig_alg"], signer_kid=orig["signer_kid"], signature=orig["signature"])
            else:
                k = K[tomb_key]
                t.update(sig_alg="ES256", signer_kid=k.kid)
                t["signature"] = k.sign_hash(signed_bytes_hash(t))
        s[2] = t
        return s
    V("230-valid-tombstone-unsigned-chain", "GDPR tombstone in an unsigned chain", ["9.3"], "accept", recs=tomb_session(False), warnings=["W_TOMBSTONE"])
    V("231-valid-tombstone-signed-by-deleting-authority", "Signed chain, tombstone re-signed by the deleting authority", ["9.3"], "accept",
      recs=tomb_session(True), warnings=["W_TOMBSTONE"])
    V("232-tombstone-copied-signature", "Tombstone keeps the deleted record's signature", ["9.3"], "reject", recs=tomb_session(True, copy_sig=True),
      errors=["E_SIGNATURE_INVALID"])
    V("233-tombstone-unsigned-in-signed-chain", "Unsigned tombstone inside a signed chain", ["9.3"], "reject", recs=tomb_session(True, unsigned_tomb=True),
      errors=["E_TOMBSTONE_UNSIGNED"])
    V("234-tombstone-without-hash", "Tombstone lacks tombstone_hash", ["9.3"], "reject", recs=tomb_session(False, drop_hash=True),
      errors=["E_TOMBSTONE_HASH"])
    V("235-tombstone-hash-wrong", "tombstone_hash does not match the next record's prev_hash", ["9.3", "6.3"], "reject",
      recs=tomb_session(False, wrong_hash=True), errors=["E_CHAIN_BROKEN"])
    V("236-tombstone-outcome-failure", "Tombstone outcome must be success", ["9.3"], "reject", recs=tomb_session(False, outcome="failure"),
      errors=["E_TOMBSTONE_OUTCOME"])
    V("237-tombstone-by-agent-key", "Agent tombstones its own record (SHOULD NOT)", ["9.3"], "accept", recs=tomb_session(True, tomb_key="agent"),
      warnings=["W_TOMBSTONE", "W_TOMBSTONE_BY_AGENT_KEY"])


def _proof(leaves, idx):
    """RFC 6962 audit path with sides, for the promote-odd-node construction of Section 6.4."""
    path, level, i = [], list(leaves), idx
    while len(level) > 1:
        if i % 2 == 1:
            path.append({"hash": level[i - 1].hex(), "side": "left"})
        elif i + 1 < len(level):
            path.append({"hash": level[i + 1].hex(), "side": "right"})
        nxt = [node(level[j], level[j + 1]) for j in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level, i = nxt, i // 2
    return path


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(OUT)
    os.makedirs(os.path.join(HERE, "keys"), exist_ok=True)
    with open(os.path.join(HERE, "keys", "public.json"), "w") as f:
        json.dump({"keys": [dict(K[n].jwk, kid=K[n].kid, use="sig", name=n) for n in PUBLISHED]}, f, indent=2)
    with open(os.path.join(HERE, "keys", "TEST-ONLY-seeds.json"), "w") as f:
        json.dump({"warning": "TEST KEYS ONLY. Derived from public seeds. Never use outside this corpus.",
                   "derivation": "seed = SHA-256('aat-conformance-test-key/' + name)",
                   "keys": {n: {"alg": K[n].alg, "seed": K[n].seed, "kid": K[n].kid} for n in K}}, f, indent=2)
    build()
    with open(os.path.join(HERE, "index.json"), "w") as f:
        json.dump({"spec": "draft-sharif-agent-audit-trail-09", "count": len(VECTORS),
                   "normative": sum(v["normative"] for v in VECTORS),
                   "vectors": [{"id": v["id"], "verdict": v["expected"]["verdict"], "normative": v["normative"]} for v in VECTORS]}, f, indent=2)
    print("wrote", len(VECTORS), "vectors (%d normative)" % sum(v["normative"] for v in VECTORS))


if __name__ == "__main__":
    main()
