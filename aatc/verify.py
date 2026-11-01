"""Agent Audit Trail (draft-sharif-agent-audit-trail-09) conformance verifier.

Written from the -09 text alone. Input: the raw JSONL bytes of one session and
a context (public keys as JWKs, the agent key map, verifier options).
Output: {"verdict", "completeness", "merkle", "errors", "warnings"}.

  verdict       "accept" | "reject"
  completeness  "complete" | "inconclusive" | "gaps" | "n/a"   (n/a when rejected)
  merkle        "pass" | "fail" | "absent"                        (Section 6.4, MAY)
"""
import base64, hashlib, json, re
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, utils

from .jcs import canonicalize, JCSError

MAX_RECORD = 256 * 1024
WARN_RECORD = 64 * 1024

ACTION_TYPES = {"tool_call", "tool_response", "decision", "delegation", "escalation", "error", "lifecycle"}
OUTCOMES = {"success", "failure", "timeout", "denied", "escalated"}
TRUST = {"L0", "L1", "L2", "L3", "L4"}
PHASES = {"pre_execution", "post_execution", "concurrent"}
PRINCIPAL_TYPES = {"human", "organization", "service", "agent"}
SIG_ALGS = {"ES256", "ML-DSA-65", "Ed25519"}
# 7.7 list, plus "heartbeat" (8.4) and "record_deleted" (9.3), which the text uses but 7.7 does not list
LIFECYCLE_EVENTS = {"session_start", "session_end", "pause", "resume", "configuration_change",
                    "key_rotation", "trust_level_change", "heartbeat", "record_deleted"}
ERROR_CATEGORIES = {"transport", "authentication", "authorization", "validation", "timeout", "internal", "external"}
URGENCY = {"low", "medium", "high", "critical"}
MANDATORY = ["record_id", "timestamp", "agent_id", "principal", "agent_version", "session_id", "action_type",
             "action_detail", "outcome", "trust_level", "parent_record_id", "prev_hash", "record_phase"]
REQUIRED_DETAIL = {
    "tool_call": ["tool_name", "parameters_hash"],
    "tool_response": ["tool_name", "response_hash", "parent_call_id"],
    "decision": ["decision_type"],
    "delegation": ["delegate_agent_id", "delegate_trust_level", "task_description_hash"],
    "escalation": ["escalation_reason", "escalation_target"],
    "error": ["error_code", "error_message", "error_category", "recoverable"],
    "lifecycle": ["event"],
}

RE_UUID4 = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
RE_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")
RE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:[^\s]+$")
RE_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                       r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
                       r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$")
RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")
RE_HEXNONCE = re.compile(r"^[0-9a-f]{32,}$")
RE_CC = re.compile(r"^[A-Z]{2}$")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK SHA-256 thumbprint. AKP (ML-DSA) members per draft-ietf-cose-dilithium."""
    kty = jwk.get("kty")
    if kty == "EC":
        req = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif kty == "OKP":
        req = {k: jwk[k] for k in ("crv", "kty", "x")}
    elif kty == "AKP":
        req = {k: jwk[k] for k in ("alg", "kty", "pub")}
    else:
        raise ValueError("unsupported kty")
    return b64u(sha256(canonicalize(req)))


def load_keyset(jwks: list) -> dict:
    out = {}
    for j in jwks:
        out[thumbprint(j)] = j
    return out


def _ts(s):
    """RFC 3339 date-time -> exact UTC seconds (Decimal), or None if invalid."""
    m = RE_TS.match(s) if isinstance(s, str) else None
    if not m:
        return None
    y, mo, d, h, mi, se, frac, off = m.groups()
    try:
        if off.upper() == "Z":
            tz = timezone.utc
        else:
            oh, om = int(off[1:3]), int(off[4:6])
            if oh > 23 or om > 59:
                return None
            tz = timezone((1 if off[0] == "+" else -1) * timedelta(hours=oh, minutes=om))
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), tzinfo=tz)
    except ValueError:
        return None
    return Decimal(int(dt.timestamp())) + (Decimal(frac) if frac else Decimal(0))


def record_hash(rec: dict) -> bytes:
    return sha256(canonicalize({k: v for k, v in rec.items() if k != "batch"}))


def signed_bytes_hash(rec: dict) -> bytes:
    return sha256(canonicalize({k: v for k, v in rec.items() if k not in ("signature", "signature_classical", "batch")}))


def leaf_hash(rec: dict) -> bytes:
    return sha256(b"\x00" + canonicalize({k: v for k, v in rec.items() if k != "batch"}))


def node(l: bytes, r: bytes) -> bytes:
    return sha256(b"\x01" + l + r)


def merkle_root(leaves: list) -> bytes:
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node(level[i], level[i + 1]))
        if len(level) % 2:
            nxt.append(level[-1])          # odd node promoted unchanged (Section 6.4)
        level = nxt
    return level[0]


def _verify_sig(alg: str, jwk: dict, h: bytes, sig: str) -> bool:
    try:
        raw = b64u_dec(sig)
        if alg == "ES256":
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or len(raw) != 64:
                return False
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(b64u_dec(jwk["x"]), "big"),
                                                int.from_bytes(b64u_dec(jwk["y"]), "big"),
                                                ec.SECP256R1()).public_key()
            der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
            pub.verify(der, h, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        if alg == "Ed25519":
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or len(raw) != 64:
                return False
            ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"])).verify(raw, h)
            return True
        if alg == "ML-DSA-65":
            if jwk.get("kty") != "AKP" or jwk.get("alg") != "ML-DSA-65":
                return False
            mldsa.MLDSA65PublicKey.from_public_bytes(b64u_dec(jwk["pub"])).verify(raw, h)
            return True
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False
    return False


class _Dup(ValueError):
    pass


def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise _Dup(k)
        d[k] = v
    return d


def verify(trail: bytes, context: dict) -> dict:
    errors, warnings = [], []
    E = lambda code, i=None: errors.append(code if i is None else f"{code}@{i}")
    W = lambda code, i=None: warnings.append(code if i is None else f"{code}@{i}")
    opts = context.get("options", {})
    keys = load_keyset(context.get("keys", []))
    agent_kids = context.get("agent_kids", {})

    def done(merkle="absent", completeness="n/a"):
        ok = not errors
        return {"verdict": "accept" if ok else "reject",
                "completeness": completeness if ok else "n/a",
                "merkle": merkle, "errors": sorted(set(errors)), "warnings": sorted(set(warnings))}

    # ---- 10.1 JSONL ----
    try:
        text = trail.decode("utf-8")
    except UnicodeDecodeError:
        E("E_UTF8"); return done()
    if text.startswith("﻿"):
        W("W_BOM"); text = text[1:]
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    recs = []
    for i, ln in enumerate(lines):
        if len(ln.encode("utf-8")) > MAX_RECORD:
            E("E_SIZE", i); continue
        if len(ln.encode("utf-8")) > WARN_RECORD:
            W("W_SIZE", i)
        try:
            obj = json.loads(ln, object_pairs_hook=_no_dups, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
        except _Dup:
            E("E_DUPLICATE_KEY", i); continue
        except ValueError:
            E("E_JSONL", i); continue
        if not isinstance(obj, dict):
            E("E_JSONL", i); continue
        try:
            canonicalize(obj)
        except JCSError:
            E("E_NOT_IJSON", i); continue
        recs.append(obj)
    if errors:
        return done()
    if not recs:
        E("E_EMPTY"); return done()

    # ---- 3.1 / 3.2 / 3.3 / 7 per record ----
    for i, r in enumerate(recs):
        for f in MANDATORY:
            if f not in r:
                if f == "principal" and opts.get("mixed_revision"):
                    W("W_PRINCIPAL_NOT_RECORDED", i)
                else:
                    E("E_MISSING_" + f.upper(), i)
        if "record_id" in r and not (isinstance(r["record_id"], str) and RE_UUID4.match(r["record_id"])):
            E("E_RECORD_ID", i)
        if "session_id" in r and not (isinstance(r["session_id"], str) and RE_UUID4.match(r["session_id"])):
            E("E_SESSION_ID", i)
        if "timestamp" in r and _ts(r["timestamp"]) is None:
            E("E_TIMESTAMP", i)
        if "agent_id" in r and not (isinstance(r["agent_id"], str) and RE_URI.match(r["agent_id"])):
            E("E_AGENT_ID", i)
        if "agent_version" in r and not (isinstance(r["agent_version"], str) and RE_SEMVER.match(r["agent_version"])):
            E("E_AGENT_VERSION", i)
        if "action_type" in r and r["action_type"] not in ACTION_TYPES:
            E("E_ACTION_TYPE", i)
        if "outcome" in r and r["outcome"] not in OUTCOMES:
            E("E_OUTCOME", i)
        if "trust_level" in r and r["trust_level"] not in TRUST:
            E("E_TRUST_LEVEL", i)
        if "record_phase" in r and r["record_phase"] not in PHASES:
            E("E_RECORD_PHASE", i)
        for f in ("parent_record_id",):
            if f in r and r[f] is not None and not (isinstance(r[f], str) and RE_UUID4.match(r[f])):
                E("E_PARENT_RECORD_ID", i)
        if "prev_hash" in r and r["prev_hash"] is not None and not (isinstance(r["prev_hash"], str) and RE_HEX64.match(r["prev_hash"])):
            E("E_PREV_HASH_FORMAT", i)
        p = r.get("principal")
        if "principal" in r:
            if not isinstance(p, dict):
                E("E_PRINCIPAL", i)
            else:
                if p.get("principal_type") not in PRINCIPAL_TYPES:
                    E("E_PRINCIPAL_TYPE", i)
                if not (isinstance(p.get("principal_id"), str) and RE_URI.match(p["principal_id"])):
                    E("E_PRINCIPAL_ID", i)
                if "authority_ref" not in p or not (p["authority_ref"] is None or isinstance(p["authority_ref"], str)):
                    E("E_AUTHORITY_REF", i)
        ad = r.get("action_detail")
        if "action_detail" in r:
            if not isinstance(ad, dict):
                E("E_ACTION_DETAIL", i); ad = None
            elif not ad:
                E("E_ACTION_DETAIL_EMPTY", i)
        if isinstance(ad, dict):
            if any(isinstance(k, str) and k.startswith("aat_") for k in ad):
                E("E_RESERVED_PREFIX", i)
            at = r.get("action_type")
            for f in REQUIRED_DETAIL.get(at, []):
                if f not in ad:
                    E("E_DETAIL_MISSING_" + f.upper(), i)
            if at == "lifecycle" and "event" in ad and ad["event"] not in LIFECYCLE_EVENTS:
                E("E_LIFECYCLE_EVENT", i)
            if at == "error":
                if "error_category" in ad and ad["error_category"] not in ERROR_CATEGORIES:
                    E("E_ERROR_CATEGORY", i)
                if "recoverable" in ad and not isinstance(ad["recoverable"], bool):
                    E("E_RECOVERABLE", i)
            if at == "escalation" and "urgency" in ad and ad["urgency"] not in URGENCY:
                E("E_URGENCY", i)
            if at == "delegation" and "delegate_trust_level" in ad and ad["delegate_trust_level"] not in TRUST:
                E("E_DELEGATE_TRUST_LEVEL", i)
            if at == "decision" and "confidence" in ad and not (isinstance(ad["confidence"], (int, float)) and not isinstance(ad["confidence"], bool) and 0 <= ad["confidence"] <= 1):
                E("E_CONFIDENCE", i)
        # optional fields (3.2)
        if "risk_score" in r and not (isinstance(r["risk_score"], (int, float)) and not isinstance(r["risk_score"], bool) and 0 <= r["risk_score"] <= 1):
            E("E_RISK_SCORE", i)
        for f in ("input_hash", "output_hash", "content_fingerprint"):
            if f in r and not (isinstance(r[f], str) and RE_HEX64.match(r[f])):
                E("E_" + f.upper(), i)
        if "jurisdiction" in r and not (isinstance(r["jurisdiction"], str) and RE_CC.match(r["jurisdiction"])):
            E("E_JURISDICTION", i)
        if "sanctions_check" in r:
            sc = r["sanctions_check"]
            if not isinstance(sc, dict) or ("result" in sc and sc["result"] not in ("clear", "match", "error")):
                E("E_SANCTIONS_CHECK", i)
        if "deny_reasons" in r and not (isinstance(r["deny_reasons"], list) and all(isinstance(x, str) for x in r["deny_reasons"])):
            E("E_DENY_REASONS", i)
        if "nonce" in r and not (isinstance(r["nonce"], str) and RE_HEXNONCE.match(r["nonce"])):
            E("E_NONCE_FORMAT", i)
        if "external_timestamp" in r:
            et = r["external_timestamp"]
            if not isinstance(et, dict) or any(k not in et for k in ("tsa_url", "token", "anchored_at")) or _ts(et.get("anchored_at")) is None:
                E("E_EXTERNAL_TIMESTAMP", i)
        if "sig_alg" in r and r["sig_alg"] not in SIG_ALGS:
            E("E_SIG_ALG", i)
        if "signature" in r and "signer_kid" not in r:
            E("E_SIGNER_KID_MISSING", i)
        if "signature_classical" in r and "signer_kid_classical" not in r:
            E("E_SIGNER_KID_CLASSICAL_MISSING", i)
        if "recording_component" in r and not (isinstance(r["recording_component"], str) and RE_URI.match(r["recording_component"])):
            E("E_RECORDING_COMPONENT", i)
        if "trust_assignment" in r:
            ta = r["trust_assignment"]
            if not isinstance(ta, dict) or not isinstance(ta.get("classifier_id"), str) or not isinstance(ta.get("policy_version"), str) or not isinstance(ta.get("downgraded"), bool):
                E("E_TRUST_ASSIGNMENT", i)
            elif "policy_digest" in ta and not (isinstance(ta["policy_digest"], str) and RE_HEX64.match(ta["policy_digest"])):
                E("E_TRUST_ASSIGNMENT", i)
        if "prior_generation_tail" in r:
            pg = r["prior_generation_tail"]
            if i != 0:
                E("E_PRIOR_GENERATION_TAIL_NOT_GENESIS", i)
            if not isinstance(pg, dict) or not isinstance(pg.get("prev_generation_id"), str) or not (isinstance(pg.get("tail_record_hash"), str) and RE_HEX64.match(pg["tail_record_hash"])):
                E("E_PRIOR_GENERATION_TAIL", i)
        if "sequence_number" in r and not (isinstance(r["sequence_number"], int) and not isinstance(r["sequence_number"], bool)):
            E("E_SEQUENCE_NUMBER", i)
        if "batch" in r:
            b = r["batch"]
            if not isinstance(b, dict) or not (isinstance(b.get("epoch_id"), str) and RE_UUID4.match(b["epoch_id"])) \
               or not (isinstance(b.get("merkle_root"), str) and RE_HEX64.match(b["merkle_root"])) \
               or not (isinstance(b.get("leaf_index"), int) and not isinstance(b.get("leaf_index"), bool) and b["leaf_index"] >= 0):
                E("E_BATCH", i)
        if "platform_attestation" in r:
            pa = r["platform_attestation"]
            if not isinstance(pa, dict) or pa.get("format") not in ("ear", "ar4si") or not isinstance(pa.get("result"), str) \
               or not (isinstance(pa.get("bound_value"), str) and RE_HEX64.match(pa["bound_value"])):
                E("E_PLATFORM_ATTESTATION", i)
    if errors:
        return done()

    # ---- session structure (8) and chain (6.1, 6.3) ----
    g = recs[0]
    if g["action_type"] != "lifecycle" or g["action_detail"].get("event") != "session_start":
        E("E_GENESIS_NOT_SESSION_START")
    if g["parent_record_id"] is not None:
        E("E_GENESIS_PARENT")
    if g["prev_hash"] is not None:
        E("E_GENESIS_PREV_HASH")
    if g["record_phase"] != "concurrent":
        E("E_GENESIS_PHASE")
    sid = g["session_id"]
    ids, nonces, call_ids = set(), set(), set()
    seq_present = ["sequence_number" in r for r in recs]
    if any(seq_present) and not all(seq_present):
        E("E_SEQUENCE_PARTIAL")
    prev_t = None
    for i, r in enumerate(recs):
        if r["session_id"] != sid:
            E("E_SESSION_MISMATCH", i)
        if r["record_id"] in ids:
            E("E_DUPLICATE_RECORD_ID", i)
        ids.add(r["record_id"])
        t = _ts(r["timestamp"])
        if prev_t is not None and t < prev_t:
            E("E_TIMESTAMP_BACKDATED", i)
        prev_t = t
        if i > 0:
            if r["parent_record_id"] is None:
                E("E_PARENT_NULL", i)
            elif r["parent_record_id"] != recs[i - 1]["record_id"]:
                E("E_PARENT_MISMATCH", i)
            prevrec = recs[i - 1]
            expect = (prevrec.get("tombstone_hash") if _is_tombstone(prevrec) else record_hash(prevrec).hex())
            if r["prev_hash"] is None or r["prev_hash"] != expect:
                E("E_CHAIN_BROKEN", i)
        if all(seq_present) and seq_present and r.get("sequence_number") != i:
            E("E_SEQUENCE_GAP", i)
        at, oc, ph, ad = r["action_type"], r["outcome"], r["record_phase"], r["action_detail"]
        if (at in ("decision", "delegation") and oc == "denied") or (at == "decision" and oc == "escalated"):
            if ph != "pre_execution":
                E("E_PHASE_PRE_EXECUTION_REQUIRED", i)
        if "nonce" in r:
            if r["nonce"] in nonces:
                E("E_NONCE_REUSED", i)
            nonces.add(r["nonce"])
        if at == "tool_call" or (_is_tombstone(r) and ad.get("original_action_type") == "tool_call"):
            call_ids.add(r["record_id"])
        if at == "tool_response" and ad.get("parent_call_id") not in call_ids:
            E("E_PARENT_CALL_UNKNOWN", i)
        if at == "lifecycle" and ad.get("event") == "session_end" and i != len(recs) - 1:
            E("E_CLOSE_NOT_LAST", i)
        if at == "lifecycle" and ad.get("event") == "session_start" and i != 0:
            E("E_SESSION_START_NOT_GENESIS", i)
        if _is_tombstone(r):
            W("W_TOMBSTONE", i)
            if not (isinstance(r.get("tombstone_hash"), str) and RE_HEX64.match(r["tombstone_hash"])):
                E("E_TOMBSTONE_HASH", i)
            if oc != "success":
                E("E_TOMBSTONE_OUTCOME", i)

    # ---- signatures and recording independence (5.2, 6.2, 6.3 step 3, 9.3) ----
    signed_chain = any("signature" in r for r in recs if not _is_tombstone(r))
    for i, r in enumerate(recs):
        tomb = _is_tombstone(r)
        if tomb and signed_chain and "signature" not in r:
            E("E_TOMBSTONE_UNSIGNED", i)
        agent_kid = agent_kids.get(r["agent_id"])
        rc = r.get("recording_component")
        independent = rc is not None and rc != r["agent_id"]
        if "signature" in r:
            kid = r["signer_kid"]
            jwk = keys.get(kid)
            alg = r.get("sig_alg", "ES256")
            if jwk is None:
                E("E_SIGNER_KID_UNKNOWN", i)
            elif not _verify_sig(alg, jwk, signed_bytes_hash(r), r["signature"]):
                E("E_SIGNATURE_INVALID", i)
            if not tomb:
                if independent and kid == agent_kid:
                    E("E_RECORDER_KEY_NOT_INDEPENDENT", i)
                if not independent and agent_kid is not None and kid != agent_kid:
                    E("E_RECORDING_COMPONENT_UNDECLARED", i)
            elif agent_kid is not None and kid == agent_kid:
                W("W_TOMBSTONE_BY_AGENT_KEY", i)
            if "signature_classical" in r:
                kc = r["signer_kid_classical"]
                if kc == kid:
                    E("E_HYBRID_SAME_KEY", i)
                jc = keys.get(kc)
                if jc is None or not _verify_sig("ES256", jc, signed_bytes_hash(r), r["signature_classical"]):
                    W("W_HYBRID_CLASSICAL_FAILED", i)
        elif "signature_classical" in r:
            E("E_CLASSICAL_WITHOUT_PRIMARY", i)

    # ---- trust-level downgrade attribution (5.3): a recorded downgrade must be attributable ----
    for i, r in enumerate(recs):
        ta = r.get("trust_assignment")
        if isinstance(ta, dict) and ta.get("downgraded") is True and r["trust_level"] not in ("L0", "L1"):
            E("E_DOWNGRADE_INCONSISTENT", i)

    # ---- hardware-attested recording (5.4) ----
    mode = g["action_detail"].get("recording_mode")
    for i, r in enumerate(recs):
        pa = r.get("platform_attestation")
        if not pa:
            continue
        if "batch" in r:
            want = r["batch"]["merkle_root"]
        elif i > 0:
            want = record_hash(recs[i - 1]).hex()
        else:
            want = None
            W("W_ATTESTATION_BINDING_UNDEFINED", i)
        if want is not None and pa["bound_value"] != want:
            E("E_ATTESTATION_UNBOUND", i)
    if mode == "hardware-attested":
        epoch_gen = {}
        for i, r in enumerate(recs):
            if "batch" in r:
                epoch_gen.setdefault(r["batch"]["epoch_id"], i)
        need = set(epoch_gen.values()) or {0}
        for i in need:
            if "platform_attestation" not in recs[i]:
                E("E_ATTESTATION_MISSING", i)
        if "recording_component" not in g:
            E("E_RECORDING_COMPONENT_UNDECLARED", 0)

    # ---- close record (8.3) ----
    last = recs[-1]
    closed = last["action_type"] == "lifecycle" and last["action_detail"].get("event") == "session_end"
    if closed:
        if last["record_phase"] != "post_execution":
            E("E_CLOSE_PHASE")
        sh = last["action_detail"].get("session_hash")
        if sh is None:
            E("E_CLOSE_SESSION_HASH_MISSING")
        else:
            try:
                want = hashlib.sha256(b"".join(bytes.fromhex(r["prev_hash"]) for r in recs[1:])).hexdigest()
            except (TypeError, ValueError):
                want = None
            if sh != want:
                E("E_SESSION_HASH")

    # ---- Merkle batch anchoring (6.4, MAY) ----
    merkle = "absent"
    epochs = {}
    for i, r in enumerate(recs):
        if "batch" in r:
            epochs.setdefault(r["batch"]["epoch_id"], []).append((r["batch"]["leaf_index"], i))
    if epochs:
        merkle = "pass"
        for ep, members in epochs.items():
            roots = {recs[i]["batch"]["merkle_root"] for _, i in members}
            if len(roots) != 1:
                merkle = "fail"; continue
            root = roots.pop()
            for li, i in members:
                proof = recs[i]["batch"].get("inclusion_proof")
                if proof is None:
                    continue
                h = leaf_hash(recs[i])
                try:
                    for step in proof:
                        sib = bytes.fromhex(step["hash"])
                        h = node(sib, h) if step["side"] == "left" else node(h, sib) if step["side"] == "right" else None
                        if h is None:
                            raise ValueError
                except (KeyError, ValueError, TypeError):
                    merkle = "fail"; continue
                if h.hex() != root:
                    merkle = "fail"
            idx = sorted(members)
            if [li for li, _ in idx] == list(range(len(idx))) and opts.get("epochs_complete", True):
                if merkle_root([leaf_hash(recs[i]) for _, i in idx]).hex() != root:
                    merkle = "fail"

    # ---- absence checks (6.3 step 9) and tail completeness (step 10) ----
    completeness = "complete" if closed else "inconclusive"
    hb = g["action_detail"].get("heartbeat_interval_s")
    if isinstance(hb, int) and hb > 0:
        tol = Decimal(opts.get("heartbeat_tolerance", 2))
        for i in range(1, len(recs)):
            if _ts(recs[i]["timestamp"]) - _ts(recs[i - 1]["timestamp"]) > hb * tol:
                completeness = "gaps"; W("W_HEARTBEAT_GAP", i)
    anchor = opts.get("anchored_head")
    if anchor:
        n, h = anchor["record_count"], anchor["record_hash"]
        if len(recs) < n:
            completeness = "gaps"; W("W_SHORTER_THAN_ANCHOR")
        elif record_hash(recs[n - 1]).hex() != h:
            E("E_ANCHOR_MISMATCH", n - 1)
    return done(merkle, completeness)


def _is_tombstone(r) -> bool:
    return r.get("action_type") == "lifecycle" and isinstance(r.get("action_detail"), dict) \
        and r["action_detail"].get("event") == "record_deleted"


def verify_files(trail_path, context_path) -> dict:
    with open(context_path) as f:
        ctx = json.load(f)
    base = context_path.rsplit("/", 1)[0]
    if "keyset" in ctx:
        with open(f"{base}/{ctx['keyset']}") as f:
            ctx["keys"] = json.load(f)["keys"]
    with open(trail_path, "rb") as f:
        return verify(f.read(), ctx)
