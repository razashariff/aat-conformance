# Agent Audit Trail conformance corpus

Test vectors for **draft-sharif-agent-audit-trail-09** (Agent Audit Trail, AAT),
with a runner and a verifier written from the draft text.

- **184 vectors** (182 normative, 2 informative). Each is a complete JSONL session with a declared result.
- **Every requirement area of -09:**
  - the record format (3.1–3.3)
  - pre-execution recording (4.2)
  - recording independence and trust-level downgrades (5.2, 5.3)
  - hardware-attested recording (5.4)
  - the hash chain and JCS canonicalization (6.1)
  - ES256, Ed25519, ML-DSA-65 and hybrid signatures (6.2)
  - chain verification, including absence and tail completeness (6.3)
  - Merkle batch anchoring (6.4)
  - all seven action types (7)
  - genesis, close, heartbeats and branching (8)
  - GDPR tombstones (9.3)
  - JSONL export (10.1)
- **Valid and invalid cases.** Each invalid vector plants exactly one defect and keeps the chain and signatures otherwise correct, so it fails for the stated reason.
- **Interop traps** that a quick implementation gets wrong:
  - ECMAScript number serialization
  - UTF-16 key ordering
  - non-canonical storage
  - DER-encoded or double-hashed ECDSA
  - signing over the `batch` object
  - computing `prev_hash` without the previous record's signature

## Run it

```
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python run.py                          # bundled verifier
.venv/bin/python run.py --cmd "path/to/yours"    # your verifier
```

Your verifier is called as `<cmd> <trail.jsonl> <context.json>` and prints one JSON object:

```json
{"verdict": "accept|reject", "completeness": "complete|inconclusive|gaps|n/a",
 "merkle": "pass|fail|absent", "errors": ["E_..."], "warnings": ["W_..."]}
```

## Conformance

A verifier **conforms** when `verdict`, `completeness` and `merkle` match the declared values on
every normative vector.

Each vector also lists the error and warning codes it is expected to trigger. Matching those
codes is recommended, not required. The runner reports code mismatches separately.

| Field | Meaning | Spec |
|---|---|---|
| `verdict` | Integrity and format: accept or reject | 3, 4.2, 5, 6.1–6.3, 7, 8, 9.3, 10.1 |
| `completeness` | `complete` (close record present), `inconclusive` (tail unverifiable), `gaps` (heartbeat silence, or shorter than an anchored head) | 6.3 steps 9–10, 8.4 |
| `merkle` | Merkle inclusion, which is optional in the draft, so reported separately | 6.4 |

## Layout

```
vectors/<id>/trail.jsonl     the session, exactly as stored
vectors/<id>/context.json    public keys, agent key map, verifier options
vectors/<id>/vector.json     title, spec sections, declared result
keys/public.json             public JWKs (ES256, Ed25519, ML-DSA-65 as AKP)
keys/TEST-ONLY-seeds.json    seeds for the test keys, so anyone can regenerate the corpus
gen.py                       builds the corpus (expected results are written by hand from the draft)
aatc/                        reference verifier and an RFC 8785 canonicalizer
run.py                       runner
SPEC-NOTES.md                ambiguities in -09 found while building this, with proposed fixes for -10
RELEASE-MANIFEST.json        SHA-256 of every file, signed with the CyberSecAI release key
```

Every record has been cross-checked against an independent RFC 8785 library (`rfc8785`) before
being written. ES256 signatures are deterministic (RFC 6979), so the corpus regenerates
byte-identically apart from the ML-DSA-65 signatures.

## Independent implementations wanted

The interop signal that matters is a verifier **written from the draft text alone**, without
reading `aatc/`, that matches every normative vector. If you build one, please report your
result. Disagreements are useful: either the vector or the draft needs fixing, and
SPEC-NOTES.md shows where the text is weakest.

## Licence

(c) 2026 CyberSecAI Ltd, Raza Sharif. Code under BUSL-1.1 (see LICENSE).
The vectors, keys and notes may be used freely to test any implementation of the draft.
