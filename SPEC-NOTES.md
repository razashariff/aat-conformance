# Notes on draft-sharif-agent-audit-trail-09 found while building this corpus

Building one test vector per requirement is a close reading of the text. These
are the places where -09 is ambiguous, inconsistent, or cannot be implemented
exactly as written. Each says what this corpus assumes and what -10 should say.

## Must fix

**N1. Hardware-attested genesis binding is undefined or circular (3.2, 5.4, 6.4).**
`bound_value` must equal the `merkle_root` of the epoch when batching is used,
otherwise "the record_hash of the record immediately preceding this object".
5.4 requires the attestation in the genesis record (or each epoch genesis).
- Without batching, the genesis record has no preceding record, so the binding is undefined.
- With batching, the attestation sits inside a leaf of the tree whose root it
  carries, so the root depends on itself. No implementation can produce it.

As written, hardware-attested mode cannot be satisfied.
*Corpus:* vector 225 is informative and warns `W_ATTESTATION_BINDING_UNDEFINED`. Vector 221 binds an attestation in a later record to the preceding record.
*Fix:* treat `platform_attestation` like `batch`: detached, and excluded from the chain hash, the signed message and the leaf hash. Or bind the genesis attestation to the hash of the genesis record computed without it.

**N2. `record_hash` is used but never defined (3.2, 5.4, 6.3, 6.4, 10.4).**
*Corpus:* `record_hash(R) = hex(SHA-256(JCS(R with "batch" removed)))`, which is the 6.1 `prev_hash` formula applied to R itself.
*Fix:* define it once in 6.1.

**N3. The lifecycle event registry (7.7) omits two events the text uses.**
`heartbeat` (8.4) and `record_deleted` (9.3) are not in the 7.7 list.
*Corpus:* both are accepted.
*Fix:* add both to 7.7 and to an IANA registry.

**N4. Tombstone shape is underspecified (9.3).**
- It is not stated whether `tombstone_hash` is a top-level field or sits inside `action_detail`.
- It is not stated which other mandatory fields the tombstone keeps.

*Corpus:* `tombstone_hash` is top-level. The tombstone keeps `agent_id`, `principal`, `agent_version`, `session_id`, `trust_level` and `record_phase` so that it is still a valid record. The next record's `prev_hash` must equal `tombstone_hash`.
*Fix:* state both.

**N5. `signer_kid` for ML-DSA-65 cannot be computed under RFC 7638 alone (3.2).**
RFC 7638 defines thumbprint members only for registered `kty` values, and there is no ML-DSA JWK in RFC 7518.
*Corpus:* uses the AKP key type from draft-ietf-cose-dilithium, with thumbprint members `alg`, `kty`, `pub`.
*Fix:* reference that draft normatively.
The earlier `aat-verify` 0.1.0 uses SHA-256 of the raw public key instead, which does not match.

## Should fix

**N6. "Sign the SHA-256 hash" (6.2 step 4) invites double hashing.**
For ES256, signing the 32-byte digest with ECDSA is exactly standard ES256 over the canonical bytes. An implementer who passes the digest to an ES256 API hashes twice instead.
*Corpus:* vector 196 rejects the double hash.
*Fix:* say "this is standard ES256 over the JCS bytes".
For Ed25519 and ML-DSA the message really is the 32-byte digest (vectors 197 and 198 reject signing the raw bytes).

**N7. Consequential actions are not machine-identifiable (5.3).**
A verifier cannot tell that a `tool_call` "indicates a payment", so the fail-safe default cannot be enforced by a generic verifier.
*Corpus:* vector 206 is informative.
*Fix:* add an `action_detail.consequence` code (payment, deletion, production_deploy, delegation, egress) with an IANA registry.

**N8. No revision marker.**
Two rules depend on the revision that produced a record, and nothing in the record says which revision that was:
- 3.1 says a mixed-revision archive may lack `principal`.
- 3.2 says a legacy signed record without `signer_kid` falls back to the -03 rule, while 3.3 says `signer_kid` MUST be present.

*Corpus:* takes the mixed-revision mode as an out-of-band verifier option (vector 016) and applies the strict 3.3 rule (vector 079).
*Fix:* add a top-level `aat_rev` field (the `aat_` reservation in 3.3 applies only to `action_detail`).

**N9. "Materially exceeds" the heartbeat interval is not quantified (6.3 step 9, 8.4).**
*Corpus:* treats more than 2x the interval as a gap (verifier option `heartbeat_tolerance`).
*Fix:* give a default.

**N10. The `session_hash` wording does not match the formula (8.3).**
The text says "concatenation of all record hashes", but the formula concatenates `prev_hash(1)` through `prev_hash(N)`. That covers records 0 to N-1 and not the close record itself, which is fine but should be said.
*Corpus:* follows the formula. Vector 147 rejects hashing the hex text.

**N11. Signed and unsigned records in one chain.**
It is not stated whether, once one record is signed, all records must be.
*Corpus:* allows a mix, except that a tombstone in a signed chain must be signed (9.3).

**N12. Hash encodings inside `action_detail` are not specified (7.x).**
`parameters_hash`, `response_hash`, `task_description_hash` and similar fields have no stated encoding. The top-level hashes in 3.2 say lowercase hex.
*Corpus:* checks presence only.

**N13. High-risk two-record pairing (4.3) needs a high-risk marker before it can be verified.**
The corpus has no vectors for it.

**N14. Padding in Base64url is not stated.**
*Corpus:* signatures are unpadded, and a verifier may accept padding.

## Inferences the corpus makes

- **Downgrade consistency (vector 204).** `downgraded: true` on a record whose `trust_level` is L2 or above contradicts 3.2's definition, which says downgraded means below the fail-safe default, and that default is L2. The corpus rejects it.
- **Recording component (vector 201).** A record signed by a key other than the agent's, with no `recording_component`, breaks 3.2 ("MUST be present" when the recorder differs from the agent).
- **Tool responses (vector 122).** `tool_response.parent_call_id` must name an earlier `tool_call`, or the tombstone of one, in the same session.
