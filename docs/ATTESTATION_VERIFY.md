# Verifying an Aegis Core attestation (S051 ③)

Core **produces** a statement about what is on a disk. This SDK **verifies it
and nothing else.**

That split is the whole design. If the SDK also walked the capsule directory,
one disk would have two implementations answering one question, and the first
time they disagreed a customer would be told two different things about their
own data. So nothing here opens a capsule, and nothing here re-derives a verdict
— every fact in the report comes from Core, and the SDK's job is to decide
whether to believe it.

Wire contract: `aegis-boundary-core/docs/ATTESTATION_CONTRACT.md`.

## Quick start

```bash
# Core produces (on the deployment host)
aegis-gateway attest --capsule-root /var/lib/aegis/capsules \
  --audit-path /var/log/aegis/audit.log \
  --nonce "$(openssl rand -hex 16)" --json > attestation.json

# The SDK verifies (anywhere — all it needs is the public key)
aegis attest-verify attestation.json \
  --expect-key d04ab2...8737 \
  --expect-host host_<fingerprint> \
  --nonce "$THE_NONCE_YOU_SENT" \
  --state ~/.aegis/attest-state.json
```

```
  PASS document           the document has the shape of an attestation
  PASS signature_valid    Ed25519 over the canonical message
  PASS signing_key        signed by the pinned key
  PASS host               about host_<fingerprint>
  PASS nonce              the challenge came back
  PASS freshness          generated 12s ago
  FAIL sequence_advanced  the ledger head is still 412 — the same head as last
                          time, again. A boundary that has stopped recording
                          reports exactly this: nothing abnormal, chain valid,
                          no losses
  ...
[ANOMALY] 1 check(s) failed
```

Identical in TypeScript: `npx aegis attest-verify …`, or the library API
(`verifyAttestation` / `verify_attestation`).

## Exit codes

| code | meaning |
|---|---|
| 0 | clean |
| 1 | an attestation was obtained and it is **abnormal** |
| 2 | an attestation **could not be obtained** |

2 is deliberately distinct, and the SDK keeps it distinct. "I could not report"
is not "I found problems", and collapsing them means a broken pipe pages the
same person as a broken deployment.

Where the SDK draws the line:

* **2** — the file is missing, the input is empty, or the bytes are not JSON.
  Bytes that are not a document are indistinguishable from an invocation that
  failed.
* **1** — a JSON document arrived and is not a valid attestation, or is valid
  and fails a check. A document that arrived is a claim, and a claim that does
  not hold is an anomaly.

An **unsigned** attestation is 1, not 2. It is a report — an unauthenticable
one. Filing it as "the invocation failed" would route it to whoever fixes
pipelines, when what happened is that a boundary produced a statement nobody
can verify.

## What is checked

Any single failure is an anomaly. The verifier does not weigh them against each
other.

| check | why |
|---|---|
| `document` | it is an attestation, read without coercing any field |
| `signature_present` | **an unsigned attestation is not a verified one** |
| `signature_valid` | Ed25519 over the canonical message, rebuilt field by field |
| `message_digest` | `message_sha256` describes the message that was signed |
| `signing_key` | the signer is the key this deployment pinned |
| `host` | the attestation is about the machine that was pinned |
| `nonce` | the freshness challenge came back |
| `freshness` | `generated_at` is inside the window, and not in the future |
| `core_abnormal` | Core's own verdict is empty |
| `chain_status` | the ledger verified — absent is not intact |
| `sequence_advanced` | **the ledger grew** |
| `chain_linked` | it grew *forward*, rather than being rewritten to the same length |
| `chain_identity` | it is still the same ledger (the genesis anchor did not change) |
| `judged_nonzero` | something was actually examined |
| `inventory` | the capsules you expected are the ones reported |
| `report_arrived` | an attestation arrived at all (raised on the SDK's own timer) |

### Silence

> **A sequence that does not advance is itself an anomaly.**

This is the failure mode the layer exists for. A boundary that has stopped
writing records produces an attestation that looks calm: nothing abnormal,
chain valid, no losses, correctly signed, fresh. Every other check passes. Only
"the same head as last time, again" separates it from a healthy deployment.

That comparison needs the previous observation, which is why `--state` is not
optional in practice:

* without it, `sequence_advanced`, `chain_linked` and `chain_identity` report
  **skip**, not pass;
* a state file that exists and cannot be read is **refused**, not treated as a
  fresh start — the degradation would be the bypass;
* `--require-previous` makes a missing baseline a failure, for a deployment
  past its first attestation.

The baseline is **monotone on two axes independently**: the highest verified
ledger head, and the most recent attestation that arrived. Neither goes
backwards. Without that, a genuinely signed *old* attestation is a rollback
tool — replay the one from head 5 and every attestation between 5 and the real
head "advances" again, while the silence check keeps reporting about a boundary
that stopped recording days ago.

The other half of silence is the report that never came:

```bash
# No attestation to hand — just: has one arrived recently enough?
aegis attest-verify --state ~/.aegis/attest-state.json --report-within 3600
```

Nothing is asked of Core here. A boundary that has stopped reporting cannot be
the thing that tells you so.

## A check that did not run is not a check that passed

Every check reports `pass` / `fail` / **`skip` with a reason**, and skips are
printed rather than folded into the green:

```
[OK] attestation verified
      4 check(s) could not run: sequence_advanced, chain_linked, chain_identity, inventory
```

S012 is why this is spelled out: a shipped verifier in this codebase once
answered `LEDGER OK` and exit 0 about evidence that did not exist.

When the signature does not verify, every content check reports **skip** — not
pass. Their answers would be about text an attacker chose, and "9 of 11 checks
passed" on a forged document is a sentence no operator should be shown.

## What Core does not claim, so neither does this

Contract §6, restated because a verifier that believes an attestation proves
more than it does is worse than no attestation:

* **Decryptability is not proven.** The attestation proves a body is present
  and non-empty. Capsule bodies are AEAD-sealed against the sealing host, so a
  check that needed a key could not run where the key is not — and a check that
  cannot run gets muted. `aegis-gateway migrate verify-integrity` is the check
  that decrypts, on the host that can.

* **Completeness is not proven.** `judged` is what Core found under the root.
  **If twenty capsules should exist and one remains, the attestation reads
  `judged: 1` and is otherwise completely clean.** Catching that needs an
  expected set held on this side:

  ```bash
  aegis attest-verify attestation.json ... --expect-capsules expected-capsules.txt
  ```

  Leave it out and `inventory` reports **skip**, never pass.

## What the signature does not cover

One field: **`signature.key_id`**.

It is a label, and the key itself is what authenticates. Pinning it with
`--key-id` catches an honest misconfiguration — a rotation that moved the key
without the label, or the reverse — and catches nothing an attacker does,
because an attacker who is rewriting the document can set the label to whatever
is expected. That is stated here rather than implied, and the corpus case
`key-id-is-outside-the-signature` pins it: a relabelled document still verifies
and `signing_key` still passes.

`UNSIGNED_FIELDS` is that list in code, and it is **measured, not described**.
`test_the_signature_covers_everything_else` mutates every other field in a
signed attestation and requires the signature to break, then mutates the
declared ones and requires it to hold. A contract change that drops a field out
of the canonical message turns the first half red; one that adds a field without
updating the list turns the second half red.

### How the list got to one member

`records_checked`, `first_break` and `skipped_non_capsule` were outside the
message in the first draft of the contract. This verifier reported that while it
was being built. None of the three could manufacture false reassurance —
`judged` and the per-capsule findings digest were already signed, so no fake
loss and no fake health could be produced — but `skipped_non_capsule` is the
only window onto what was **not** counted, and blanking it hides "nineteen files
under the root were skipped" while every check still passes.

Core moved all three inside the message rather than leaving the SDK to report
them: a field that exists to be seen must be one that cannot be quietly emptied.
Three corpus cases (`records_checked-rewritten-after-signing` and its siblings)
pin that each one now breaks the signature on its own.

## Generating the challenge

Core validates the nonce at its entrance: a nonce containing control characters,
or longer than 128 bytes, is refused with **exit 2** rather than escaped — a
freshness challenge has no legitimate reason to contain a control character, and
escaping it would leave invisible characters in the operator's ledger. Multibyte
nonces are accepted; the digest is defined over bytes, so rejecting non-ASCII
would be a different rule wearing this one's name.

Whatever generates your challenge must respect the same limit, or Core refuses
the request and no attestation is produced at all. The SDK does not re-check it
— a nonce that reached an attestation already passed Core's entrance.

## Library API

```python
from aegis_trust import (
    AttestExpectation, verify_attestation, load_state, save_state,
    advance_state, report_arrived_check,
)

previous = load_state("state.json")          # None only if the file is ABSENT
verdict = verify_attestation(
    document,
    AttestExpectation(
        public_key_hex=PINNED_KEY,
        host_fingerprint=PINNED_HOST,
        nonce=challenge_i_sent,
        capsule_ids=("cap_0001", "cap_0002"),   # or None -> inventory skips
    ),
    previous,
)
if not verdict.ok:
    for finding in verdict.findings:
        alert(finding.check, finding.detail)
moved = advance_state(previous, verdict)      # None = do not rewrite the file
if moved:
    save_state("state.json", moved)
```

```ts
import { verifyAttestation, loadState, saveState, advanceState } from "aegis-trust";
```

## Ed25519, and why there are two implementations

The Node SDK verifies through OpenSSL (`node:crypto`). The Python SDK cannot:
`pip install aegis-trust` is dependency-free by contract, and Python has no
Ed25519 in its standard library. Adding a crypto dependency to the LITE path so
that a few users can verify an attestation would break the packaging invariant
for everyone else — so `python/src/aegis_trust/_ed25519.py` implements RFC 8032
**verification only** in `int` arithmetic.

Verification touches no secret: the public key, the message and the signature
are all values an attacker already has, so the absence of constant-time
behaviour costs nothing. That asymmetry is exactly why the verification half is
safe to hand-implement and a signing counterpart never would be. **There is no
signing code in either SDK, and there must not be.**

Two implementations of one primitive stop agreeing silently, so the agreement is
written down: `conformance/ed25519_vectors.v0.json` (the RFC 8032 known answers,
a real `ed25519-dalek` signature from the shipped Core binary, and rejection
vectors including the unreduced scalar `S + L`), read by both.

## How this is kept honest

* `conformance/attest_verify.v0.json` carries the **whole verdict** for each
  case — every check identifier, outcome and detail sentence — and both SDKs
  assert against it. The two cannot drift into describing one attestation two
  different ways.
* Every case carries a **hand-written `must`** (which checks have to fail, pass
  and skip). The generator refuses to emit a case whose verdict disagrees with
  it, and both runners re-assert it, so the corpus cannot become a record of
  whatever the code happens to do.
* Both runners assert that **every check has both a rejecting case and an
  accepting case**. A suite built only from broken material is passed by an
  implementation that always answers red; one built only from healthy material
  is passed by one that always answers green.
* `scripts/attest_verify_mutation_battery.py` goes a level lower: it breaks the
  shipped verifier on purpose and requires the suites to go red. A mutation that
  survives is a decorative test, and is reported as one.
* The Core-produced vectors are the byte-level pin. Nothing about the canonical
  message can be settled by reading the contract, so those four attestations were
  produced by the real `aegis-gateway` binary — three signed by `ed25519-dalek`,
  and one deliberately unsigned so that "no key configured" has a vector too.
  One of them carries a capsule id outside ASCII, because Rust's `str::len()`
  counts bytes and a
  verifier that length-prefixed by character count would agree on every ASCII
  capsule and diverge on the first one that is not.
