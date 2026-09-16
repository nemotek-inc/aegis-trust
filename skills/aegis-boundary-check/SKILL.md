---
name: aegis-boundary-check
description: >-
  Check an Aegis deployment's boundary from the customer's own machine and say
  plainly what was verified and what was NOT. Use when someone asks "is our
  Aegis boundary healthy", "verify the attestation", "did the boundary report",
  "is the watcher running", "境界は生きているか", "attestation を検証して", or
  hands over an attestation file / heartbeat file to look at. NOT for changing
  policy, opening capsules, or anything that writes to the deployment.
---

# Check the boundary, and be honest about the edges

This skill runs the `aegis-trust` verifier **on the reader's own machine**,
against files the reader already holds, and reports the answer in the form the
reader can act on.

It exists because the verifier could already answer these questions and the
answer only ever appeared as an exit code and a line on stderr. A number nobody
can read is a number nobody checks.

## The one rule

**Report the limit with the result, every time — including when everything is
clean.** A reader who only ever sees "verified ✓" will take it for a guarantee
it is not, and the first time that matters is the time it is wrong.

Never say "your boundary is secure". Say what was checked, against what, and
what that leaves open.

## What to run

Verification of one attestation:

```bash
aegis attest-verify <attestation.json> \
  --expect-key <64-hex public key> \
  --expect-host <host fingerprint> \
  --state <state file> \
  --json
```

Whether a report arrived at all (no attestation needed — this is the silence
check):

```bash
aegis attest-verify --expect-key <key> --expect-host <host> \
  --state <state file> --report-within 7200 --json
```

Is the watcher running:

```bash
cat <heartbeat file>    # age of `finished_at` is the answer
```

## Exit codes are the verdict

| exit | meaning | say |
|---:|---|---|
| 0 | clean | every check the verifier can make, passed |
| 1 | abnormal | a check failed — name **which** one from the JSON |
| 2 | no report could be obtained | **not** "a problem was found", and **not** "fine". The verifier could not get an answer |

**Never collapse 1 and 2.** "I found something wrong" and "I could not look" are
different situations for the person reading, and merging them means a broken
invocation pages the same person as a broken deployment.

## What to report

1. **The verdict**, in one line, with the exit code.
2. **Which checks ran and what they said** — from `--json`, not from memory.
3. **What this does not establish.** Always. Use the list below.
4. If the verdict is bad: **what the reader can do next**, concretely.

### What a clean verdict does NOT establish

Say these in the reader's own terms; do not skip them because the result was
green.

* **It verifies an attestation, not your disk.** The verifier never opens the
  capsule directory. It checks that a signed statement from Core is
  well-formed, current, from the key and host you pinned, and consistent with
  what it said last time. If Core's own view of the disk is wrong, a valid
  attestation carries that wrongness faithfully.
* **A clean check covers the period the attestation describes** — not the time
  since. `--report-within` is what makes silence visible; without it, "no news"
  and "good news" are the same string.
* **Pinning is only as good as the values you pinned.** `--expect-key` and
  `--expect-host` are the reader's assertion. If those came from the same place
  as the attestation, the check is circular — and the skill should say so when
  it can tell.
* **The watcher can be dead while the last report was clean.** Check the
  heartbeat's age separately; a stale heartbeat means nobody has been looking,
  which is exactly the state the whole thing exists to make visible.
* **No notification path means no notification.** If `attest-watch` runs without
  `--notify-command`, a bad verdict is written to the heartbeat and told to
  nobody. The heartbeat records that; report it as a finding, not a detail.

## When the reader has no attestation yet

Do not simulate one and do not describe what it "would" say. Say that the
deployment has not produced a report the reader can check, and that this is
itself the first thing to fix — a boundary that cannot show its work is not
distinguishable, from outside, from one that is not working.

## Never

* Never open, decrypt, or list capsules. This skill reads an attestation and a
  heartbeat; that is the whole surface.
* Never write to the deployment, change policy, or restart a service.
* Never report a check the tool did not run. If a flag was unavailable, say the
  check was **not performed** rather than passing over it.
