# logchain — Secure Log Aggregator with Merkle Integrity

Tamper-evident audit trail for log files. Each log entry is SHA-256 hashed on ingestion and incorporated into a Merkle tree — any retroactive modification to any historical entry is cryptographically detectable, without a blockchain or external service.

**59 tests · Rust · CLI · No external dependencies at runtime**

Independently checkable: a second verifier in Python ([`reference/verify_journal.py`](reference/verify_journal.py),
standard library only) implements the format from [`docs/FORMAT.md`](docs/FORMAT.md) without
touching this crate, and the two are checked against each other on every test run. What this
does and does not prove: [`docs/LIMITS.md`](docs/LIMITS.md).

---

## What problem does this solve?

Log files are the ground truth for audits, incident response, and compliance. They're also easy to falsify: an attacker with filesystem access can edit a log line and nothing in the system will notice.

logchain makes that edit detectable. Every entry is committed to a Merkle tree, and the root is
stored alongside the journal. Change any byte in any historical entry and the root no longer matches.

**Detectable by whom, and under what assumption, is the whole question.** A root kept next to the
journal it commits to is only evidence against someone who cannot edit both. That assumption, and
everything it excludes, is stated in [`docs/LIMITS.md`](docs/LIMITS.md) — read it before relying on this.

---

## How the Merkle tree works

A Merkle tree is a binary hash tree. Each leaf is `SHA-256(raw_log_line)`. Each internal node is `SHA-256(left_child || right_child)`. The root is a single 32-byte commitment over the entire ordered sequence.

```
                    root
                   /    \
                 H01    H23
                /   \  /   \
               h0   h1 h2   h3
```

Where `h0 = SHA-256(log_line_0)`, `H01 = SHA-256(h0 || h1)`, etc.

**Why this matters:** Change `log_line_2` → `h2` changes → `H23` changes → `root` changes. Every ancestor of the modified leaf changes. The stored root no longer matches the recomputed root, proving the journal was altered.

**Odd-count handling (Bitcoin convention):** When a level has an odd number of nodes, the last node is paired with itself before hashing up. Three leaves `[h0, h1, h2]` become pairs `(h0, h1)` and `(h2, h2)`. This means every internal node always has exactly two children, no matter the leaf count.

**Why not just hash everything concatenated?** `SHA-256("ab" || "c") == SHA-256("a" || "bc")` — this boundary ambiguity allows an attacker to split one entry into two or merge two into one without changing the hash. A Merkle tree avoids this by always hashing fixed-length 32-byte children.

**Order sensitivity:** `SHA-256(h0 || h1) != SHA-256(h1 || h0)`. Reordering any two log entries changes every internal node above them, all the way to the root.

---

## Two-level tamper detection

logchain catches tampering at two independent levels:

**Level 1 — per-entry:** On every `verify`, recompute `SHA-256(raw)` for each entry and compare it to the stored `hash` field. If they differ, the raw text was modified. This catches simple log falsification even if the attacker doesn't touch the hash field.

**Level 2 — Merkle root:** Recompute the Merkle root from all stored `hash` fields and compare it to the root saved in the state file. If they differ, either the hash fields themselves were modified, or entries were added/removed/reordered. This catches a sophisticated attacker who also updates the per-entry `hash` field — because they'd still need to recompute the root, and if an external snapshot was archived, that root will differ.

The combination means: modifying only `raw` is caught by level 1. Modifying `raw` + `hash` is caught by level 2. Either way, the falsification is detected.

---

## CLI commands

```
logchain [--data-dir PATH] <COMMAND>

Commands:
  tail <file> [--interval-ms N] [--once]   Ingest a log file (live or batch)
  verify                                    Check integrity against stored root
  export                                    Print committed JSON snapshot to stdout
  prove <seq>                               Print a Merkle inclusion proof for one entry
  status                                    Show entry count and current root
```

**`tail`** — reads a log file and appends any new lines to the journal. With `--once`, reads the whole file and exits. Without `--once`, polls for new lines every `--interval-ms` milliseconds (default 500).

**`verify`** — runs the full two-level check. Exits 0 if clean, 2 if tampered.

**What verification does and does not localise.** Detection is guaranteed; attribution is
deliberately limited, and the tool does not guess beyond what the data supports.

| finding | what it pins down | what it cannot say |
|---|---|---|
| `EntryHashMismatch` | the exact `seq` whose `raw` and `hash` disagree | **which of the two was edited.** `SHA-256(raw) != hash` is symmetric — editing the text and editing the stored hash produce an identical signature, and nothing in the journal distinguishes them |
| `RootMismatch` | that the journal as a whole no longer matches the stored root | **any single entry.** Every entry is self-consistent, so the cause is a state-file edit or whole entries added, dropped or reordered. It carries no `seq` because attributing it to one would be fabricated |
| `SeqMismatch` | the exact position whose `seq` is out of order | — |

Localising a `RootMismatch` any further would need an independent record of the expected
entry set. A journal plus its own state file cannot provide that — which is the argument for
archiving `export` output somewhere the attacker does not control.

**`export`** — prints a JSON snapshot containing the Merkle root and the full ordered list of per-entry hashes. Archive this externally so a local root-modification attack is also detectable.

**`prove`** — prints the inclusion proof for one entry as JSON, in the format documented in
[`docs/FORMAT.md`](docs/FORMAT.md) §9. Anyone holding the published root can check it without the journal.

**`status`** — quick summary of current state (entry count, root hex, last updated timestamp).

---

## Storage format

Two files in the data directory (default `./logchain-data/`):

**`logchain.journal`** — newline-delimited JSON, one entry per line:
```json
{"seq":0,"ingested_at":"2026-06-30T08:00:00Z","hash":"60f80b...","raw":"2026-06-30 INFO service started"}
```

- `seq`: zero-based index; out-of-order seqs are a tamper signal
- `ingested_at`: when logchain ingested the line (not the log's own timestamp)
- `hash`: `SHA-256(raw)`, hex-encoded
- `raw`: the original log line, verbatim

**`logchain.state`** — JSON object with the current Merkle root:
```json
{
  "merkle_root": "563ed4c9b240...",
  "entry_count": 20,
  "last_updated": "2026-06-30T08:04:17Z"
}
```

---

## Merkle inclusion proofs

The library (`src/merkle.rs`) also implements Merkle inclusion proofs. Given a leaf index, `generate_proof()` returns an `O(log n)` list of sibling hashes that lets any holder of the root verify that a specific entry was present when the root was computed — without needing the full journal.

```rust
let proof = generate_proof(&leaves, index).unwrap();
assert!(verify_proof(leaves[index], &proof, root));
```

---

## Check it yourself, without running our binary

Everything above is a claim about a format. `examples/audit-log/` is that claim as files you
can run, using a verifier that shares no code with the tool that wrote them.

`reference/verify_journal.py` is a second, independent implementation of the format in
`docs/FORMAT.md`: single file, Python 3 standard library only, no dependencies, and it
imports nothing from this crate and shells out to nothing. If you do not trust the Rust
binary — and you should not have to — this is the one to run. `docs/FORMAT.md` is precise
enough to write a third.

```
examples/audit-log/
  access.log               the 7 source log lines
  logchain.journal         the journal built from them
  logchain.state           the writer's own record of the root
  published-root.txt       the root and entry count, as they would be archived off-box
  proof-seq-3.json         an inclusion proof for entry 3
  tampered-entry/          one log line edited, its hash left alone
  tampered-root/           one line edited, its hash AND the state root rewritten to match
  forged-duplicate/        a known format defect, demonstrated (see step 5)
```

Set up (any shell; no build required for the verifier):

```bash
cd examples/audit-log
ROOT=$(grep merkle_root published-root.txt | cut -d= -f2)
N=$(grep entry_count published-root.txt | cut -d= -f2)
V="python ../../reference/verify_journal.py"
```

### 1. The clean journal passes

```console
$ $V --journal logchain.journal --root $ROOT --expect-entries $N
entries checked:  7
stored root:      11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
recomputed root:  11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
INTEGRITY OK
$ echo $?
0
```

The verifier recomputed all seven leaf hashes from the `raw` text and rebuilt the tree, and
landed on the same root that was published. Nothing was taken on trust from the state file.

**The root is reproducible from `access.log` alone.** Ingest it into a fresh directory and
you get the same root, even though every `ingested_at` timestamp will differ, because
`ingested_at` is not part of any hash:

```console
$ cargo run -q -- --data-dir /tmp/fresh tail access.log --once
$ grep merkle_root /tmp/fresh/logchain.state
  "merkle_root": "11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15",
```

### 2. The tampered copy fails, and names the entry

`tampered-entry/` has one line rewritten to hide the size of a bulk export —
`12,480 rows` became `12 rows` — with the stored hash left untouched. Level 1 catches it:

```console
$ $V --journal tampered-entry/logchain.journal --root $ROOT --expect-entries $N
entries checked:  7
stored root:      11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
recomputed root:  11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
  EntryHashMismatch seq=3 stored=18e1aaeb1177171e5522b0d34695ff5f9968ef1ad52cbb8512c15d84ce913987 recomputed=9d078ec76f026197a89d1de3dd501ce069133581d0b2f79de1f82f7164806901
INTEGRITY VIOLATION
$ echo $?
2
```

Note the root still matches: it is built from the stored `hash` fields, which were not
touched. The finding names `seq=3` but does not claim to know whether `raw` or `hash` was
the side that moved — that check is symmetric and nothing in the journal distinguishes them.

### 3. Why the published root has to be held by someone else

`tampered-root/` is the same edit made competently: the line, its `hash`, **and** the root in
`logchain.state` were all rewritten to agree. Checked against its own state file, it is clean:

```console
$ $V --journal tampered-root/logchain.journal --state tampered-root/logchain.state
entries checked:  7
stored root:      d3671c4e99e930f19eea8958a35d19c8b71162f981a59b56a5d803b593f41bff
recomputed root:  d3671c4e99e930f19eea8958a35d19c8b71162f981a59b56a5d803b593f41bff
INTEGRITY OK
```

`cargo run -- --data-dir examples/audit-log/tampered-root verify` says the same thing, because
the CLI has only the state file to compare against. The falsification surfaces only when the
root comes from outside:

```console
$ $V --journal tampered-root/logchain.journal --root $ROOT --expect-entries $N
entries checked:  7
stored root:      11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
recomputed root:  d3671c4e99e930f19eea8958a35d19c8b71162f981a59b56a5d803b593f41bff
  RootMismatch
INTEGRITY VIOLATION
$ echo $?
2
```

That contrast is the whole argument of `docs/LIMITS.md`. A self-held root catches accidents.
It does not catch the operator.

### 4. Checking the inclusion proof

`proof-seq-3.json` proves entry 3 was in the tree that produced the published root, without
needing the rest of the journal:

```console
$ $V --proof proof-seq-3.json --journal logchain.journal --root $ROOT
INCLUSION PROOF VALID   seq=3
$ echo $?
0
```

Passing `--journal` also confirms the entry with that `seq` really carries the leaf hash the
proof claims. Point the same proof at the forged root from step 3 and it is rejected:

```console
$ $V --proof proof-seq-3.json --root d3671c4e99e930f19eea8958a35d19c8b71162f981a59b56a5d803b593f41bff
INCLUSION PROOF INVALID seq=3
```

### 5. A defect this example also demonstrates

`forged-duplicate/` has **eight** entries — the seventh, duplicated and renumbered — and
produces a root byte-identical to the seven-entry journal it was forged from. Both verifiers
in this repository call it clean:

```console
$ $V --journal forged-duplicate/logchain.journal --root $ROOT
entries checked:  8
stored root:      11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
recomputed root:  11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
INTEGRITY OK
```

This is the odd-node convention working exactly as specified and being exploitable anyway —
the flaw known from Bitcoin as CVE-2012-2459. The entry count is what the root cannot carry,
which is why `published-root.txt` publishes both:

```console
$ $V --journal forged-duplicate/logchain.journal --root $ROOT --expect-entries $N
entries checked:  8
stored root:      11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
recomputed root:  11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
  EntryCountMismatch expected=7 actual=8
INTEGRITY VIOLATION
$ echo $?
2
```

Documented in `docs/FORMAT.md` §7, and pinned by a test so it cannot quietly change.

---

## Two implementations, checked against each other

`tests/cross_language.rs` runs the Rust verifier and the Python reference verifier over the
same on-disk fixtures — clean journals, every odd leaf count from 3 to 9, and each tampered
case the existing Rust tests build — and fails unless they agree on **all** of: the
recomputed root, the entry count, the root-match verdict, the clean verdict, and the ordered
list of findings with their field values.

Agreement on the clean cases alone would prove little. The value is that they agree on the
corrupted ones: the same `EntryHashMismatch` on the same `seq` with the same two hex digests,
the same lone `RootMismatch` where the format says a finding must not be attributed to any
entry.

The harness was checked for teeth by breaking the Python verifier three ways and confirming
the tests fail:

| deliberate mutation | tests failed |
|---|---|
| odd node promoted instead of paired with itself | 4 of 11 — every fixture that has an odd level somewhere; the even-only ones still passed, which is correct |
| `RootMismatch` reported without the suppression rule | 1 of 11 — the one fixture where a root difference and an entry finding coexist |
| pair-hash operand order swapped | 9 of 11 — everything except the empty and single-entry journals, which never pair |

---

## Demo

```powershell
# Build
cargo build --release

# Run the full tamper-detection demo
.\demo\tamper_demo.ps1
```

The demo:
1. Generates a 20-entry sample log (`demo/generate_log.py`)
2. Ingests it into the journal
3. Verifies clean
4. Exports a committed snapshot
5. Surgically modifies one historical entry in the journal
6. Re-verifies — logchain catches exactly the tampered entry

Expected output at step 7:
```
  ✓ Merkle root matches
  ✗ 1 tampered entry

    TAMPERED seq=7: raw content and stored hash disagree
        stored hash:     4fbbcd1905122571b40d8cfb320b9c92d41903a0c6357b13e60be8cfebe97431
        recomputed hash: 2bc19fdba5336b22b5f829b89967c704e7c9c5a5369cfb9566e034047f30761f
        (cannot tell which side was edited - the check is symmetric)

  ✗ INTEGRITY VIOLATION — journal has been tampered with
```

---

## Tests

```
cargo test
```

**59 tests total:**
- `src/hasher.rs` — 5 unit tests (known SHA-256 values, determinism, order sensitivity, hex round-trip)
- `src/merkle.rs` — 19 unit tests (root construction for 0–5 leaves, duplication rule, all-leaf tamper coverage, proof generation and verification, manual computation verification)
- `src/journal.rs` — 7 unit tests (append, sequential seqs, hash correctness, state update, state persistence, empty journal, incremental ingest)
- `src/verify.rs` — 7 unit tests (clean, empty, entry-hash mismatch detection, hash-field tamper detection, single entry, count + root match)
- `tests/integration.rs` — 10 end-to-end tests (ingest→verify clean, incremental ingest, raw-tamper caught, hash-tamper caught, **state-root tamper caught and not blamed on an entry**, export count/root, export hash correctness, root changes after tamper, empty clean, single-entry round-trip)

- `tests/cross_language.rs` — 11 cross-implementation tests. Each builds a fixture on disk,
  runs **both** the Rust verifier and `reference/verify_journal.py`, and fails unless they
  agree on the recomputed root, entry count, root-match verdict, clean verdict and the ordered
  findings. Covers clean journals, every odd leaf count from 3 to 9, all four tamper cases the
  other tests use, a deletion, Rust-generated inclusion proofs checked by the Python verifier,
  and **a pinned known defect** (`duplicated_last_entry_collides_with_the_genuine_root`).

Thirteen of these are the ones that matter: they write a real journal or proof, corrupt it on
disk, and assert the specific failure (2 in `verify.rs`, 4 in `integration.rs`, 7 in
`cross_language.rs`). A tamper-evidence claim that is only tested on the happy path is
not evidence of anything — and one that is only checked by the binary that wrote the file is
not independent of it.

These tests need a Python 3 interpreter on `PATH`. They fail loudly rather than skipping if
one is missing, because a silently skipped cross-implementation test would leave the central
claim of this repository unchecked.

---

## What tamper-evidence does not cover

logchain proves that entries in the journal were not altered after they were written. It
proves nothing about entries that were never written, and nothing about an entry that was
written accurately but left something out. A well-formed log line committed to the Merkle tree
verifies exactly the same whether or not it tells the whole story, because the commitment is
over the bytes it was given.

It also proves nothing about *who* wrote an entry or *when* — there is no signature anywhere in
this project, and `ingested_at` sits outside the leaf hash.

That gap is not an unfinished feature here. Testing whether a record is *complete* requires
starting from an independent population the operator does not control, which is a different
kind of work from hashing.

[`docs/LIMITS.md`](docs/LIMITS.md) is the short, full version of this section, including the
custody assumption the whole scheme rests on and a known defect in format version 1.

[**You cannot prove nothing was hidden**](https://github.com/JakPot42/filing-check/blob/master/docs/you-cannot-prove-nothing-was-hidden.md)
is an essay on exactly this boundary: what Merkle chains, Certificate Transparency, witness
cosigning and RFC 3161 timestamping genuinely deliver, why none of it reaches a filed report
that is false by omission, and what the measured result was when the independent-population
approach was actually built and run against live public data ([filing-check](https://github.com/JakPot42/filing-check)).

---

## Connection to portfolio themes

This project connects two threads running through the broader portfolio:

**Harvest Horizon** explored post-quantum cryptographic migration — the "harvest now, decrypt later" threat. logchain addresses a different but related problem: *retroactive log falsification*. Both are about cryptographic commitments: Harvest Horizon asks "are today's encryption choices secure against tomorrow's adversary?", logchain asks "can yesterday's log entries be trusted today?". Both come down to the same principle: a cryptographic commitment made at the right time and archived to an out-of-band location is unforgeable.

**Audit-trail/governance thread:** Every compliance-oriented project in the portfolio (SEAD 3, ATO Accelerator, CFIUS Screener) relies on audit logs as the ground truth for regulatory review. logchain is the cryptographic infrastructure that makes those audit logs trustworthy. A CFIUS filing or ATO package that references a logchain-verified audit trail can prove to a reviewer that the logs haven't been touched since the system was approved.

---

## Architecture

```
src/
  lib.rs       — module declarations
  hasher.rs    — SHA-256 primitives (Hash type alias, hash_bytes, hash_pair, to_hex/from_hex)
  merkle.rs    — pure Rust Merkle tree (compute_root, generate_proof, verify_proof)
  journal.rs   — on-disk storage (JournalEntry, LogchainState, append_entry, ingest_file)
  verify.rs    — integrity checking (check_journal, two-level tamper detection)
  report.rs    — terminal output, JSON export snapshot, inclusion proof files
  main.rs      — clap v4 CLI (tail, verify, export, prove, status)
reference/
  verify_journal.py — SECOND implementation: independent verifier, Python stdlib only
docs/
  FORMAT.md    — the on-disk format and verification procedure, byte level
  LIMITS.md    — what this proves and what it does not
examples/
  audit-log/   — runnable worked example: clean journal, published root, inclusion
                 proof, and three tampered copies
tests/
  integration.rs    — end-to-end pipeline tests
  cross_language.rs — Rust verifier vs Python verifier, same fixtures, must agree
demo/
  generate_log.py   — generates 20-entry sample.log
  tamper_demo.ps1   — orchestrates the full demo sequence
```

**`reference/verify_journal.py` deliberately shares nothing with `src/`.** No imports, no
subprocess calls, no generated code. It was written from `docs/FORMAT.md`. That independence
is the only thing that makes the agreement between them meaningful.

**Crate pattern:** `[lib]` + `[[bin]]` — the library is importable in integration tests without going through the binary. Same pattern as pcap-anomaly and bin-intel.

**No unsafe code. No hand-rolled cryptography.** SHA-256 comes from the `sha2` crate (RustCrypto project). The Merkle tree structure is hand-implemented — it's simple enough to fit in one file and important enough to understand every line.
