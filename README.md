# logchain — Secure Log Aggregator with Merkle Integrity

Tamper-evident audit trail for log files. Each log entry is SHA-256 hashed on ingestion and incorporated into an RFC 6962 Merkle tree — any retroactive modification to any historical entry is cryptographically detectable, without a blockchain or external service.

**Format version 2 · 64 tests · Rust · CLI · No external dependencies at runtime**

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

Format version 2 uses the RFC 6962 construction. Each leaf is
`SHA-256(0x00 || raw_log_line)`; each internal node is `SHA-256(0x01 || left || right)`.
The root is a single 32-byte commitment over the entire ordered sequence.

```
Four entries (a power of two, so the tree is balanced):

                    root
                   /    \
                 N01    N23
                /   \   /  \
               h0   h1 h2  h3

Seven entries: split at k=4, the largest power of two below 7.

                        root
                     /        \
              (0..4)            (4..7)
              /    \            /     \
            N01    N23        N45     h6
           /  \    /  \       /  \
          h0  h1  h2  h3     h4  h5
```

Where `h0 = SHA-256(0x00 || log_line_0)` and `N01 = SHA-256(0x01 || h0 || h1)`.
Note `h6`: a lone leaf is carried up unchanged, never paired with itself.

**Why this matters:** Change `log_line_2` → `h2` changes → `N23` changes → `root`
changes. Every ancestor of the modified leaf changes, so the stored root no longer
matches the recomputed root.

**Domain separation (`0x00` / `0x01`).** Tagging leaves and internal nodes differently
means the two are hashed in disjoint domains, so a 64-byte internal-node preimage can
never be passed off as a log line, or the reverse.

**Uneven counts: split at the largest power of two.** When the leaf count `n` is not a
power of two, the list is split into the first `k` leaves and the rest, where `k` is the
largest power of two below `n` — not paired adjacently with a leftover. Seven leaves
split 4 and 3; three leaves split 2 and 1, and the lone leaf is carried up unchanged.
**No node is ever its own sibling**, so the tree's shape is determined entirely by `n`
and journals of different lengths cannot share a root.

> **Version 1 did this differently and had a root collision.** It paired adjacent nodes
> and duplicated the last node on an odd level, which let a journal gain a duplicate
> final entry without changing its root — CVE-2012-2459, found here by writing
> [`docs/FORMAT.md`](docs/FORMAT.md) rather than by testing. Version 2 is a clean break:
> v1 roots are void, v1 journals are detected and rejected rather than misread. The
> story is in [`docs/LIMITS.md`](docs/LIMITS.md); the forgery is kept as a runnable
> fixture in step 5 below. Note that domain separation alone would *not* have fixed it —
> only the tree-shape change did.

**Why not just hash everything concatenated?** `SHA-256("ab" || "c") == SHA-256("a" || "bc")` — this boundary ambiguity allows an attacker to split one entry into two or merge two into one without changing the hash. A Merkle tree avoids this by always hashing fixed-length 32-byte children.

**Order sensitivity:** `NODE(h0, h1) != NODE(h1, h0)`. Reordering any two log entries changes every internal node above them, all the way to the root.

---

## Two-level tamper detection

logchain catches tampering at two independent levels:

**Level 1 — per-entry:** On every `verify`, recompute `SHA-256(0x00 || raw)` for each entry and compare it to the stored `hash` field. If they differ, the raw text was modified. This catches simple log falsification even if the attacker doesn't touch the hash field.

**Level 2 — Merkle root:** Recompute the Merkle root from all stored `hash` fields and compare it against a published root. If they differ, either the hash fields themselves were modified, or entries were added, removed or reordered. This catches a sophisticated attacker who also updates the per-entry `hash` field.

**Level 2 is only worth anything if the root comes from outside the data directory.** Compared against the root in the journal's own `logchain.state`, it proves the two files agree and nothing more — whoever can rewrite one can rewrite the other. Pass `--root <published hex>` to `logchain verify` (or to the reference verifier) with a root held by someone who cannot write here. The CLI warns when you don't.

The combination means: modifying only `raw` is caught by level 1. Modifying `raw` + `hash` is caught by level 2. Either way, the falsification is detected.

---

## CLI commands

```
logchain [--data-dir PATH] <COMMAND>

Commands:
  tail <file> [--interval-ms N] [--once]   Ingest a log file (live or batch)
  verify [--root HEX]                       Check integrity, ideally against a published root
  export                                    Print committed JSON snapshot to stdout
  prove <seq>                               Print a Merkle inclusion proof for one entry
  status                                    Show entry count and current root
```

**`tail`** — reads a log file and appends any new lines to the journal. With `--once`, reads the whole file and exits. Without `--once`, polls for new lines every `--interval-ms` milliseconds (default 500).

**`verify`** — runs the full two-level check. Exits 0 if clean, 2 if tampered.

**Pass `--root` with a root held somewhere you cannot write.** Without it, `verify`
compares the journal against the `merkle_root` in its own `logchain.state`, which proves
only that the two files agree — anyone able to edit one can edit the other. The command
prints a warning to stderr when run without `--root`, and step 3 of the walkthrough below
shows a falsified journal that passes the default check and fails the `--root` one.

**What verification does and does not localise.** Detection is guaranteed; attribution is
deliberately limited, and the tool does not guess beyond what the data supports.

| finding | what it pins down | what it cannot say |
|---|---|---|
| `EntryHashMismatch` | the exact `seq` whose `raw` and `hash` disagree | **which of the two was edited.** `SHA-256(raw) != hash` is symmetric — editing the text and editing the stored hash produce an identical signature, and nothing in the journal distinguishes them |
| `RootMismatch` | that the journal as a whole no longer matches the stored root | **any single entry.** Every entry is self-consistent, so the cause is a state-file edit or whole entries added, dropped or reordered. It carries no `seq` because attributing it to one would be fabricated |
| `SeqMismatch` | the exact position whose `seq` is out of order | — |
| `LegacyV1Journal` | that this is a format version 1 journal, not a tampered version 2 one | anything about its integrity — v1 roots are not comparable with v2 roots, so it is rejected rather than checked |

Localising a `RootMismatch` any further would need an independent record of the expected
entry set. A journal plus its own state file cannot provide that — which is the argument for
archiving the root somewhere the attacker does not control, and for passing it back with
`--root`.

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
- `ingested_at`: when logchain ingested the line (not the log's own timestamp). **Not covered by any hash** — do not treat it as a trusted timestamp
- `hash`: the leaf hash `SHA-256(0x00 || raw)`, hex-encoded lowercase
- `raw`: the original log line, verbatim

**`logchain.state`** — JSON object with the current Merkle root:
```json
{
  "format_version": 2,
  "merkle_root": "b07c68b5b3d4...",
  "entry_count": 7,
  "last_updated": "2026-09-07T06:43:58Z"
}
```

`format_version` is checked before anything else. A version 1 file (no such field) is
rejected with an explanation rather than misreported as tampered — v1 and v2 roots over
the same lines are different values and neither verifies against the other.

The full byte-level specification, precise enough to write a third verifier from, is
[`docs/FORMAT.md`](docs/FORMAT.md).

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
[`docs/FORMAT.md`](docs/FORMAT.md): single file, Python 3 standard library only, no
dependencies, and it imports nothing from this crate and shells out to nothing. If you do
not trust the Rust binary — and you should not have to — this is the one to run.
`docs/FORMAT.md` is precise enough to write a third.

```
examples/audit-log/
  access.log               the 7 source log lines
  logchain.journal         the journal built from them
  logchain.state           the writer's own record of the root
  published-root.txt       the root, as it would be archived off-box
  proof-seq-3.json         an inclusion proof for entry 3
  tampered-entry/          one log line edited, its hash left alone
  tampered-root/           one line edited, its hash AND the state root rewritten to match
  forged-duplicate/        the version 1 forgery, kept as a fixture (see step 5)
```

Set up (any shell; the reference verifier needs no build):

```bash
cd examples/audit-log
ROOT=$(grep merkle_root published-root.txt | cut -d= -f2)
V="python ../../reference/verify_journal.py"
```

### 1. The clean journal passes

```console
$ $V --journal logchain.journal --root $ROOT
entries checked:  7
stored root:      b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
recomputed root:  b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
INTEGRITY OK
$ echo $?
0
```

The verifier recomputed all seven leaf hashes from the `raw` text and rebuilt the tree, and
landed on the same root that was published. Nothing was taken on trust from the state file.

The Rust CLI does the same thing against the same external root:

```console
$ cargo run -q -- --data-dir . verify --root $ROOT
  Entries checked:  7
  Stored root:      b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
  Recomputed root:  b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
  ✓ INTEGRITY OK — no tampering detected
```

**The root is reproducible from `access.log` alone.** Ingest it into a fresh directory and
you get the same root, even though every `ingested_at` timestamp will differ, because
`ingested_at` is not part of any hash:

```console
$ cargo run -q -- --data-dir /tmp/fresh tail access.log --once
$ grep merkle_root /tmp/fresh/logchain.state
  "merkle_root": "b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436",
```

### 2. The tampered copy fails, and names the entry

`tampered-entry/` has one line rewritten to hide the size of a bulk export —
`12,480 rows` became `12 rows` — with the stored hash left untouched. Level 1 catches it:

```console
$ $V --journal tampered-entry/logchain.journal --root $ROOT
entries checked:  7
stored root:      b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
recomputed root:  b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
  EntryHashMismatch seq=3 stored=475b455e0ddd47021e8cc343533a75645982ad36f3d8d1e3087d5e673845f4b1 recomputed=bf584b7249eae951c604e6a671c3514821a6016154e232c62dce3f0922fab847
INTEGRITY VIOLATION
$ echo $?
2
```

Note the root still matches: it is built from the stored `hash` fields, which were not
touched. The finding names `seq=3` but does not claim to know whether `raw` or `hash` was
the side that moved — that check is symmetric and nothing in the journal distinguishes them.

### 3. Why the published root has to be held by someone else

`tampered-root/` is the same edit made competently: the line, its `hash`, **and** the root in
`logchain.state` were all rewritten to agree. Checked against its own state file — the
default, and what the CLI does with no `--root` — it is clean:

```console
$ cargo run -q -- --data-dir tampered-root verify
  Entries checked:  7
  Stored root:      f762c11319b352da891641965f3fa5568566921d2c28fb6bc12fa47e0d7f58b9
  Recomputed root:  f762c11319b352da891641965f3fa5568566921d2c28fb6bc12fa47e0d7f58b9
  ✓ INTEGRITY OK — no tampering detected

note: checked against this journal's own state file, which whoever can
      write the journal can also rewrite. For evidence against them,
      re-run with --root <the externally published root>.
```

Supply the root from outside and the falsification surfaces immediately:

```console
$ cargo run -q -- --data-dir tampered-root verify --root $ROOT
  Entries checked:  7
  Stored root:      b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
  Recomputed root:  f762c11319b352da891641965f3fa5568566921d2c28fb6bc12fa47e0d7f58b9
  ✗ Merkle root MISMATCH — tree has been altered
    TAMPERED stored Merkle root does not match the journal
  ✗ INTEGRITY VIOLATION — journal has been tampered with
$ echo $?
2
```

The reference verifier agrees, from a separate implementation:

```console
$ $V --journal tampered-root/logchain.journal --root $ROOT
  RootMismatch
INTEGRITY VIOLATION
```

That contrast is the whole argument of [`docs/LIMITS.md`](docs/LIMITS.md). A self-held root
catches accidents. It does not catch the operator.

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
$ $V --proof proof-seq-3.json --root f762c11319b352da891641965f3fa5568566921d2c28fb6bc12fa47e0d7f58b9
INCLUSION PROOF INVALID seq=3
```

### 5. The version 1 forgery, kept as a fixture

`forged-duplicate/` has **eight** entries — the seventh, duplicated and renumbered so its
`seq` still matches its position. **Under format version 1 this verified completely clean
against the seven-entry root**, because the odd-node rule paired the last leaf with itself
and the two trees computed byte-identical roots. No check fired. That is CVE-2012-2459.

Under version 2 it fails:

```console
$ $V --journal forged-duplicate/logchain.journal --root $ROOT
entries checked:  8
stored root:      b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
recomputed root:  e6a423a5133478ca8b799846a2e299670bc0c9203332737113f56bb73682bc1d
  RootMismatch
INTEGRITY VIOLATION
$ echo $?
2
```

Nothing out of band was needed to catch it — no published entry count, no side channel. The
root itself now commits to how many entries there are, which is exactly what version 1 could
not do. The fixture stays in the repository as a regression test
(`duplicated_last_entry_no_longer_collides_with_the_genuine_root`) so the defect cannot
return unnoticed. Full account in [`docs/LIMITS.md`](docs/LIMITS.md).

---

## Two implementations, checked against each other

`tests/cross_language.rs` runs the Rust verifier and the Python reference verifier over the
same on-disk fixtures — clean journals, every odd leaf count from 3 to 9, each tampered
case the existing Rust tests build, a deletion, a version 1 journal, and the duplication
forgery — and fails unless they agree on **all** of: the recomputed root, the entry count,
the root-match verdict, the clean verdict, and the ordered list of findings with their
field values.

Agreement on the clean cases alone would prove little. The value is that they agree on the
corrupted ones: the same `EntryHashMismatch` on the same `seq` with the same two hex digests,
the same lone `RootMismatch` where the format says a finding must not be attributed to any
entry.

The harness was checked for teeth by breaking the Python verifier five ways and confirming
the tests fail:

| deliberate mutation | tests failed |
|---|---|
| split at `n/2` instead of the largest power of two below `n` | 4 of 12 — every fixture whose leaf count is not a power of two |
| `RootMismatch` reported without the suppression rule | 1 of 12 — the one fixture where a root difference and an entry finding coexist |
| node operands swapped (`right ‖ left`) | 9 of 12 — everything except the empty and single-entry journals, which never build a node |
| node prefix changed from `0x01` to `0x00` (domain separation removed) | 9 of 12 |
| leaf prefix dropped entirely (silently reverting to the v1 leaf rule) | 9 of 12 |

The last two matter because they are the version 2 change itself: if either prefix were
wrong, or dropped, the harness says so.

**One thing the harness cannot do, stated plainly.** Both implementations agreed on the
version 1 root collision — they computed the same wrong answer, so cross-checking them
against each other would never have found it. It was found by writing
[`docs/FORMAT.md`](docs/FORMAT.md) and having to state exactly which bytes are hashed at
every level. Two implementations agreeing is evidence they implement the same specification.
It is not evidence the specification is right.

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
        stored hash:     64b00251d36c041b81c1717e519d96049dc7055e16fc3c77d14ba85a07a9ba73
        recomputed hash: b82cefa3eaa7b8d58fac9fbd705bd44e883fe5a2ef41f1648d5f05f5fd31dec8
        (cannot tell which side was edited - the check is symmetric)

  ✗ INTEGRITY VIOLATION — journal has been tampered with
```

---

## Tests

```
cargo test
```

**64 tests total:**
- `src/hasher.rs` — 7 unit tests (known SHA-256 values, the `0x00`/`0x01` prefix vectors, **leaf and node domains proven disjoint**, determinism, order sensitivity, hex round-trip)
- `src/merkle.rs` — 21 unit tests (the split-point rule, root construction for 0–7 leaves, every proof of every shape from 1 to 33 leaves, logarithmic proof length, all-leaf tamper coverage, cross-tree proof rejection, and the two tests that pin format version 2's reason for existing — see below)
- `src/journal.rs` — 7 unit tests (append, sequential seqs, hash correctness, state update, state persistence, empty journal, incremental ingest)
- `src/verify.rs` — 7 unit tests (clean, empty, entry-hash mismatch detection, hash-field tamper detection, single entry, count + root match)
- `tests/integration.rs` — 10 end-to-end tests (ingest→verify clean, incremental ingest, raw-tamper caught, hash-tamper caught, **state-root tamper caught and not blamed on an entry**, export count/root, export hash correctness, root changes after tamper, empty clean, single-entry round-trip)
- `tests/cross_language.rs` — 12 cross-implementation tests. Each builds a fixture on disk,
  runs **both** the Rust verifier and `reference/verify_journal.py`, and fails unless they
  agree on the recomputed root, entry count, root-match verdict, clean verdict and the ordered
  findings. Covers clean journals, every odd leaf count from 3 to 9, all the tamper cases the
  other tests use, a deletion, a version 1 journal, Rust-generated inclusion proofs checked by
  the Python verifier, and the duplication forgery that version 1 could not catch.

**The two tests that carry format version 2:**
`merkle::appending_a_duplicate_of_the_last_entry_changes_the_root` checks every leaf count
from 1 to 64, and `merkle::domain_separation_alone_would_not_have_fixed_the_v1_collision`
reconstructs version 1's tree shape *with* version 2's prefixes and shows the collision
surviving untouched — the demonstration that the `0x00`/`0x01` tags alone were not the fix,
and that the tree-shape change was required.

Sixteen of these are the ones that matter: they write a real journal or proof, corrupt it on
disk, and assert the specific failure (2 in `verify.rs`, 4 in `integration.rs`, 8 in
`cross_language.rs`, plus the two collision tests above). A tamper-evidence claim that is
only tested on the happy path is not evidence of anything — and one that is only checked by
the binary that wrote the file is not independent of it.

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
  journal.rs   — on-disk storage (JournalEntry, LogchainState, append_entry, ingest_file)
  verify.rs    — integrity checking (check_journal, two-level tamper detection)
  hasher.rs    — SHA-256 primitives (hash_leaf/hash_node with the RFC 6962 prefixes)
  merkle.rs    — RFC 6962 Merkle tree (compute_root, generate_proof, verify_proof)
  report.rs    — terminal output, JSON export snapshot, inclusion proof files
  main.rs      — clap v4 CLI (tail, verify [--root], export, prove, status)
reference/
  verify_journal.py — SECOND implementation: independent verifier, Python stdlib only
docs/
  FORMAT.md    — the on-disk format and verification procedure, byte level
  LIMITS.md    — what this proves and what it does not
examples/
  audit-log/   — runnable worked example: clean journal, published root, inclusion
                 proof, two tampered copies, and the version 1 forgery fixture
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

**No unsafe code. No hand-rolled cryptography.** SHA-256 comes from the `sha2` crate (RustCrypto project). The Merkle tree structure is hand-implemented — it's simple enough to fit in one file and important enough to understand every line. The construction follows RFC 6962 rather than being invented here, which is what version 1 got wrong.
