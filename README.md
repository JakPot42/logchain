# logchain

A tamper-evident journal for log files, in Rust. Each line is hashed with SHA-256 and placed in an
RFC 6962 Merkle tree. An edited line no longer matches its stored hash, and a rewrite that also
changes the stored hashes no longer matches a root published somewhere the editor cannot write.

**Format version 2 · Rust · command-line tool · 64 tests**

A second verifier in Python ([`reference/verify_journal.py`](reference/verify_journal.py),
standard library only) implements the format from [`docs/FORMAT.md`](docs/FORMAT.md) without
touching this crate, and `cargo test` runs the two against each other. What this does and does
not prove: [`docs/LIMITS.md`](docs/LIMITS.md).

---

## What problem does this solve?

Anyone with write access to a log file can change a line, and nothing in the file shows it.

logchain records each line in a journal together with its hash, and keeps a Merkle root over
all the hashes. `logchain verify` recomputes both. An edited line no longer matches its stored
hash. A changed, added, removed or reordered hash no longer matches the root.

**Detectable by whom, and under what assumption, is the whole question.** A root kept next to the
journal it commits to is only evidence against someone who cannot edit both. That assumption, and
everything it excludes, is stated in [`docs/LIMITS.md`](docs/LIMITS.md). Read it before relying on this.

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

**Why this matters:** if `h2` changes, `N23` changes, and so does `root`. Every ancestor of a
changed leaf hash changes, so a root computed after the change no longer matches one computed
before it (`any_change_to_any_leaf_changes_root`).

**Domain separation (`0x00` / `0x01`).** Leaves and internal nodes are hashed with different
prefixes, so the same bytes hash differently as a leaf and as a node. A log line made of two
32-byte child hashes does not hash to the node over those children
(`leaf_and_node_domains_are_disjoint` checks this case).

**Uneven counts: split at the largest power of two.** When the leaf count `n` is not a
power of two, the list is split into the first `k` leaves and the rest, where `k` is the
largest power of two below `n`. Seven leaves split 4 and 3; three leaves split 2 and 1, and
the lone leaf is carried up unchanged. **No node is ever its own sibling**, so the tree's
shape is determined entirely by `n`. `appending_a_duplicate_of_the_last_entry_changes_the_root`
checks every leaf count from 1 to 64.

> **Version 1 did this differently and had a root collision.** It paired adjacent nodes
> and duplicated the last node on an odd level, which let a journal gain a duplicate
> final entry without changing its root. This is the defect known as CVE-2012-2459. It was
> found while writing [`docs/FORMAT.md`](docs/FORMAT.md), not by a test. Version 2 is a clean
> break: version 1 roots are void, and version 1 journals are detected and rejected rather
> than misread. The forgery is kept as a runnable fixture (step 5 below). Domain separation
> alone would *not* have fixed it; only the change to the tree's shape did
> (`domain_separation_alone_would_not_have_fixed_the_v1_collision`). The full account is in
> [`docs/LIMITS.md`](docs/LIMITS.md).

**Why not hash the lines concatenated?** `SHA-256("ab" || "c") == SHA-256("a" || "bc")`:
one hash over the concatenated lines cannot tell where one entry ends and the next begins, so
an editor could split or merge entries without changing it. logchain hashes each line as its
own leaf, and each internal node over two 32-byte child hashes, so moving a boundary between
entries changes their leaf hashes.

**Order sensitivity:** `NODE(h0, h1) != NODE(h1, h0)` (`hash_node_is_order_sensitive`).
Reordering two entries changes the internal nodes above them, up to the root (`order_matters`).
Unless the `seq` fields are renumbered as well, it also shows up as a `SeqMismatch`.

---

## Two-level tamper detection

`logchain verify` checks at two levels.

**Level 1, per entry:** recompute `SHA-256(0x00 || raw)` for each entry and compare it with the
stored `hash` field. If they differ, the entry was edited. This catches an edit to the text that
leaves the `hash` field alone.

**Level 2, Merkle root:** recompute the Merkle root from the stored `hash` fields and compare it
with a root: the one in `logchain.state`, or one passed with `--root`. If they differ, a `hash`
field was changed, entries were added, removed or reordered, or the stored root itself was
changed.

**Level 2 is only worth anything if the root comes from outside the data directory.** Compared
against the root in the journal's own `logchain.state`, it proves the two files agree and nothing
more: whoever can rewrite one can rewrite the other. Pass `--root <published hex>` to
`logchain verify` (or to the reference verifier) with a root held by someone who cannot write
here. The CLI prints a note when you don't.

Together: editing only `raw` is caught by level 1. Editing `raw` and `hash` is caught by level 2.
Editing `raw`, `hash` and the root in `logchain.state` is caught only against a root held
elsewhere (step 3 below).

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

**`tail`** reads a log file and appends any new lines to the journal. With `--once` it reads the
whole file and exits; without it, it polls for new lines every `--interval-ms` milliseconds
(default 500).

**`verify`** runs both levels. It exits 0 if the journal is clean, 2 if it is not, and 1 if it
cannot read the journal.

**Pass `--root` with a root held somewhere you cannot write.** Without it, `verify`
compares the journal against the `merkle_root` in its own `logchain.state`, which proves
only that the two files agree; anyone able to edit one can edit the other. The command
prints a note to stderr when run without `--root`, and step 3 of the walkthrough below
shows a falsified journal that passes the default check and fails the `--root` one.

**What each finding pins down.** A finding names only what the data supports.

| finding | what it pins down | what it cannot say |
|---|---|---|
| `EntryHashMismatch` | the exact `seq` whose `raw` and `hash` disagree | **which of the two was edited.** `SHA-256(raw) != hash` is symmetric: editing the text and editing the stored hash produce the same finding, and nothing in the journal distinguishes them |
| `RootMismatch` | that the journal as a whole no longer matches the root | **any single entry.** It is reported only when every entry is self-consistent, so the cause is an edited root, or whole entries added, dropped or reordered. It carries no `seq`, because no single entry is at fault in the data |
| `SeqMismatch` | the exact position whose `seq` is out of order | why it is out of order |
| `LegacyV1Journal` | that this is a format version 1 journal, not a tampered version 2 one | anything about its integrity. Version 1 roots are not comparable with version 2 roots, so it is rejected rather than checked |

Localising a `RootMismatch` any further would need an independent record of the expected
entry set. A journal plus its own state file cannot provide that, which is the argument for
archiving the root somewhere the editor does not control and passing it back with `--root`.

**`export`** prints a JSON snapshot with the Merkle root, the entry count and the ordered
list of per-entry hashes. Archive it somewhere the journal's owner cannot write; its root is
the one to pass back with `--root`.

**`prove`** prints the inclusion proof for one entry as JSON, in the format documented in
[`docs/FORMAT.md`](docs/FORMAT.md) §9. Anyone holding the published root can check it without the journal.

**`status`** prints the format version, the entry count, the current root and the time of the
last update.

---

## Storage format

Two files in the data directory (default `./logchain-data/`):

**`logchain.journal`**: newline-delimited JSON, one entry per line:
```json
{"seq":0,"ingested_at":"2026-06-30T08:00:00Z","hash":"60f80b...","raw":"2026-06-30 INFO service started"}
```

- `seq`: zero-based index; an out-of-order `seq` is reported as a `SeqMismatch`
- `ingested_at`: when logchain ingested the line, not the log's own timestamp. **Not covered by any hash**: do not treat it as a trusted timestamp
- `hash`: the leaf hash `SHA-256(0x00 || raw)`, hex-encoded lowercase
- `raw`: the original log line, verbatim

**`logchain.state`**: a JSON object with the current Merkle root:
```json
{
  "format_version": 2,
  "merkle_root": "b07c68b5b3d4...",
  "entry_count": 7,
  "last_updated": "2026-09-07T06:43:58Z"
}
```

A version 1 file (no `format_version` field) is rejected with an explanation rather than
reported as tampered: version 1 and version 2 roots over the same lines are different values,
and neither verifies against the other.

The full byte-level specification, precise enough to write a third verifier from, is
[`docs/FORMAT.md`](docs/FORMAT.md).

---

## Merkle inclusion proofs

The library (`src/merkle.rs`) also implements Merkle inclusion proofs. Given a leaf index, `generate_proof()` returns an `O(log n)` list of sibling hashes that lets any holder of the root verify that a specific entry was present when the root was computed, without the full journal.

```rust
let proof = generate_proof(&leaves, index).unwrap();
assert!(verify_proof(leaves[index], &proof, root));
```

---

## Check it yourself, without running our binary

Everything above is a claim about a format. `examples/audit-log/` is that claim as files you
can run, using a verifier that shares no code with the tool that wrote them.

`reference/verify_journal.py` is a second, independent implementation of the format in
[`docs/FORMAT.md`](docs/FORMAT.md): a single file, Python 3 standard library only, no
dependencies. It imports nothing from this crate and shells out to nothing. If you do
not trust the Rust binary, and you should not have to, this is the one to run.

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

The verifier recomputed all seven leaf hashes from the `raw` text and compared each with its
stored hash, then rebuilt the tree from the stored hashes and arrived at the published root. It
read no root from the state file.

The Rust CLI, run from the same directory as `cargo run -q -- --data-dir . verify --root $ROOT`,
reports the same two roots and exits 0.

**The root is reproducible from `access.log` alone.** Ingest it into a fresh directory and
you get the same root, even though every `ingested_at` timestamp will differ, because
`ingested_at` is not part of any hash:

```console
$ cargo run -q -- --data-dir /tmp/fresh tail access.log --once
$ grep merkle_root /tmp/fresh/logchain.state
  "merkle_root": "b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436",
```

### 2. The tampered copy fails, and names the entry

`tampered-entry/` has one line rewritten to hide the size of a bulk export
(`12,480 rows` became `12 rows`), with the stored hash left untouched. Level 1 catches it:

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

Note the root still matches: the tree is built from the stored `hash` fields, which were not
touched. The finding names `seq=3` but does not claim to know whether `raw` or `hash` was
the side that moved; that check is symmetric and nothing in the journal distinguishes them.

### 3. Why the published root has to be held by someone else

`tampered-root/` is the same edit made competently: the line, its `hash`, **and** the root in
`logchain.state` were all rewritten to agree. Checked against its own state file, it is clean:

```console
$ $V --journal tampered-root/logchain.journal --state tampered-root/logchain.state
entries checked:  7
stored root:      f762c11319b352da891641965f3fa5568566921d2c28fb6bc12fa47e0d7f58b9
recomputed root:  f762c11319b352da891641965f3fa5568566921d2c28fb6bc12fa47e0d7f58b9
INTEGRITY OK
$ echo $?
0
```

`logchain verify` with no `--root` makes the same check: it exits 0 and prints this note to
stderr:

```
note: checked against this journal's own state file, which whoever can
      write the journal can also rewrite. For evidence against them,
      re-run with --root <the externally published root>.
```

Supply the root from outside and the falsification surfaces:

```console
$ $V --journal tampered-root/logchain.journal --root $ROOT
entries checked:  7
stored root:      b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436
recomputed root:  f762c11319b352da891641965f3fa5568566921d2c28fb6bc12fa47e0d7f58b9
  RootMismatch
INTEGRITY VIOLATION
$ echo $?
2
```

`logchain verify --root $ROOT` reports the same mismatch and exits 2.

That contrast is the whole argument of [`docs/LIMITS.md`](docs/LIMITS.md). A root kept beside
the journal catches an edit by someone who cannot also rewrite `logchain.state`. It does not
catch the operator.

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

`forged-duplicate/` has **eight** entries: the seventh, duplicated and renumbered so its
`seq` still matches its position. **Under format version 1 this verified clean against the
seven-entry root**, because the odd-node rule paired the last leaf with itself and the two
trees computed identical roots. No check fired. That is CVE-2012-2459.

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

Nothing out of band was needed to catch it: no published entry count, no side channel. The
root itself now commits to how many entries there are, which is what version 1 could not do.
The fixture stays in the repository as a regression test
(`duplicated_last_entry_no_longer_collides_with_the_genuine_root`).

---

## Two implementations, checked against each other

`tests/cross_language.rs` runs the Rust verifier and the Python reference verifier over the
same on-disk fixtures: clean journals of 0, 1, 3, 5, 7 and 9 entries, an edited line, an edited
hash, an edited state root, a consistent rewrite of one entry, a deletion, a version 1 journal,
and the duplication forgery. Each test fails unless the two agree on all of: the recomputed
root, the entry count, the root-match verdict, the clean verdict, and the ordered list of
findings with their field values. A twelfth test has the Python verifier check inclusion proofs
generated by the Rust code.

Agreement on the clean cases alone would prove little. The value is that they agree on the
corrupted ones: the same `EntryHashMismatch` on the same `seq` with the same two hex digests,
the same lone `RootMismatch` where the format says a finding must not be attributed to any
entry.

The harness was checked for teeth by breaking the Python verifier five ways by hand and
confirming the tests fail. This was a manual check, not part of `cargo test`; repeating it
means editing the verifier the same way.

| deliberate mutation | tests failed |
|---|---|
| split at `n/2` instead of the largest power of two below `n` | 4 of 12: every fixture whose leaf count is not a power of two |
| `RootMismatch` reported without the suppression rule | 1 of 12: the one fixture where a root difference and an entry finding coexist |
| node operands swapped (`right ‖ left`) | 9 of 12: everything except the empty and single-entry journals, which never build a node |
| node prefix changed from `0x01` to `0x00` (domain separation removed) | 9 of 12 |
| leaf prefix dropped entirely (silently reverting to the v1 leaf rule) | 9 of 12 |

The last two matter because they are the version 2 change itself: if either prefix were
wrong, or dropped, the harness says so.

**One thing the harness cannot do, stated plainly.** Both implementations agreed on the
version 1 root collision: they computed the same wrong answer, so cross-checking them
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
3. Shows the journal's status
4. Verifies it clean
5. Exports a snapshot of the root and the entry hashes
6. Edits one historical entry, `seq=7`, in the journal
7. Verifies again

At step 7, `verify` reports that the Merkle root still matches and that one entry, `seq=7`,
has a line and a stored hash that disagree. It prints both hashes, says it cannot tell which
side was edited, and exits 2.

---

## Tests

```
cargo test
```

**64 tests:**
- `src/hasher.rs`: 7 unit tests (known SHA-256 values, the `0x00`/`0x01` prefix values, a leaf and a node over the same bytes hashing differently, determinism, order sensitivity, hex round trip)
- `src/merkle.rs`: 21 unit tests (the split-point rule; roots for 0, 1, 2, 3, 4, 5 and 7 leaves, and a four-leaf root computed by hand; any changed leaf changes the root; order matters; the same leaves give the same root; every proof for every tree size from 1 to 33 leaves verifies; proof length is logarithmic; a single-leaf proof is empty; invalid proofs, wrong roots, proofs from another tree and out-of-range indexes are rejected; and the two tests below)
- `src/journal.rs`: 7 unit tests (append and read back, sequential `seq` values, stored hash matches the line, state updated after an append, state round trip through the file, empty journal, incremental ingest skips lines already seen)
- `src/verify.rs`: 7 unit tests (clean journal, empty journal, edited line detected, edited hash detected, single entry, entry count, roots match on a clean journal)
- `tests/integration.rs`: 10 end-to-end tests (ingest then verify clean, incremental ingest, edited line caught, edited hash caught, **edited state root caught and not blamed on an entry**, export count and root, export hashes, root changes after an edit, empty journal clean, single-entry round trip)
- `tests/cross_language.rs`: 12 cross-implementation tests, described in the section above.

**The two tests that carry format version 2:**
`merkle::appending_a_duplicate_of_the_last_entry_changes_the_root` checks every leaf count
from 1 to 64, and `merkle::domain_separation_alone_would_not_have_fixed_the_v1_collision`
rebuilds version 1's tree shape *with* version 2's prefixes and shows the collision
surviving. The `0x00`/`0x01` prefixes alone were not the fix; the change to the tree's shape was.

The tests that matter most write a real journal or proof, corrupt it on disk, and assert the
specific failure. A tamper-evidence claim that is only tested on the happy path is not evidence
of anything, and one that is only checked by the binary that wrote the file is not independent
of it.

The cross-language tests need a Python 3 interpreter on `PATH`. They fail rather than skip if
one is missing, because a silently skipped cross-implementation test would leave the central
claim of this repository unchecked.

---

## What tamper-evidence does not cover

logchain shows that entries in the journal were not altered after they were written. It
shows nothing about entries that were never written, and nothing about an entry that was
written accurately but left something out. A well-formed log line committed to the Merkle tree
verifies exactly the same whether or not it tells the whole story, because the commitment is
over the bytes it was given.

It also shows nothing about *who* wrote an entry or *when*. There is no signature anywhere in
this project, and `ingested_at` sits outside the leaf hash.

That gap is not an unfinished feature here. Testing whether a record is *complete* requires
starting from an independent population the operator does not control, which is a different
kind of work from hashing.

[`docs/LIMITS.md`](docs/LIMITS.md) is the short, full version of this section, including the
custody assumption the whole scheme rests on and the defect in format version 1.

An essay on this boundary,
[You cannot prove nothing was hidden](https://github.com/JakPot42/filing-check/blob/master/docs/you-cannot-prove-nothing-was-hidden.md),
is in the `filing-check` repository.

---

## Architecture

```
src/
  lib.rs       module declarations
  journal.rs   on-disk storage (JournalEntry, LogchainState, append_entry, ingest_file)
  verify.rs    integrity checking (check_journal, two-level tamper detection)
  hasher.rs    SHA-256 primitives (hash_leaf/hash_node with the RFC 6962 prefixes)
  merkle.rs    RFC 6962 Merkle tree (compute_root, generate_proof, verify_proof)
  report.rs    terminal output, JSON export snapshot, inclusion proof files
  main.rs      clap v4 CLI (tail, verify [--root], export, prove, status)
reference/
  verify_journal.py   SECOND implementation: independent verifier, Python stdlib only
docs/
  FORMAT.md    the on-disk format and verification procedure, byte level
  LIMITS.md    what this proves and what it does not
examples/
  audit-log/   runnable worked example: clean journal, published root, inclusion
               proof, two tampered copies, and the version 1 forgery fixture
tests/
  integration.rs      end-to-end pipeline tests
  cross_language.rs   Rust verifier vs Python verifier, same fixtures, must agree
demo/
  generate_log.py     generates a 20-entry sample.log
  tamper_demo.ps1     runs the demo sequence
```

**`reference/verify_journal.py` deliberately shares nothing with `src/`.** No imports beyond the
Python standard library, no subprocess calls, no generated code. It was written from
`docs/FORMAT.md`. That independence is the only thing that makes the agreement between them
meaningful.

**Crate layout:** `[lib]` + `[[bin]]`, so the integration tests use the library without going
through the binary.

**No unsafe code. No hand-rolled cryptography.** SHA-256 comes from the `sha2` crate (RustCrypto
project). The Merkle tree is implemented here, in one file, `src/merkle.rs`. The construction
follows RFC 6962 rather than being invented here, which is what version 1 got wrong.
