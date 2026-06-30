# logchain — Secure Log Aggregator with Merkle Integrity

Tamper-evident audit trail for log files. Each log entry is SHA-256 hashed on ingestion and incorporated into a Merkle tree — any retroactive modification to any historical entry is cryptographically detectable, without a blockchain or external service.

**47 tests · Rust · CLI · No external dependencies at runtime**

---

## What problem does this solve?

Log files are the ground truth for audits, incident response, and compliance. They're also easy to falsify: an attacker with filesystem access can edit a log line and nothing in the system will notice.

logchain makes that impossible to hide. Every entry is committed to a Merkle tree, and the root is stored alongside the journal. Change any byte in any historical entry — the root no longer matches.

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
  export                                    Print signed JSON snapshot to stdout
  status                                    Show entry count and current root
```

**`tail`** — reads a log file and appends any new lines to the journal. With `--once`, reads the whole file and exits. Without `--once`, polls for new lines every `--interval-ms` milliseconds (default 500).

**`verify`** — runs the full two-level check. Exits 0 if clean, 2 if tampered.

**`export`** — prints a JSON snapshot containing the Merkle root and the full ordered list of per-entry hashes. Archive this externally so a local root-modification attack is also detectable.

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
4. Exports a signed snapshot
5. Surgically modifies one historical entry in the journal
6. Re-verifies — logchain catches exactly the tampered entry

Expected output at step 7:
```
  ✓ Merkle root matches
  ✗ 1 tampered entry

    TAMPERED seq=7: raw content modified
        stored hash:     4fbbcd19...
        recomputed hash: 2bc19fdb...

  ✗ INTEGRITY VIOLATION — journal has been tampered with
```

---

## Tests

```
cargo test
```

**47 tests total:**
- `src/hasher.rs` — 5 unit tests (known SHA-256 values, determinism, order sensitivity, hex round-trip)
- `src/merkle.rs` — 25 unit tests (root construction for 0–5 leaves, duplication rule, all-leaf tamper coverage, 7 proof tests, manual computation verification)
- `src/journal.rs` — 7 unit tests (append, sequential seqs, hash correctness, state update, state persistence, empty journal, incremental ingest)
- `src/verify.rs` — 6 unit tests (clean, empty, raw-tamper detection, hash-tamper detection, single entry, count + root match)
- `tests/integration.rs` — 9 end-to-end tests (ingest→verify clean, incremental ingest, raw-tamper caught, hash-tamper caught, export count/root, export hash correctness, root changes after tamper, empty clean, single-entry round-trip)

---

## Connection to portfolio themes

This project connects two threads running through the broader portfolio:

**Harvest Horizon (P32)** explored post-quantum cryptographic migration — the "harvest now, decrypt later" threat. logchain addresses a different but related problem: *retroactive log falsification*. Both are about cryptographic commitments: Harvest Horizon asks "are today's encryption choices secure against tomorrow's adversary?", logchain asks "can yesterday's log entries be trusted today?". Both come down to the same principle: a cryptographic commitment made at the right time and archived to an out-of-band location is unforgeable.

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
  report.rs    — terminal output and JSON export snapshot
  main.rs      — clap v4 CLI (tail, verify, export, status)
tests/
  integration.rs  — end-to-end pipeline tests
demo/
  generate_log.py   — generates 20-entry sample.log
  tamper_demo.ps1   — orchestrates the full demo sequence
```

**Crate pattern:** `[lib]` + `[[bin]]` — the library is importable in integration tests without going through the binary. Same pattern as P56 (pcap-anomaly) and P57 (bin-intel).

**No unsafe code. No hand-rolled cryptography.** SHA-256 comes from the `sha2` crate (RustCrypto project). The Merkle tree structure is hand-implemented — it's simple enough to fit in one file and important enough to understand every line.
