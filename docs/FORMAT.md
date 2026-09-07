# logchain journal format, version 1

This document defines the on-disk format and the verification procedure completely
enough to write an independent verifier without reading any logchain source code.

There are two implementations of this spec in this repository, and they are checked
against each other on every test run:

- `src/` — Rust, the writer and the primary verifier
- `reference/verify_journal.py` — Python 3, standard library only, verifier only

`tests/cross_language.rs` runs both over the same fixtures and fails if any finding,
root, or verdict differs. If a third implementation disagrees with this document, the
document is what is wrong.

Keywords **MUST**, **MUST NOT**, **SHOULD** and **MAY** are used in the RFC 2119 sense.

---

## 1. Files

A logchain data directory contains exactly two files:

| file | contents |
|---|---|
| `logchain.journal` | the ordered entries, newline-delimited JSON |
| `logchain.state` | a single JSON object holding the current Merkle root |

The journal is append-only in normal operation. Nothing in the format enforces that;
enforcement is what the Merkle root is for.

---

## 2. `logchain.journal`

Newline-delimited JSON (JSON Lines). Rules:

- The file **MUST** be UTF-8. No byte-order mark.
- Each non-blank line **MUST** be exactly one JSON object, on one line.
- Lines are terminated by `\n`. A reader **MUST** tolerate `\r\n` by stripping the
  trailing `\r` before parsing.
- Blank lines (empty, or only whitespace) **MUST** be skipped, not treated as entries.
- Entry order in the file **is** the order committed to the tree. Line *n* (counting
  non-blank lines from 0) is leaf *n*.

### 2.1 Entry object

Every entry object **MUST** have these four fields. Additional fields are not defined
by this version and a verifier **MUST** ignore them for hashing purposes.

| field | JSON type | meaning |
|---|---|---|
| `seq` | integer, `>= 0` | zero-based position of this entry. For an untampered journal, `seq` equals the entry's line index. |
| `ingested_at` | string | RFC 3339 timestamp of when logchain ingested the line. **Not** the timestamp inside the log line, and **not** an attestation of when the event happened. Not covered by any hash — see §7. |
| `hash` | string | `SHA-256(raw)`, hex-encoded, **lowercase**, exactly 64 characters. |
| `raw` | string | the original log line, verbatim, with its line terminator removed. |

Example line (wrapped here for reading; it is one line in the file):

```json
{"seq":0,"ingested_at":"2026-09-07T05:49:33.270121800+00:00",
 "hash":"aa568c3641d8ceb1b230328d1b4950acd8840001711af45fda6...",
 "raw":"2026-09-01T09:14:02Z INFO  auth: session opened for operator id=4471"}
```

---

## 3. The leaf hash: exactly which bytes are hashed

This is the part most likely to be got wrong, so it is stated exhaustively.

> **The leaf for entry *n* is `SHA-256(B)`, where `B` is the UTF-8 encoding of the
> *decoded* string value of that entry's `raw` field.**

"Decoded" means after JSON unescaping. If the file contains `"raw":"a\"b"`, the string
is `a"b` (3 characters) and `B` is the 3 bytes `61 22 62`. The escape sequence is not
hashed; the string it denotes is.

The following are **NOT** part of `B`:

- the trailing newline of the original log line (it is stripped before storage);
- any surrounding JSON quotes;
- any other field — `seq`, `ingested_at` and the `hash` field itself are **not** hashed;
- any length prefix, separator, salt, or domain-separation tag.

There is no domain separation between leaves and internal nodes in version 1. A leaf is
a plain `SHA-256` of the line's bytes; an internal node is a plain `SHA-256` of 64 bytes.
This is the Bitcoin-style construction and it carries the known consequence noted in §7.

### 3.1 Test vectors

`SHA-256` of the empty byte string, as a self-check that your hasher is wired up:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

For the three log lines `alpha`, `beta`, `gamma`:

```
h0 = SHA-256("alpha") = 8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8
h1 = SHA-256("beta")  = f44e64e75f3948e9f73f8dfa94721c4ce8cbb4f265c4790c702b2d41cfbf2753
h2 = SHA-256("gamma") = be9d587defa1f0c09ef49eb17e206983a5f8f8289e4281860bd0ee5a19592c67
```

---

## 4. The pair hash

An internal node is the `SHA-256` of the **concatenation of its two children's raw
32-byte digests** — the binary digests, not their hex strings:

```
node = SHA-256( left_digest_32_bytes || right_digest_32_bytes )
```

The input is always exactly 64 bytes. Nothing separates the halves.

**Order is significant.** `H(a || b)` is not `H(b || a)`. Swapping two adjacent log
entries changes every node above them, up to the root.

A common implementation error is to concatenate the 64-character hex *strings* and hash
those 128 ASCII bytes. That produces a different tree. Decode to bytes first.

---

## 5. Computing the root

Given the ordered list of leaf digests `L`:

1. If `L` is empty, the root is **null** (JSON `null` in the state file). Not the hash
   of the empty string, not a zero digest.
2. If `L` has exactly one element, the root **is that element**, unchanged. It is not
   hashed again, and it is not paired with itself.
3. Otherwise, repeat until one node remains:
   - Take the current level left to right in pairs.
   - **Odd-node convention:** if the level has an odd length, the final node is paired
     **with itself**. It is *not* promoted unchanged to the next level, and it is *not*
     paired with a zero digest or a copy of any other node.
   - The next level is the list of `SHA-256(left || right)` results, in order.

The rule in step 3 applies at **every level**, not only the leaf level. A 5-leaf tree
duplicates at the leaf level and again at the level above it.

In pseudocode:

```
function root(L):
    if L is empty:  return null
    if |L| == 1:    return L[0]
    while |L| > 1:
        next = []
        for i = 0; i < |L|; i += 2:
            left  = L[i]
            right = L[i+1] if i+1 < |L| else L[i]     # odd node paired with itself
            next.append(SHA256(left || right))
        L = next
    return L[0]
```

### 5.1 Worked example: three leaves

Using `h0`, `h1`, `h2` from §3.1:

```
level 0:  [h0, h1, h2]                    <- odd, so h2 pairs with itself
level 1:  [ H(h0||h1), H(h2||h2) ]
level 2:  [ H( H(h0||h1) || H(h2||h2) ) ] <- the root

H(h0||h1) = 8450e9a90d144185def662fffc477da5e0325d80be5de388ec20d9c58d6c72d0
H(h2||h2) = 8c84e4f2d27ecb9bd6db03cdff169c1a28cee1fab5973ff5eecebe149c8bda92
root      = 50298939464ed02cbf2b587250a55746b3422e133ac4f09b7e2b07869023bc9e
```

A third implementation that ingests the lines `alpha`, `beta`, `gamma` in that order
and does not produce `50298939…bc9e` has diverged from this spec.

---

## 6. `logchain.state`

A single JSON object:

```json
{
  "merkle_root": "11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15",
  "entry_count": 7,
  "last_updated": "2026-09-07T05:49:33.495881400+00:00"
}
```

| field | JSON type | meaning |
|---|---|---|
| `merkle_root` | string or `null` | lowercase hex root over all journal leaves, in journal order. `null` if and only if the journal has no entries. |
| `entry_count` | integer, `>= 0` | number of entries the writer believes are in the journal. |
| `last_updated` | string | RFC 3339 timestamp of the last write to this file. Informational only; nothing verifies it. |

**The state file is written by the same process that writes the journal, and carries no
authentication.** Anyone who can edit the journal can edit the state file to match. It
is a convenience cache of the root, not evidence. A verification that compares the
journal only against this file proves the two files are mutually consistent and nothing
more. See `docs/LIMITS.md`, and §8.2 below.

---

## 7. What the format does not cover

- **`ingested_at` is not committed to anything.** It sits outside the leaf hash, so it
  can be altered without affecting the root and without producing any finding. Do not
  treat it as a trusted timestamp. Establishing *when* a root existed needs an external
  timestamp authority (RFC 3161) or publication to an append-only log; this format has
  neither.
- **`seq` is not committed to the leaf hash either.** It is checked only against line
  position (§8.1, `SeqMismatch`). Ordering is committed structurally, by which leaf sits
  where in the tree, not by the `seq` field.
- **A root does not pin the entry count, and this is exploitable.** Because odd nodes are
  duplicated (§5) and leaves and internal nodes use the same unprefixed hash, two journals
  of *different lengths* can produce the *same* root. Concretely: appending a copy of the
  last entry to an odd-length journal leaves the root completely unchanged.

  A 7-leaf tree pairs its levels as `(0,1)(2,3)(4,5)(6,6)`. An 8-leaf journal whose 8th
  entry is a duplicate of the 7th pairs as `(0,1)(2,3)(4,5)(6,7)` — and since leaf 7 *is*
  leaf 6, that is the same four nodes and therefore the same root. If the forger also
  renumbers the added line's `seq` to match its position, **no finding in §8.1 fires at
  all**: every entry is self-consistent, `seq` matches position, and the root matches.

  This is the flaw known from Bitcoin as CVE-2012-2459, present here for the same reason.
  `examples/audit-log/forged-duplicate/` is a committed, runnable instance: 8 entries,
  byte-identical root to the 7-entry journal it was forged from, reported clean by both
  implementations in this repository when checked against the root alone.

  **Mitigation, and it is required, not advisory:** publish the **entry count alongside
  the root** and check both. The count is what the root cannot carry.
  `examples/audit-log/published-root.txt` publishes both, and the reference verifier's
  `--expect-entries` performs the check (§8.1, optional findings).

  A version 2 of this format should adopt RFC 6962 domain separation — hash a leaf as
  `SHA-256(0x00 || data)` and a node as `SHA-256(0x01 || left || right)` — which removes
  the ambiguity at its source. Version 1 does not, and every root already published under
  version 1 is a version 1 root. Changing the construction would invalidate them, so it is
  recorded here as a known defect with a stated workaround rather than silently patched.
- **Nothing here is signed.** There is no keypair anywhere in this format. A root
  commits to content; it says nothing about who produced it.

---

## 8. The verification procedure

A verifier takes a journal and a root. The root **SHOULD** come from outside the data
directory — see §8.2.

### 8.1 Findings

Parse the journal per §2, in order. Then:

**Level 1, per entry, in journal order.** For each entry at line position `p`:

1. If `entry.seq != p`, emit `SeqMismatch { position: p, stored_seq: entry.seq }`.
2. Compute `recomputed = hex(SHA-256(utf8(entry.raw)))`. If the **string**
   `recomputed != entry.hash`, emit
   `EntryHashMismatch { seq: entry.seq, stored: entry.hash, recomputed }`.

   The comparison is on the hex strings, case-sensitively. A `hash` field that is
   byte-correct but uppercase is a malformed journal under §2.1 and **MUST** be
   reported. Implementations differ here if they compare decoded bytes instead, so it
   is pinned deliberately.

   This finding names an entry, but **cannot say which side of it was edited**: editing
   `raw` and editing `hash` produce an identical condition. A verifier **MUST NOT**
   claim to know which.

**Level 2, aggregate.** Decode every entry's `hash` field to 32 bytes (hex decoding
here **MAY** accept either case) and compute the root per §5. Compare it to the supplied
root, as lowercase hex, treating a `null` supplied root and a `null` recomputed root as
equal.

3. If the roots differ **and** no `EntryHashMismatch` was emitted, emit `RootMismatch`.

   The suppression in step 3 is normative, not cosmetic: when an entry is already known
   to be internally inconsistent, that finding explains the root difference, and adding
   `RootMismatch` on top would report one edit as two.

   `RootMismatch` carries **no** entry identifier. Every entry is self-consistent in
   this case, so the cause is a state-file edit, or entries added, dropped or reordered.
   A verifier **MUST NOT** attribute it to a particular entry — nothing in the journal
   supports that, and localising it further would require an independent record of the
   expected entry set.

**Optional findings.** These are outside the core set above. An implementation **MAY**
emit them; two implementations are still considered in agreement if they differ here,
because they depend on information the journal does not contain.

4. `EntryCountMismatch { expected, actual }` — emitted when the verifier was given a
   published entry count and the journal's length differs from it. Any verifier that can
   obtain a published count **SHOULD** perform this check: §7 shows a forged journal that
   passes every core check and is caught only by this one.

**Verdict.** The journal is *clean* if and only if no findings were emitted **and** the
roots matched.

Exit codes used by both implementations here: `0` clean, `2` integrity violation, `1`
usage or I/O error.

### 8.2 Where the root must come from

Checking a journal against the `merkle_root` in its own `logchain.state` detects a
careless edit and nothing else. An operator who edits the journal can recompute the root
and rewrite the state file, and the result verifies clean — `examples/audit-log/tampered-root/`
is exactly that, committed so it can be run.

For level 2 to mean anything, the root **MUST** be obtained from a copy held by someone
who cannot edit the journal. This format specifies the bytes; it cannot specify that
custody, which is the load-bearing assumption. `docs/LIMITS.md` states it plainly.

The published artifact **MUST** be the root **and** the entry count together, for the
reason in §7. Publishing the root alone leaves the duplication forgery undetectable.
`examples/audit-log/published-root.txt` is the minimal form:

```
merkle_root=11671fa9483717828eaf704669fa70b8168f405e55628394adaf618d64c6cb15
entry_count=7
```

---

## 9. Inclusion proofs

A proof lets a holder of the root confirm one entry was present when the root was
computed, without the rest of the journal.

### 9.1 Proof file

```json
{
  "proof_version": "1",
  "seq": 2,
  "entry_count": 3,
  "leaf_hash": "be9d587defa1f0c09ef49eb17e206983a5f8f8289e4281860bd0ee5a19592c67",
  "merkle_root": "50298939464ed02cbf2b587250a55746b3422e133ac4f09b7e2b07869023bc9e",
  "path": [
    { "hash": "be9d587defa1f0c09ef49eb17e206983a5f8f8289e4281860bd0ee5a19592c67", "side": "right" },
    { "hash": "8450e9a90d144185def662fffc477da5e0325d80be5de388ec20d9c58d6c72d0", "side": "left"  }
  ]
}
```

| field | meaning |
|---|---|
| `proof_version` | `"1"` for this format. |
| `seq` | zero-based leaf index the proof is about. |
| `entry_count` | number of leaves in the tree the proof was cut from. |
| `leaf_hash` | the leaf digest being proved, lowercase hex. |
| `merkle_root` | the root the proof reconstructs. Informational: a checker **SHOULD** compare against an independently held root instead. |
| `path` | sibling digests from the leaf upward, one per level, **ordered leaf-first**. |

**`side` names where the *sibling* sits**, which is what fixes the argument order.
`"left"` means the sibling is the left child; `"right"` means it is the right child.

Note the first step in the example above: leaf 2 of a 3-leaf tree is its own sibling,
so the path's first entry equals `leaf_hash` with side `right`. That is the odd-node
convention (§5) showing through, and it is correct.

For a single-entry journal the path is empty and the leaf is the root.

### 9.2 Checking a proof

```
current = leaf_hash
for step in path:
    if step.side == "left":   current = SHA-256(step.hash || current)
    else:                     current = SHA-256(current || step.hash)
return current == root
```

A checker that also holds the journal **SHOULD** additionally confirm that the entry
with that `seq` really has `leaf_hash` as its `hash` field. Without that, the proof
shows only that *some* leaf with that digest was in the tree.

Replaying the example: `H(h2||h2)` then `H(H(h0||h1) || that)` gives
`50298939…bc9e`, the root from §5.1.

### 9.3 What a valid proof does and does not show

It shows the leaf was in the tree that produced that root. It does **not** show the
entry is accurate, that it is the whole record, or that other entries were not omitted
before the root was ever computed. `docs/LIMITS.md`.
