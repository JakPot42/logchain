# logchain journal format, version 2

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

## 1. Files and versioning

A logchain data directory contains exactly two files:

| file | contents |
|---|---|
| `logchain.journal` | the ordered entries, newline-delimited JSON |
| `logchain.state` | a single JSON object holding the current Merkle root |

The journal is append-only in normal operation. Nothing in the format enforces that;
enforcement is what the Merkle root is for.

### 1.1 Version 1 is not readable by a version 2 verifier

The current version is **2**, declared in `logchain.state` as `"format_version": 2`.

Version 1 differed in both hashing rules:

| | version 1 | version 2 |
|---|---|---|
| leaf hash | `SHA-256(raw)` | `SHA-256(0x00 ‖ raw)` |
| internal node | `SHA-256(left ‖ right)` | `SHA-256(0x01 ‖ left ‖ right)` |
| odd node | paired with itself | no odd node exists — see §5 |

**A version 1 root and a version 2 root over the same log lines are different values,
and neither verifies against the other.** A verifier **MUST** reject a journal it
cannot read rather than reporting it as tampered:

1. If `logchain.state` declares a `format_version` other than 2, reject with an error
   naming the version found. A state file with **no** `format_version` field is a
   version 1 file (the field did not exist), and is rejected on the same grounds.
2. When the root is supplied out of band and no state file is read, apply the check in
   §8.1 finding 4 (`LegacyV1Journal`), which identifies a v1 journal from the entry
   hashes alone.

Version 1 is not supported and there is no migration path that preserves roots. A v1
journal must be re-ingested to obtain a v2 root, and any previously published v1 root
is meaningless under v2. **Why the break was taken rather than a compatibility layer:
version 1 had a root collision** — see §5.2.

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
| `hash` | string | the **leaf hash** of `raw` (§3), hex-encoded, **lowercase**, exactly 64 characters. |
| `raw` | string | the original log line, verbatim, with its line terminator removed. |

Example line (wrapped here for reading; it is one line in the file):

```json
{"seq":0,"ingested_at":"2026-09-07T06:43:58.7+00:00",
 "hash":"ad2c26f9f0ea1c0b2b3ff01e2a5e3f...",
 "raw":"2026-09-01T09:14:02Z INFO  auth: session opened for operator id=4471"}
```

---

## 3. The leaf hash: exactly which bytes are hashed

This is the part most likely to be got wrong, so it is stated exhaustively.

> **The leaf for entry *n* is `SHA-256(0x00 ‖ B)`, where `B` is the UTF-8 encoding of
> the *decoded* string value of that entry's `raw` field, and `0x00` is one literal
> zero byte prepended to it.**

"Decoded" means after JSON unescaping. If the file contains `"raw":"a\"b"`, the string
is `a"b` (3 characters), `B` is the 3 bytes `61 22 62`, and the hashed input is the
4 bytes `00 61 22 62`.

The following are **NOT** part of the hashed input:

- the trailing newline of the original log line (it is stripped before storage);
- any surrounding JSON quotes;
- any other field — `seq`, `ingested_at` and the `hash` field itself are **not** hashed;
- any length prefix, separator, or salt beyond the single `0x00` tag.

The `0x00` tag is the RFC 6962 leaf prefix. Paired with the `0x01` node prefix (§4) it
means leaf digests and internal-node digests are computed in **disjoint domains**, so
a 64-byte internal-node preimage can never be presented as a log line, or the reverse.

### 3.1 Test vectors

`SHA-256` of the empty byte string, as a self-check that your hasher is wired up at all:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

A leaf over empty data, `SHA-256(0x00)` — checks that the prefix is one byte, and is on
the correct side of the data:

```
6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
```

For the three log lines `alpha`, `beta`, `gamma`:

```
h0 = SHA-256(0x00 ‖ "alpha") = 2a158d8afd48e3f88cb4195dfdb2a9e4817d95fa57fd34440d93f9aae5c4f82b
h1 = SHA-256(0x00 ‖ "beta")  = e23537b050e84af2cbaab46f2f83d8d3b5febc8e5ac6200d306284f687d46924
h2 = SHA-256(0x00 ‖ "gamma") = 4c79d0d62f7cf5ca8874155f2d3b875f2625da2bb3abc86bbd6833f25ba90e51
```

---

## 4. The internal node hash

An internal node is:

```
node = SHA-256( 0x01 ‖ left_digest_32_bytes ‖ right_digest_32_bytes )
```

The input is always exactly 65 bytes: the one-byte tag, then the two **binary** 32-byte
child digests. Nothing separates the halves.

**Order is significant.** `NODE(a, b)` is not `NODE(b, a)`. Swapping two adjacent log
entries changes every node above them, up to the root.

A common implementation error is to concatenate the 64-character hex *strings* and hash
those ASCII bytes. That produces a different tree. Decode to bytes first.

A node over two all-zero digests, as a fixed check of tag placement and operand order:

```
SHA-256(0x01 ‖ 0x00*32 ‖ 0x00*32) = ae0798d0ecaed2b778eddebf18f071a561c53658c05e76cedecc27cafbdbc577
```

---

## 5. Computing the root

Given the ordered list of leaf digests `L` (RFC 6962 §2.1):

1. If `L` is empty, the root is **null** (JSON `null` in the state file).
2. If `L` has exactly one element, the root **is that element**, unchanged. It is not
   hashed again, and it is not paired with anything.
3. Otherwise, let **`k` be the largest power of two strictly less than `n = |L|`**.
   Split `L` into `L[0:k]` and `L[k:n]`, compute each half's root by this same rule,
   and combine them:

```
function root(L):
    if L is empty:  return null
    if |L| == 1:    return L[0]
    k = largest power of two < |L|
    return NODE( root(L[0:k]), root(L[k:|L|]) )
```

`k` for the first few sizes: `n=2 -> 1`, `3 -> 2`, `4 -> 2`, `5 -> 4`, `7 -> 4`,
`8 -> 4`, `9 -> 8`, `16 -> 8`, `17 -> 16`.

**No node is ever its own sibling.** The tree shape is fully determined by `n`, so two
journals of different lengths cannot produce the same root. That property is the whole
reason for this construction; §5.2 explains what happened without it.

### 5.1 Worked example: three leaves

Using `h0`, `h1`, `h2` from §3.1. `n = 3`, so `k = 2`: the halves are `[h0, h1]` and
`[h2]`. The lone right-hand leaf is carried up unchanged.

```
root = NODE( NODE(h0, h1), h2 )

NODE(h0,h1) = 983cb57c04cddd52634edab38a7bef85708a974f114bbd9aa9ec5d4ce6656b4b
root        = 385da30f3917282c8939dff851957e519ab1846b1351a14c0adb3b11632742aa
```

A third implementation that ingests the lines `alpha`, `beta`, `gamma` in that order
and does not produce `385da30f…42aa` has diverged from this spec.

### 5.2 Why version 1's rule was abandoned — a real root collision

Version 1 built the tree level by level, pairing adjacent nodes, and on an odd-length
level **paired the last node with itself**. That made the tree shape ambiguous.

Take a 7-entry journal. Its levels pair as `(0,1)(2,3)(4,5)(6,6)`. Now append a copy of
entry 6, making 8 entries; that pairs as `(0,1)(2,3)(4,5)(6,7)` — and since leaf 7 *is*
leaf 6, those are the same four nodes, and therefore **the same root, byte for byte**.
Renumber the added line's `seq` to match its position and *no check fired at all*: every
entry was self-consistent, `seq` matched position, and the root matched. A journal could
gain an entry the published root never committed to, undetectably.

This is the flaw known from Bitcoin as CVE-2012-2459. It was found in this project by
writing this specification, not by testing the code.

**Domain separation alone would not have fixed it.** Adding the `0x00`/`0x01` prefixes
changes every digest's value but not the equality: both trees still perform the identical
`NODE(h6, h6)` step. The prefixes solve a different problem (§3). What removes the
collision is *this section's* construction, in which the shape is a function of `n` and
self-pairing does not exist. Both halves of the version 2 change were necessary, and
`merkle::tests::domain_separation_alone_would_not_have_fixed_the_v1_collision`
demonstrates the prefix-only variant still colliding.

`examples/audit-log/forged-duplicate/` is that exact forgery, kept as a committed
fixture. Under version 1 it verified clean; under version 2 it produces a
`RootMismatch`, and `tests/cross_language.rs` pins that.

### 5.3 One deliberate deviation from RFC 6962

RFC 6962 defines the empty tree's hash as `SHA-256()` of the empty string. This format
uses **`null`** instead, because an empty journal has nothing to commit to and a state
file carrying a magic constant for "no entries" reads as data rather than absence. This
is the only place this format departs from RFC 6962's Merkle Tree Hash, and it is noted
so an implementer reusing an off-the-shelf RFC 6962 library knows to special-case it.

---

## 6. `logchain.state`

A single JSON object:

```json
{
  "format_version": 2,
  "merkle_root": "b07c68b5b3d4e3d4a3fbe9da2bcab24399ec19697d1110d4fa6e59fcc75ba436",
  "entry_count": 7,
  "last_updated": "2026-09-07T06:43:58.913421900+00:00"
}
```

| field | JSON type | meaning |
|---|---|---|
| `format_version` | integer | `2`. Absent means version 1 (§1.1). A verifier **MUST** reject any other value. |
| `merkle_root` | string or `null` | lowercase hex root over all journal leaves, in journal order. `null` if and only if the journal has no entries. |
| `entry_count` | integer, `>= 0` | number of entries the writer believes are in the journal. Informational: under version 2 the root already commits to the count (§5). |
| `last_updated` | string | RFC 3339 timestamp of the last write to this file. Informational only; nothing verifies it. |

**The state file is written by the same process that writes the journal, and carries no
authentication.** Anyone who can edit the journal can edit the state file to match. It
is a convenience cache of the root, not evidence. A verification that compares the
journal only against this file proves the two files are mutually consistent and nothing
more. See §8.2 and `docs/LIMITS.md`.

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
- **Nothing here is signed.** There is no keypair anywhere in this format. A root
  commits to content; it says nothing about who produced it.
- **A root commits to the entry set and its order, and to nothing about the entries'
  truth.** See `docs/LIMITS.md`.

---

## 8. The verification procedure

A verifier takes a journal and a root. The root **SHOULD** come from outside the data
directory — see §8.2.

### 8.1 Findings

Reject the journal outright if the state file declares a `format_version` other than 2
(§1.1). Otherwise parse the journal per §2, in order, then:

**Level 0, format.** If the journal is non-empty and **every** entry's stored `hash`
equals the *version 1* leaf rule — bare `SHA-256(raw)`, with no `0x00` prefix — emit
`LegacyV1Journal { entry_count }` and stop. Do not proceed to the checks below.

4. This exists so a version 1 journal is identified as an old format rather than
   reported as every entry being tampered with, which is what the level 1 check would
   otherwise produce. It is the only detection available when the root was supplied out
   of band and no state file was read.

**Level 1, per entry, in journal order.** For each entry at line position `p`:

1. If `entry.seq != p`, emit `SeqMismatch { position: p, stored_seq: entry.seq }`.
2. Compute `recomputed = hex(SHA-256(0x00 ‖ utf8(entry.raw)))`. If the **string**
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

**Verdict.** The journal is *clean* if and only if no findings were emitted **and** the
roots matched.

Exit codes used by both implementations here: `0` clean, `2` integrity violation, `1`
usage or I/O error.

### 8.2 Where the root must come from

Checking a journal against the `merkle_root` in its own `logchain.state` detects a
careless edit and nothing else. An operator who can edit the journal can recompute the
root and rewrite the state file, and the result verifies clean —
`examples/audit-log/tampered-root/` is exactly that, committed so it can be run.

For level 2 to mean anything, the root **MUST** be obtained from a copy held by someone
who cannot edit the journal. Both verifiers here take it as an argument for that reason
(`logchain verify --root <hex>`; `verify_journal.py --root <hex>`), and the Rust CLI
prints a warning when run without one.

This format specifies the bytes; it cannot specify that custody, which is the
load-bearing assumption. `docs/LIMITS.md` states it plainly.

Publishing the root alone is sufficient under version 2 — the root commits to the entry
count and order (§5). Under version 1 it was not, which is why
`examples/audit-log/published-root.txt` still publishes `entry_count` alongside it: a
second, independent value costs nothing and is a useful cross-check.

---

## 9. Inclusion proofs

A proof lets a holder of the root confirm one entry was present when the root was
computed, without the rest of the journal.

### 9.1 Proof file

```json
{
  "proof_version": "2",
  "format_version": 2,
  "seq": 2,
  "entry_count": 3,
  "leaf_hash": "4c79d0d62f7cf5ca8874155f2d3b875f2625da2bb3abc86bbd6833f25ba90e51",
  "merkle_root": "385da30f3917282c8939dff851957e519ab1846b1351a14c0adb3b11632742aa",
  "path": [
    { "hash": "983cb57c04cddd52634edab38a7bef85708a974f114bbd9aa9ec5d4ce6656b4b", "side": "left" }
  ]
}
```

| field | meaning |
|---|---|
| `proof_version` | `"2"` for this format. |
| `format_version` | `2`. A verifier **MUST** reject any other value: a v1 and a v2 proof are not interchangeable, since both the hashing and the tree shape differ. |
| `seq` | zero-based leaf index the proof is about. |
| `entry_count` | number of leaves in the tree the proof was cut from. |
| `leaf_hash` | the leaf digest being proved, lowercase hex. |
| `merkle_root` | the root the proof reconstructs. Informational: a checker **SHOULD** compare against an independently held root instead. |
| `path` | sibling digests from the leaf upward, one per level, **ordered leaf-first**. |

**`side` names where the *sibling* sits**, which is what fixes the argument order.
`"left"` means the sibling is the left child; `"right"` means it is the right child.

The path is RFC 6962's `PATH(m, D[n])`: at each level, recurse into the half containing
the leaf and record the *other* half's root as the sibling. For a single-entry journal
the path is empty and the leaf is the root. Path length is at most `ceil(log2 n)`.

### 9.2 Checking a proof

```
current = leaf_hash
for step in path:
    if step.side == "left":   current = NODE(step.hash, current)
    else:                     current = NODE(current, step.hash)
return current == root
```

A checker that also holds the journal **SHOULD** additionally confirm that the entry
with that `seq` really has `leaf_hash` as its `hash` field. Without that, the proof
shows only that *some* leaf with that digest was in the tree.

Replaying the §9.1 example: leaf 2 of a 3-leaf tree has one sibling, the left subtree
root `NODE(h0,h1)`, so `NODE(983cb57c…, 4c79d0d6…)` gives `385da30f…42aa`, the root from
§5.1.

### 9.3 What a valid proof does and does not show

It shows the leaf was in the tree that produced that root. It does **not** show the
entry is accurate, that it is the whole record, or that other entries were not omitted
before the root was ever computed. `docs/LIMITS.md`.
