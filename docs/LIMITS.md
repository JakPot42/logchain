# What logchain proves, and what it does not

Short by design. If you read one page before relying on this, read this one.

---

## What it proves

**No entry in the journal was altered, added, removed, or reordered after it was
written** — provided the root it is checked against came from somewhere the writer
cannot reach.

That is the whole claim. It is a real one: any edit to any historical entry changes that
leaf, every node above it, and the root. Two independent implementations
(`src/` in Rust, `reference/verify_journal.py` in Python) agree on that detection across
clean and corrupted fixtures, and `examples/audit-log/` lets you run it yourself.

---

## What it does not prove

**Nothing about entries that were never written.** A log that was never told about an
event contains no trace of that event, and its root is perfectly valid. Every hash checks
out. Tamper-evidence operates on the bytes it was given; it has no opinion about the bytes
it was not given.

**Nothing about an entry that was written accurately but left something out.** A
well-formed line committed to the tree verifies identically whether or not it tells the
whole story. "This log has not been edited" and "this log is a complete and faithful
record" are different claims, and only the first one is cryptographic.

**Nothing about who wrote it.** There is no keypair and no signature anywhere in this
project. A root is a commitment to content, not an attestation of authorship. Anyone who
can write the journal can produce a matching root.

**Nothing about when it was written.** The `ingested_at` field sits outside the leaf hash
(`docs/FORMAT.md` §7), so it can be changed with no effect on the root and no finding.
Establishing that a root existed at a particular time needs a timestamp authority or
publication to an append-only log. Neither is implemented here.

---

## The assumption everything rests on: who holds the root

Level 2 — the Merkle root check — is only meaningful if the root you compare against is
held by **someone other than whoever can edit the journal**.

An operator who can edit the journal can also recompute the root and rewrite
`logchain.state`. The result is internally consistent and **verifies clean**. This is not
hypothetical: `examples/audit-log/tampered-root/` is a committed journal with a falsified
entry that both verifiers pass when checked against its own state file, and that fails
the moment the externally published root is supplied with `--root`.

So: **a single-operator log with a self-held root is close to worthless as evidence
against that operator.** It still detects accidental corruption, a careless edit, and a
third party who got filesystem access but did not think to update the state file. It does
not detect the operator, and the operator is usually who an audit trail is for.

Both verifiers take the root as an argument for this reason, and `logchain verify` warns
when run without one. Publish the root somewhere the operator does not control, on a
schedule, and keep the published copies. What the tool gives you is only ever as good as
that arrangement.

---

## Version 1 had a root collision. Version 2 fixed it.

This is recorded rather than quietly patched, because how a defect was found and what was
done about it is part of what the tool is worth.

**The defect.** Version 1 built the Merkle tree by pairing adjacent nodes level by level
and, on an odd-length level, pairing the last node **with itself**. That made the tree
shape ambiguous: appending a duplicate of the last entry to an odd-length journal produced
a **byte-identical root**, because `(h6, h6)` is computed either way. With the added
line's `seq` renumbered to match its position, **no check fired at all** — every entry was
self-consistent, `seq` matched, the root matched. A journal could gain an entry that the
published root never committed to, and verify clean. This is the flaw known from Bitcoin
as CVE-2012-2459.

**How it was found: by writing the format specification, not by testing the code.** Both
implementations agreed on the wrong answer, so no amount of cross-checking them against
each other would have surfaced it. Forcing "exactly which bytes are hashed, at every
level" onto paper is what exposed that the root did not determine the leaf count.

**What did not fix it.** Domain separation alone — tagging leaves `0x00` and nodes `0x01`
per RFC 6962 — does **not** close this. It changes every digest's value but not the
equality: both trees still perform the identical node computation over `(h6, h6)`. The
prefixes solve a different problem, keeping leaf and node digests in disjoint domains so
one cannot be presented as the other. `merkle::tests::domain_separation_alone_would_not_
have_fixed_the_v1_collision` demonstrates the prefix-only variant still colliding.

**What fixed it.** Version 2 adopts the full RFC 6962 construction: the prefixes *and* the
tree shape, splitting the leaf list at the largest power of two below `n` instead of
pairing adjacently. No node is ever its own sibling, the shape is a function of `n`, and
journals of different lengths cannot share a root. **The root now commits to the entry
count and order on its own** — nothing out of band is needed.

**What it cost.** A clean break. Version 1 roots and version 2 roots are different values
over the same log lines and neither verifies against the other, so **every root published
under version 1 is void** and a v1 journal must be re-ingested. A v1 journal is detected
and rejected with an explanation rather than misreported as tampered
(`docs/FORMAT.md` §1.1). The migration cost was zero here because the only published roots
were this project's own, and it would only have grown.

The forgery is kept as a committed fixture at `examples/audit-log/forged-duplicate/` —
under v1 it verified clean, under v2 it produces a `RootMismatch` — with a regression test
pinning that, so the defect cannot return unnoticed.

---

## Why this page exists

The gap between "this record was not altered" and "this record is complete" is not an
unfinished feature. It is a boundary that hashing cannot cross, in either direction, no
matter how the tree is built. Testing whether a record is *complete* requires starting
from an independent population that the record's author does not control — a different
kind of work entirely.

[**You cannot prove nothing was hidden**](https://github.com/JakPot42/filing-check/blob/master/docs/you-cannot-prove-nothing-was-hidden.md)
is an essay on exactly that boundary: what Merkle chains, Certificate Transparency,
witness cosigning and RFC 3161 timestamping genuinely deliver, why none of it reaches a
filed report that is false by omission, and what the measured result was when the
independent-population approach was built and run against live public data
([filing-check](https://github.com/JakPot42/filing-check)).
