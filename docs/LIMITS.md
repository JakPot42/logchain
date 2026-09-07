# What logchain proves, and what it does not

Short by design. If you read one page before relying on this, read this one.

---

## What it proves

**No entry in the journal was altered after it was written** — provided the root it is
checked against came from somewhere the writer cannot reach.

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
entry that both verifiers pass when checked against its own state file, and that only
fails once the externally published root is supplied.

So: **a single-operator log with a self-held root is close to worthless as evidence
against that operator.** It still detects accidental corruption, a careless edit, and a
third party who got filesystem access but did not think to update the state file. It does
not detect the operator, and the operator is usually who an audit trail is for.

The README's framing — "makes that impossible to hide" — is true only under the custody
assumption. Without an externally held root, it overstates what this tool delivers.

Publish the root **and the entry count** (`docs/FORMAT.md` §7 — the count is not
recoverable from the root, and a forgery exists that exploits that) to somewhere the
operator does not control, on a schedule, and keep the published copies. What the tool
gives you is only ever as good as that arrangement.

---

## A known defect in format version 1

Appending a duplicate of the last entry to an odd-length journal produces the **same
root**. With the added line renumbered, no check in the format fires. It is the Bitcoin
flaw CVE-2012-2459, present here for the same reason: odd nodes are paired with
themselves and leaves are not domain-separated from internal nodes.

It is documented in `docs/FORMAT.md` §7, demonstrated in
`examples/audit-log/forged-duplicate/`, and pinned by a test so it cannot change
unnoticed. The workaround is to publish the entry count with the root. The fix is RFC 6962
domain separation, which would be a format version 2 and would invalidate every root
already published.

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
