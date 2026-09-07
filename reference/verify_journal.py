#!/usr/bin/env python3
"""Independent reference verifier for the logchain journal format.

A second implementation, written from docs/FORMAT.md. It imports nothing from
the Rust crate, links to nothing, and shells out to nothing: the only reason to
trust a logchain journal should be the format, not the binary that wrote it.

Python 3.8+, standard library only.

    verify_journal.py --journal J --state S     # root taken from the state file
    verify_journal.py --journal J --root HEX    # root supplied out of band
    verify_journal.py --journal J --root HEX --expect-entries N
    verify_journal.py --proof P --root HEX      # check one inclusion proof

`--expect-entries` is not optional in practice: the odd-node convention lets a
journal that appends a duplicate of its own last entry produce the SAME root, so
a root alone does not pin the entry count. See docs/FORMAT.md section 7.

Exit codes: 0 clean, 2 integrity violation, 1 usage or I/O error.
"""
import argparse
import hashlib
import json
import sys

HEX64 = set("0123456789abcdefABCDEF")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_pair(left: bytes, right: bytes) -> bytes:
    """Internal node = SHA-256(left || right). Order matters."""
    return hashlib.sha256(left + right).digest()


def merkle_root(leaves):
    """Odd node at any level is paired with itself. Empty -> None; one -> itself."""
    if not leaves:
        return None
    level = list(leaves)
    while len(level) > 1:
        level = [
            hash_pair(level[i], level[i + 1] if i + 1 < len(level) else level[i])
            for i in range(0, len(level), 2)
        ]
    return level[0]


def verify_inclusion(leaf: bytes, path, root: bytes) -> bool:
    """`side` names where the SIBLING sits, so it fixes the argument order."""
    cur = leaf
    for step in path:
        sib = decode_hash(step["hash"], "proof path")
        side = step["side"]
        if side == "left":
            cur = hash_pair(sib, cur)
        elif side == "right":
            cur = hash_pair(cur, sib)
        else:
            raise ValueError("proof step side must be 'left' or 'right', got %r" % side)
    return cur == root


def decode_hash(text, where):
    if not isinstance(text, str) or len(text) != 64 or any(c not in HEX64 for c in text):
        raise ValueError("%s: not a 64-character hex SHA-256: %r" % (where, text))
    return bytes.fromhex(text)


def read_entries(path):
    """One JSON object per line; blank lines skipped, as the writer's reader does."""
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError("journal line %d is not valid JSON: %s" % (lineno, exc))
            for field, kind in (("seq", int), ("ingested_at", str), ("hash", str), ("raw", str)):
                if not isinstance(obj.get(field), kind) or isinstance(obj.get(field), bool):
                    raise ValueError("journal line %d: missing or bad field %r" % (lineno, field))
            if obj["seq"] < 0:
                raise ValueError("journal line %d: seq is negative" % lineno)
            decode_hash(obj["hash"], "journal line %d" % lineno)
            entries.append(obj)
    return entries


def check_journal(entries, stored_root, expect_entries=None):
    """Level 1: SHA-256(raw) vs stored hash, plus seq order. Level 2: Merkle root."""
    findings = []
    for position, entry in enumerate(entries):
        if entry["seq"] != position:
            findings.append({"finding": "SeqMismatch", "position": position,
                             "stored_seq": entry["seq"]})
        recomputed = sha256(entry["raw"].encode("utf-8")).hex()
        # String comparison, deliberately: a stored hash that is byte-correct but
        # not lowercase is a malformed journal, and the format requires lowercase.
        if recomputed != entry["hash"]:
            findings.append({"finding": "EntryHashMismatch", "seq": entry["seq"],
                             "stored": entry["hash"], "recomputed": recomputed})

    root = merkle_root([bytes.fromhex(e["hash"]) for e in entries])
    recomputed_root = root.hex() if root is not None else None
    root_matches = stored_root == recomputed_root

    # A root mismatch is only reported on its own account when no entry is
    # internally inconsistent; otherwise the entry findings already explain it.
    if not root_matches and not any(f["finding"] == "EntryHashMismatch" for f in findings):
        findings.append({"finding": "RootMismatch"})

    # Optional, outside the core finding set of docs/FORMAT.md section 8.1: only
    # possible when the count was published alongside the root.
    if expect_entries is not None and len(entries) != expect_entries:
        findings.append({"finding": "EntryCountMismatch", "expected": expect_entries,
                         "actual": len(entries)})

    return {"entry_count": len(entries), "merkle_root_stored": stored_root,
            "merkle_root_recomputed": recomputed_root, "root_matches": root_matches,
            "findings": findings, "clean": not findings and root_matches}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Independent verifier for a logchain journal.")
    ap.add_argument("--journal", help="path to logchain.journal")
    ap.add_argument("--state", help="path to logchain.state (source of the root)")
    ap.add_argument("--root", help="published Merkle root, hex (overrides --state)")
    ap.add_argument("--expect-entries", type=int, metavar="N",
                    help="entry count published alongside the root")
    ap.add_argument("--proof", help="path to an inclusion proof JSON file")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    try:
        if args.proof:
            proof = json.load(open(args.proof, "r", encoding="utf-8"))
            root_hex = args.root or proof.get("merkle_root")
            leaf = decode_hash(proof["leaf_hash"], "proof leaf_hash")
            ok = verify_inclusion(leaf, proof["path"], decode_hash(root_hex, "root"))
            if args.journal:  # confirm the proof is about the entry it claims
                entries = read_entries(args.journal)
                match = [e for e in entries if e["seq"] == proof["seq"]]
                if not match or match[0]["hash"] != proof["leaf_hash"]:
                    ok = False
            out = {"mode": "inclusion_proof", "seq": proof.get("seq"),
                   "root_checked": root_hex, "proof_valid": ok}
            print(json.dumps(out, indent=2) if args.json else
                  ("INCLUSION PROOF VALID   seq=%s" % proof.get("seq") if ok else
                   "INCLUSION PROOF INVALID seq=%s" % proof.get("seq")))
            return 0 if ok else 2

        if not args.journal:
            ap.error("--journal is required (or use --proof)")
        stored_root = args.root
        if stored_root is None:
            if not args.state:
                ap.error("supply --root or --state")
            stored_root = json.load(open(args.state, "r", encoding="utf-8"))["merkle_root"]
        result = check_journal(read_entries(args.journal), stored_root, args.expect_entries)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("entries checked:  %d" % result["entry_count"])
        print("stored root:      %s" % result["merkle_root_stored"])
        print("recomputed root:  %s" % result["merkle_root_recomputed"])
        for f in result["findings"]:
            detail = " ".join("%s=%s" % (k, v) for k, v in f.items() if k != "finding")
            print(("  %s %s" % (f["finding"], detail)).rstrip())
        print("INTEGRITY OK" if result["clean"] else "INTEGRITY VIOLATION")
    return 0 if result["clean"] else 2


if __name__ == "__main__":
    sys.exit(main())
