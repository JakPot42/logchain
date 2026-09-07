#!/usr/bin/env python3
"""Independent reference verifier for the logchain journal format, version 2.

A second implementation, written from docs/FORMAT.md. It imports nothing from
the Rust crate, links to nothing, and shells out to nothing: the only reason to
trust a logchain journal should be the format, not the binary that wrote it.

Python 3.8+, standard library only.

    verify_journal.py --journal J --state S     # root taken from the state file
    verify_journal.py --journal J --root HEX    # root supplied out of band
    verify_journal.py --proof P --root HEX      # check one inclusion proof

Format version 2 hashes leaves as SHA-256(0x00 || raw) and internal nodes as
SHA-256(0x01 || left || right), and builds the tree by splitting the leaf list at
the largest power of two below n (RFC 6962). Version 1 journals are detected and
rejected rather than misverified; their roots are not comparable.

Exit codes: 0 clean, 2 integrity violation, 1 usage or I/O error.
"""
import argparse
import hashlib
import json
import sys

FORMAT_VERSION = 2
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
HEX64 = set("0123456789abcdefABCDEF")


def hash_leaf(data: bytes) -> bytes:
    """RFC 6962 leaf: SHA-256(0x00 || data)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal node: SHA-256(0x01 || left || right). Order matters."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def split_point(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << (n - 1).bit_length() - 1


def merkle_root(leaves):
    """RFC 6962 MTH over already-hashed leaves. Empty -> None; one -> itself.

    No node is ever its own sibling, which is what version 1 got wrong.
    """
    if not leaves:
        return None
    if len(leaves) == 1:
        return leaves[0]
    k = split_point(len(leaves))
    return hash_node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def verify_inclusion(leaf: bytes, path, root: bytes) -> bool:
    """`side` names where the SIBLING sits, so it fixes the argument order."""
    cur = leaf
    for step in path:
        sib = decode_hash(step["hash"], "proof path")
        side = step["side"]
        if side == "left":
            cur = hash_node(sib, cur)
        elif side == "right":
            cur = hash_node(cur, sib)
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


def check_journal(entries, stored_root):
    """Level 1: leaf hash vs stored hash, plus seq order. Level 2: Merkle root."""
    # A version 1 journal would otherwise report every entry as mismatched, which
    # would misdescribe an old format as tampering. Identify it and stop.
    if entries and all(
        e["hash"] == hashlib.sha256(e["raw"].encode("utf-8")).hexdigest() for e in entries
    ):
        return {"entry_count": len(entries), "merkle_root_stored": stored_root,
                "merkle_root_recomputed": None, "root_matches": False,
                "findings": [{"finding": "LegacyV1Journal", "entry_count": len(entries)}],
                "clean": False}

    findings = []
    for position, entry in enumerate(entries):
        if entry["seq"] != position:
            findings.append({"finding": "SeqMismatch", "position": position,
                             "stored_seq": entry["seq"]})
        recomputed = hash_leaf(entry["raw"].encode("utf-8")).hex()
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

    return {"entry_count": len(entries), "merkle_root_stored": stored_root,
            "merkle_root_recomputed": recomputed_root, "root_matches": root_matches,
            "findings": findings, "clean": not findings and root_matches}


def root_from_state(path):
    state = json.load(open(path, "r", encoding="utf-8"))
    version = state.get("format_version", 1)  # absent means version 1
    if version != FORMAT_VERSION:
        raise ValueError(
            "unsupported journal format version %s (this verifier reads version %d). "
            "Version 1 hashes leaves without the 0x00 prefix and pairs odd nodes with "
            "themselves; its roots are not comparable. See docs/FORMAT.md section 1.1."
            % (version, FORMAT_VERSION))
    return state["merkle_root"]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Independent verifier for a logchain journal.")
    ap.add_argument("--journal", help="path to logchain.journal")
    ap.add_argument("--state", help="path to logchain.state (source of the root)")
    ap.add_argument("--root", help="published Merkle root, hex (overrides --state)")
    ap.add_argument("--proof", help="path to an inclusion proof JSON file")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    try:
        if args.proof:
            proof = json.load(open(args.proof, "r", encoding="utf-8"))
            if proof.get("format_version", 1) != FORMAT_VERSION:
                raise ValueError("proof is format version %s, not %d"
                                 % (proof.get("format_version", 1), FORMAT_VERSION))
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
        if args.root is not None:
            stored_root = args.root.lower()
        elif args.state:
            stored_root = root_from_state(args.state)
        else:
            ap.error("supply --root or --state")
        result = check_journal(read_entries(args.journal), stored_root)
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
