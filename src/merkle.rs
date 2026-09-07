//! Merkle tree, RFC 6962 construction. Format version 2.
//!
//! ## Construction
//!
//! Leaves are hashed `SHA-256(0x00 || data)` and internal nodes
//! `SHA-256(0x01 || left || right)` (see `hasher.rs`). The tree is built by
//! splitting the leaf list at **`k`, the largest power of two strictly less than
//! `n`** — not by pairing adjacent nodes level by level:
//!
//! ```text
//! MTH({})     = none
//! MTH({d0})   = d0                         (already a leaf hash)
//! MTH(D[n])   = NODE( MTH(D[0:k]), MTH(D[k:n]) ),  k = largest 2^x < n
//! ```
//!
//! For 7 leaves that gives `k = 4`:
//!
//! ```text
//!                     root
//!                   /      \
//!            (0..4)          (4..7)
//!            /    \          /     \
//!        (0,1)   (2,3)    (4,5)    h6
//!        /  \    /  \     /   \
//!       h0  h1  h2  h3   h4   h5
//! ```
//!
//! ## Why not the version 1 rule
//!
//! Version 1 paired adjacent nodes and, on an odd level, **paired the last node
//! with itself**. That made the tree shape ambiguous: appending a duplicate of
//! the last entry to an odd-length journal produced a *byte-identical root*,
//! because `(h6, h6)` is computed either way. An entry could be added to a
//! journal without changing the root and without any check firing — the flaw
//! known from Bitcoin as CVE-2012-2459.
//!
//! Domain separation alone does **not** fix that; `hash_node(h6, h6)` is the same
//! computation whether or not it carries a `0x01` prefix. What fixes it is this
//! construction, in which the shape is a function of `n` and no node is ever its
//! own sibling. Both halves of the change were needed, and
//! `domain_separation_alone_would_not_have_fixed_the_v1_collision` below is the
//! demonstration.

use crate::hasher::{hash_node, Hash};

/// Which side the **sibling** sits on at each proof step.
/// This determines argument order in `hash_node` at verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is to the LEFT  → hash_node(sibling, current)
    Left,
    /// Sibling is to the RIGHT → hash_node(current, sibling)
    Right,
}

/// A single step in a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofNode {
    pub hash: Hash,
    pub side: Side,
}

/// The largest power of two strictly less than `n`. Requires `n >= 2`.
///
/// `n = 2 -> 1`, `3 -> 2`, `4 -> 2`, `5 -> 4`, `8 -> 4`, `9 -> 8`.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    1usize << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// Compute the Merkle root of `leaves`, which are already leaf hashes.
/// Returns `None` only for an empty slice; a single leaf returns itself.
pub fn compute_root(leaves: &[Hash]) -> Option<Hash> {
    match leaves.len() {
        0 => None,
        1 => Some(leaves[0]),
        n => {
            let k = split_point(n);
            let left = compute_root(&leaves[..k])?;
            let right = compute_root(&leaves[k..])?;
            Some(hash_node(left, right))
        }
    }
}

/// Generate an inclusion proof for the leaf at `index`.
///
/// The proof is a list of sibling hashes plus the side each sibling sits on,
/// ordered **leaf first**. To verify: start with the leaf hash and combine with
/// each sibling in order; the final value must equal the root.
///
/// Returns `None` if `index >= leaves.len()`.
pub fn generate_proof(leaves: &[Hash], index: usize) -> Option<Vec<ProofNode>> {
    if index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    build_path(leaves, index, &mut proof);
    Some(proof)
}

/// RFC 6962 PATH(m, D[n]): recurse into the half holding the leaf, then record
/// the other half's root as the sibling. Recursing before pushing is what puts
/// the deepest sibling first.
fn build_path(leaves: &[Hash], m: usize, out: &mut Vec<ProofNode>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if m < k {
        build_path(&leaves[..k], m, out);
        out.push(ProofNode {
            hash: compute_root(&leaves[k..]).expect("right half is non-empty"),
            side: Side::Right,
        });
    } else {
        build_path(&leaves[k..], m - k, out);
        out.push(ProofNode {
            hash: compute_root(&leaves[..k]).expect("left half is non-empty"),
            side: Side::Left,
        });
    }
}

/// Verify an inclusion proof against a known root.
///
/// Start with the leaf hash, repeatedly combine with sibling hashes using the
/// order recorded in the proof. If the result equals `root`, the entry was
/// present when the root was computed.
pub fn verify_proof(leaf: Hash, proof: &[ProofNode], root: Hash) -> bool {
    let result = proof.iter().fold(leaf, |current, node| match node.side {
        Side::Left => hash_node(node.hash, current),
        Side::Right => hash_node(current, node.hash),
    });
    result == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::hash_leaf;

    fn h(s: &str) -> Hash {
        hash_leaf(s.as_bytes())
    }

    // -- split_point ---------------------------------------------------------

    #[test]
    fn split_point_is_largest_power_of_two_below_n() {
        let cases = [
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 4),
            (6, 4),
            (7, 4),
            (8, 4),
            (9, 8),
            (16, 8),
            (17, 16),
        ];
        for (n, expected) in cases {
            assert_eq!(split_point(n), expected, "split_point({n})");
        }
    }

    // -- compute_root --------------------------------------------------------

    #[test]
    fn root_empty_returns_none() {
        assert_eq!(compute_root(&[]), None);
    }

    #[test]
    fn root_single_leaf_is_the_leaf_itself() {
        let leaf = h("only entry");
        assert_eq!(compute_root(&[leaf]), Some(leaf));
    }

    #[test]
    fn root_two_leaves_is_node_of_pair() {
        let a = h("a");
        let b = h("b");
        assert_eq!(compute_root(&[a, b]), Some(hash_node(a, b)));
    }

    #[test]
    fn root_three_leaves_splits_two_and_one() {
        // k = 2, so the halves are [h0, h1] and [h2]. The lone right-hand leaf
        // is carried up unchanged - it is NOT paired with itself.
        let h0 = h("zero");
        let h1 = h("one");
        let h2 = h("two");
        let expected = hash_node(hash_node(h0, h1), h2);
        assert_eq!(compute_root(&[h0, h1, h2]), Some(expected));
    }

    #[test]
    fn root_four_leaves_symmetric() {
        let leaves: Vec<Hash> = ["a", "b", "c", "d"].iter().map(|s| h(s)).collect();
        let expected = hash_node(
            hash_node(leaves[0], leaves[1]),
            hash_node(leaves[2], leaves[3]),
        );
        assert_eq!(compute_root(&leaves), Some(expected));
    }

    #[test]
    fn root_five_leaves_splits_four_and_one() {
        // k = 4: halves are [h0..h3] and [h4].
        let leaves: Vec<Hash> = (0..5).map(|i| h(&i.to_string())).collect();
        let left = hash_node(
            hash_node(leaves[0], leaves[1]),
            hash_node(leaves[2], leaves[3]),
        );
        let expected = hash_node(left, leaves[4]);
        assert_eq!(compute_root(&leaves), Some(expected));
    }

    #[test]
    fn root_seven_leaves_splits_four_and_three() {
        let leaves: Vec<Hash> = (0..7).map(|i| h(&i.to_string())).collect();
        let left = hash_node(
            hash_node(leaves[0], leaves[1]),
            hash_node(leaves[2], leaves[3]),
        );
        let right = hash_node(hash_node(leaves[4], leaves[5]), leaves[6]);
        assert_eq!(compute_root(&leaves), Some(hash_node(left, right)));
    }

    #[test]
    fn any_change_to_any_leaf_changes_root() {
        let mut leaves: Vec<Hash> = (0..8).map(|i| h(&i.to_string())).collect();
        let original_root = compute_root(&leaves).unwrap();

        for i in 0..8 {
            let saved = leaves[i];
            leaves[i] = h("tampered");
            assert_ne!(
                compute_root(&leaves).unwrap(),
                original_root,
                "root should change when leaf {i} is tampered"
            );
            leaves[i] = saved;
        }
    }

    #[test]
    fn order_matters() {
        let a = h("first");
        let b = h("second");
        assert_ne!(compute_root(&[a, b]), compute_root(&[b, a]));
    }

    #[test]
    fn same_leaves_same_root() {
        let leaves: Vec<Hash> = (0..10).map(|i| h(&i.to_string())).collect();
        assert_eq!(compute_root(&leaves), compute_root(&leaves));
    }

    // -- the defect this format version exists to fix ------------------------

    /// Every leaf count from 1 to 64 must produce a distinct root, so the root
    /// commits to how many entries there are. Under version 1 this was false:
    /// n and n+1 collided whenever n was odd and the extra entry duplicated the
    /// last one.
    #[test]
    fn appending_a_duplicate_of_the_last_entry_changes_the_root() {
        for n in 1..=64usize {
            let leaves: Vec<Hash> = (0..n).map(|i| h(&format!("line {i}"))).collect();
            let mut appended = leaves.clone();
            appended.push(leaves[n - 1]); // the v1 forgery

            assert_ne!(
                compute_root(&leaves),
                compute_root(&appended),
                "n={n}: duplicating the last entry must change the root"
            );
        }
    }

    /// THE REASON THE TREE SHAPE CHANGED, not just the prefixes.
    ///
    /// This reconstructs version 1's pair-and-duplicate rule but WITH the RFC 6962
    /// domain-separation prefixes applied, and shows the collision survives
    /// untouched. Adding `0x00`/`0x01` tags does nothing here, because both trees
    /// perform the identical `NODE(h6, h6)` step. Only abandoning self-pairing
    /// fixes it.
    #[test]
    fn domain_separation_alone_would_not_have_fixed_the_v1_collision() {
        // v1's shape, with v2's prefixes.
        fn root_v1_shape(leaves: &[Hash]) -> Hash {
            let mut level = leaves.to_vec();
            while level.len() > 1 {
                let mut next = Vec::new();
                let mut i = 0;
                while i < level.len() {
                    let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
                    next.push(hash_node(level[i], right));
                    i += 2;
                }
                level = next;
            }
            level[0]
        }

        let seven: Vec<Hash> = (0..7).map(|i| h(&format!("line {i}"))).collect();
        let mut eight = seven.clone();
        eight.push(seven[6]);

        assert_eq!(
            root_v1_shape(&seven),
            root_v1_shape(&eight),
            "prefixes alone leave the duplication collision fully intact"
        );
        assert_ne!(
            compute_root(&seven),
            compute_root(&eight),
            "the RFC 6962 split rule is what actually removes it"
        );
    }

    // -- Merkle proofs -------------------------------------------------------

    #[test]
    fn proof_single_leaf_is_empty_and_valid() {
        let leaf = h("solo");
        let root = compute_root(&[leaf]).unwrap();
        let proof = generate_proof(&[leaf], 0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_proof(leaf, &proof, root));
    }

    /// Every index of every leaf count from 1 to 33, so no shape goes unchecked.
    #[test]
    fn every_proof_of_every_shape_verifies() {
        for n in 1..=33usize {
            let leaves: Vec<Hash> = (0..n).map(|i| h(&format!("entry {i}"))).collect();
            let root = compute_root(&leaves).unwrap();
            for (i, &leaf) in leaves.iter().enumerate() {
                let proof = generate_proof(&leaves, i).unwrap();
                assert!(verify_proof(leaf, &proof, root), "n={n} index={i} proof failed");
            }
        }
    }

    /// Proof length is the leaf's depth, which for RFC 6962 is at most
    /// ceil(log2(n)) - the property that makes proofs cheap.
    #[test]
    fn proof_length_is_logarithmic() {
        for n in 1..=64usize {
            let leaves: Vec<Hash> = (0..n).map(|i| h(&i.to_string())).collect();
            let max_depth = (usize::BITS - (n - 1).leading_zeros()) as usize; // ceil(log2 n)
            for i in 0..n {
                let proof = generate_proof(&leaves, i).unwrap();
                assert!(
                    proof.len() <= max_depth,
                    "n={n} index={i}: proof length {} exceeded {max_depth}",
                    proof.len()
                );
            }
        }
    }

    #[test]
    fn invalid_proof_fails() {
        let leaves: Vec<Hash> = (0..4).map(|i| h(&i.to_string())).collect();
        let root = compute_root(&leaves).unwrap();
        let proof = generate_proof(&leaves, 0).unwrap();
        assert!(!verify_proof(leaves[1], &proof, root));
    }

    #[test]
    fn wrong_root_fails_proof() {
        let leaves: Vec<Hash> = (0..4).map(|i| h(&i.to_string())).collect();
        let root = compute_root(&leaves).unwrap();
        let tampered_root = hash_node(root, root);
        let proof = generate_proof(&leaves, 0).unwrap();
        assert!(!verify_proof(leaves[0], &proof, tampered_root));
    }

    /// A proof cut from one tree must not verify against a different tree's root,
    /// even when the leaf is present in both.
    #[test]
    fn proof_from_a_different_tree_fails() {
        let five: Vec<Hash> = (0..5).map(|i| h(&i.to_string())).collect();
        let six: Vec<Hash> = (0..6).map(|i| h(&i.to_string())).collect();
        let proof = generate_proof(&five, 4).unwrap();
        let six_root = compute_root(&six).unwrap();
        assert!(!verify_proof(five[4], &proof, six_root));
    }

    #[test]
    fn proof_out_of_bounds_returns_none() {
        let leaves = [h("a"), h("b")];
        assert_eq!(generate_proof(&leaves, 5), None);
    }

    #[test]
    fn root_matches_manual_four_leaf_computation() {
        let entries = [
            b"2026-01-01 INFO start" as &[u8],
            b"2026-01-01 WARN slow",
            b"2026-01-01 ERROR crash",
            b"2026-01-01 INFO restart",
        ];
        let leaves: Vec<Hash> = entries.iter().map(|e| hash_leaf(e)).collect();
        let manual_root = hash_node(
            hash_node(leaves[0], leaves[1]),
            hash_node(leaves[2], leaves[3]),
        );
        assert_eq!(compute_root(&leaves), Some(manual_root));
    }
}
