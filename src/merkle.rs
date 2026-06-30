//! Pure Rust Merkle tree — no external crates beyond the sha2 hasher.
//!
//! ## Construction
//!
//! Given N leaf hashes, build upward by hashing adjacent pairs:
//!
//! ```text
//!           root
//!          /    \
//!        H01    H23
//!        / \    / \
//!       h0 h1  h2 h3
//! ```
//!
//! **Odd-count rule (Bitcoin convention):** when a level has an odd number of
//! nodes, the last node is duplicated before pairing:
//!
//! ```text
//! 3 leaves:   h0   h1   h2 [h2]   ← h2 paired with itself
//!              \   /     \   /
//!              H01       H22
//!                \       /
//!                  root
//! ```
//!
//! This means every internal node still has exactly two children, no matter
//! the leaf count. The root is always a single 32-byte value.

use crate::hasher::{hash_pair, Hash};

/// Which side the **sibling** sits on at each proof step.
/// This determines argument order in hash_pair at verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Sibling is to the LEFT  → hash_pair(sibling, current)
    Left,
    /// Sibling is to the RIGHT → hash_pair(current, sibling)
    Right,
}

/// A single step in a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofNode {
    pub hash: Hash,
    pub side: Side,
}

/// Compute the Merkle root of `leaves`.
/// Returns `None` only for an empty slice; a single leaf returns itself.
pub fn compute_root(leaves: &[Hash]) -> Option<Hash> {
    match leaves.len() {
        0 => None,
        1 => Some(leaves[0]),
        _ => {
            let mut level: Vec<Hash> = leaves.to_vec();

            while level.len() > 1 {
                level = pair_up(&level);
            }

            Some(level[0])
        }
    }
}

/// Reduce one level of the tree: pair adjacent nodes, duplicate last if odd.
fn pair_up(nodes: &[Hash]) -> Vec<Hash> {
    let mut next = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;
    while i < nodes.len() {
        let left = nodes[i];
        // If there's no right sibling, duplicate the left node.
        let right = if i + 1 < nodes.len() { nodes[i + 1] } else { nodes[i] };
        next.push(hash_pair(left, right));
        i += 2;
    }
    next
}

/// Generate an inclusion proof for the leaf at `index`.
///
/// The proof is a list of sibling hashes + their sides.  To verify: start
/// with the leaf hash, then for each step compute `hash_pair` with the
/// sibling (order given by `Side`).  The final value must equal the root.
///
/// Returns `None` if `index >= leaves.len()`.
pub fn generate_proof(leaves: &[Hash], index: usize) -> Option<Vec<ProofNode>> {
    if index >= leaves.len() {
        return None;
    }
    if leaves.len() == 1 {
        return Some(vec![]); // leaf IS the root; empty proof is valid
    }

    let mut proof = Vec::new();
    let mut current_level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        // Determine sibling index.
        // idx % 2 == 0 → we're the LEFT child; sibling is idx+1 (to the right).
        // idx % 2 == 1 → we're the RIGHT child; sibling is idx-1 (to the left).
        let (sibling_idx, side) = if idx % 2 == 0 {
            let sib = if idx + 1 < current_level.len() { idx + 1 } else { idx };
            (sib, Side::Right)
        } else {
            (idx - 1, Side::Left)
        };

        proof.push(ProofNode {
            hash: current_level[sibling_idx],
            side,
        });

        // Move up one level; our new index is the parent's index.
        current_level = pair_up(&current_level);
        idx /= 2;
    }

    Some(proof)
}

/// Verify an inclusion proof against a known root.
///
/// Start with the leaf hash, repeatedly combine with sibling hashes using
/// the order recorded in the proof.  If the result equals `root`, the
/// entry was present when the root was computed.
pub fn verify_proof(leaf: Hash, proof: &[ProofNode], root: Hash) -> bool {
    let result = proof.iter().fold(leaf, |current, node| match node.side {
        Side::Left => hash_pair(node.hash, current),
        Side::Right => hash_pair(current, node.hash),
    });
    result == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::hash_bytes;

    fn h(s: &str) -> Hash {
        hash_bytes(s.as_bytes())
    }

    // ── compute_root ─────────────────────────────────────────────────────────

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
    fn root_two_leaves_is_hash_of_pair() {
        let a = h("a");
        let b = h("b");
        let expected = hash_pair(a, b);
        assert_eq!(compute_root(&[a, b]), Some(expected));
    }

    #[test]
    fn root_three_leaves_uses_duplication() {
        // Level 0: [h0, h1, h2]
        // Pairs: (h0,h1) and (h2,h2)   ← h2 duplicated
        // Level 1: [H(h0,h1), H(h2,h2)]
        // Root:    H(H(h0,h1), H(h2,h2))
        let h0 = h("zero");
        let h1 = h("one");
        let h2 = h("two");
        let n01 = hash_pair(h0, h1);
        let n22 = hash_pair(h2, h2);
        let expected = hash_pair(n01, n22);
        assert_eq!(compute_root(&[h0, h1, h2]), Some(expected));
    }

    #[test]
    fn root_four_leaves_symmetric() {
        let h0 = h("a");
        let h1 = h("b");
        let h2 = h("c");
        let h3 = h("d");
        let n01 = hash_pair(h0, h1);
        let n23 = hash_pair(h2, h3);
        let expected = hash_pair(n01, n23);
        assert_eq!(compute_root(&[h0, h1, h2, h3]), Some(expected));
    }

    #[test]
    fn root_five_leaves() {
        // Level 0: [h0,h1,h2,h3,h4]
        // Pairs: (h0,h1),(h2,h3),(h4,h4)
        // Level 1: [H01, H23, H44]
        // Pairs: (H01,H23),(H44,H44)
        // Level 2: [H(H01,H23), H(H44,H44)]
        // Root: H(H(H01,H23), H(H44,H44))
        let leaves: Vec<Hash> = (0..5).map(|i| h(&i.to_string())).collect();
        let n01 = hash_pair(leaves[0], leaves[1]);
        let n23 = hash_pair(leaves[2], leaves[3]);
        let n44 = hash_pair(leaves[4], leaves[4]);
        let n0123 = hash_pair(n01, n23);
        let n4444 = hash_pair(n44, n44);
        let expected = hash_pair(n0123, n4444);
        assert_eq!(compute_root(&leaves), Some(expected));
    }

    #[test]
    fn any_change_to_any_leaf_changes_root() {
        let mut leaves: Vec<Hash> = (0..8).map(|i| h(&i.to_string())).collect();
        let original_root = compute_root(&leaves).unwrap();

        // Flip every leaf in turn and verify root changes each time.
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
        let root1 = compute_root(&leaves);
        let root2 = compute_root(&leaves);
        assert_eq!(root1, root2);
    }

    // ── Merkle proofs ─────────────────────────────────────────────────────────

    #[test]
    fn proof_single_leaf_is_empty_and_valid() {
        let leaf = h("solo");
        let root = compute_root(&[leaf]).unwrap();
        let proof = generate_proof(&[leaf], 0).unwrap();
        assert!(proof.is_empty());
        assert!(verify_proof(leaf, &proof, root));
    }

    #[test]
    fn proof_two_leaves_index_zero() {
        let a = h("a");
        let b = h("b");
        let leaves = [a, b];
        let root = compute_root(&leaves).unwrap();
        let proof = generate_proof(&leaves, 0).unwrap();
        assert!(verify_proof(a, &proof, root));
    }

    #[test]
    fn proof_two_leaves_index_one() {
        let a = h("a");
        let b = h("b");
        let leaves = [a, b];
        let root = compute_root(&leaves).unwrap();
        let proof = generate_proof(&leaves, 1).unwrap();
        assert!(verify_proof(b, &proof, root));
    }

    #[test]
    fn proof_three_leaves_all_valid() {
        let leaves: Vec<Hash> = ["x", "y", "z"].iter().map(|s| h(s)).collect();
        let root = compute_root(&leaves).unwrap();
        for (i, &leaf) in leaves.iter().enumerate() {
            let proof = generate_proof(&leaves, i).unwrap();
            assert!(
                verify_proof(leaf, &proof, root),
                "proof for index {i} should be valid"
            );
        }
    }

    #[test]
    fn proof_four_leaves_all_valid() {
        let leaves: Vec<Hash> = (0..4).map(|i| h(&i.to_string())).collect();
        let root = compute_root(&leaves).unwrap();
        for (i, &leaf) in leaves.iter().enumerate() {
            let proof = generate_proof(&leaves, i).unwrap();
            assert!(verify_proof(leaf, &proof, root), "index {i} proof failed");
        }
    }

    #[test]
    fn proof_five_leaves_index_four() {
        // Tests the double-duplication path for the last element when count=5.
        let leaves: Vec<Hash> = (0..5).map(|i| h(&i.to_string())).collect();
        let root = compute_root(&leaves).unwrap();
        let proof = generate_proof(&leaves, 4).unwrap();
        assert!(verify_proof(leaves[4], &proof, root));
    }

    #[test]
    fn invalid_proof_fails() {
        let leaves: Vec<Hash> = (0..4).map(|i| h(&i.to_string())).collect();
        let root = compute_root(&leaves).unwrap();
        // Use the proof for leaf 0, but verify against leaf 1 — should fail.
        let proof = generate_proof(&leaves, 0).unwrap();
        assert!(!verify_proof(leaves[1], &proof, root));
    }

    #[test]
    fn wrong_root_fails_proof() {
        let leaves: Vec<Hash> = (0..4).map(|i| h(&i.to_string())).collect();
        let root = compute_root(&leaves).unwrap();
        let tampered_root = hash_pair(root, root); // definitely not the real root
        let proof = generate_proof(&leaves, 0).unwrap();
        assert!(!verify_proof(leaves[0], &proof, tampered_root));
    }

    #[test]
    fn proof_out_of_bounds_returns_none() {
        let leaves = [h("a"), h("b")];
        assert_eq!(generate_proof(&leaves, 5), None);
    }

    #[test]
    fn root_matches_manual_four_leaf_computation() {
        // Manually compute a 4-leaf root and compare to compute_root().
        // If this passes, every step of pair_up() is correct.
        let entries = [b"2026-01-01 INFO start" as &[u8], b"2026-01-01 WARN slow", b"2026-01-01 ERROR crash", b"2026-01-01 INFO restart"];
        let leaves: Vec<Hash> = entries.iter().map(|e| hash_bytes(e)).collect();

        let n01 = hash_pair(leaves[0], leaves[1]);
        let n23 = hash_pair(leaves[2], leaves[3]);
        let manual_root = hash_pair(n01, n23);

        assert_eq!(compute_root(&leaves), Some(manual_root));
    }
}
