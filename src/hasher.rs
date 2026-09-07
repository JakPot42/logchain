use sha2::{Digest, Sha256};

/// A SHA-256 digest: exactly 32 bytes, fixed-width.
/// Using a type alias instead of a newtype keeps it Copy and slice-compatible.
pub type Hash = [u8; 32];

/// Hash arbitrary bytes into a 32-byte SHA-256 digest.
pub fn hash_bytes(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Domain-separation prefixes, per RFC 6962 section 2.1.
///
/// Every hash in the tree is tagged by its role before the data it covers, so a
/// leaf digest and an internal-node digest are computed in disjoint domains and
/// one can never be presented as the other.
pub const LEAF_PREFIX: u8 = 0x00;
pub const NODE_PREFIX: u8 = 0x01;

/// Leaf hash: `SHA-256(0x00 || data)`.
///
/// The `0x00` tag is what stops an internal node's 64-byte preimage being passed
/// off as a log line (and vice versa). Format version 2 onward; version 1 hashed
/// the data with no prefix. See `docs/FORMAT.md`.
pub fn hash_leaf(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    h.finalize().into()
}

/// Internal node: `SHA-256(0x01 || left || right)` over the two 32-byte children.
///
/// Order matters — `hash_node(a, b) != hash_node(b, a)` — which is what makes the
/// tree sensitive to log entries being reordered.
pub fn hash_node(left: Hash, right: Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

pub fn to_hex(hash: Hash) -> String {
    hex::encode(hash)
}

pub fn from_hex(s: &str) -> Result<Hash, hex::FromHexError> {
    let bytes = hex::decode(s)?;
    bytes.try_into().map_err(|_| hex::FromHexError::InvalidStringLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-256 of empty string — fixed known value, verifiable at https://emn178.github.io/online-tools/sha256.html
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    // SHA-256 of "hello" — another fixed reference value
    const SHA256_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn hash_empty_string_is_known_value() {
        let h = to_hex(hash_bytes(b""));
        assert_eq!(h, SHA256_EMPTY);
    }

    #[test]
    fn hash_hello_is_known_value() {
        let h = to_hex(hash_bytes(b"hello"));
        assert_eq!(h, SHA256_HELLO);
    }

    #[test]
    fn hash_is_deterministic() {
        let a = hash_bytes(b"log entry");
        let b = hash_bytes(b"log entry");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_node_is_order_sensitive() {
        let a = hash_leaf(b"left");
        let b = hash_leaf(b"right");
        assert_ne!(hash_node(a, b), hash_node(b, a));
    }

    /// The whole point of the prefixes: the two domains must never overlap.
    #[test]
    fn leaf_and_node_domains_are_disjoint() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");

        // An internal node over (a, b) must not equal a leaf over the same 64
        // bytes. Without the prefixes these would be identical.
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&a);
        concatenated.extend_from_slice(&b);
        assert_ne!(hash_node(a, b), hash_leaf(&concatenated));

        // And a leaf is not the bare hash of its data, which is what version 1
        // stored. A v1 journal therefore cannot be mistaken for a v2 one.
        assert_ne!(hash_leaf(b"a"), hash_bytes(b"a"));
    }

    /// Fixed vectors, so a third implementation can check its prefixes are on
    /// the right side of the data and are single bytes.
    #[test]
    fn prefixed_hashes_are_known_values() {
        // SHA-256(0x00) — a leaf over empty data.
        assert_eq!(
            to_hex(hash_leaf(b"")),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        // SHA-256(0x01 || 0x00*32 || 0x00*32) — a node over two zero digests.
        assert_eq!(
            to_hex(hash_node([0u8; 32], [0u8; 32])),
            "ae0798d0ecaed2b778eddebf18f071a561c53658c05e76cedecc27cafbdbc577"
        );
    }

    #[test]
    fn hex_round_trip() {
        let original = hash_bytes(b"round trip test");
        let hex_str = to_hex(original);
        let decoded = from_hex(&hex_str).unwrap();
        assert_eq!(original, decoded);
    }
}
