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

/// Hash the concatenation of two hashes (used for Merkle internal nodes).
/// Crucially: hash_pair(a, b) ≠ hash_pair(b, a) — order matters.
/// This is what makes a Merkle tree order-sensitive: swapping two log entries
/// changes every ancestor all the way to the root.
pub fn hash_pair(left: Hash, right: Hash) -> Hash {
    let mut h = Sha256::new();
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
    fn hash_pair_is_order_sensitive() {
        let a = hash_bytes(b"left");
        let b = hash_bytes(b"right");
        assert_ne!(hash_pair(a, b), hash_pair(b, a));
    }

    #[test]
    fn hex_round_trip() {
        let original = hash_bytes(b"round trip test");
        let hex_str = to_hex(original);
        let decoded = from_hex(&hex_str).unwrap();
        assert_eq!(original, decoded);
    }
}
