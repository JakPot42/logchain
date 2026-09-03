use crate::hasher::{hash_bytes, to_hex};
use crate::journal::{leaf_hashes, load_state, read_entries, DataPaths};
use crate::merkle::compute_root;

#[derive(Debug)]
pub enum Tamper {
    /// An entry's `raw` and its stored `hash` disagree: SHA-256(raw) != hash.
    ///
    /// This is deliberately NOT called "raw modified", because the check is
    /// symmetric and cannot tell which side moved.  Editing `raw` and editing
    /// `hash` both produce exactly this condition, and nothing in the journal
    /// distinguishes them.  Localisation is to the entry, not to the field.
    EntryHashMismatch { seq: usize, stored: String, recomputed: String },
    /// Every entry is internally consistent, but the Merkle root recomputed
    /// from the journal does not match the root stored in the state file.
    ///
    /// This is what a state-file edit looks like, and also what truncating,
    /// reordering or dropping whole entries looks like.  It is NOT attributable
    /// to any single entry, which is why it carries no `seq`.
    RootMismatch,
    /// An entry's seq field doesn't match its position in the file.
    SeqMismatch { position: usize, stored_seq: usize },
}

#[derive(Debug)]
pub struct VerifyResult {
    pub entry_count: usize,
    pub merkle_root_stored: Option<String>,
    pub merkle_root_recomputed: Option<String>,
    pub root_matches: bool,
    pub tampered_entries: Vec<Tamper>,
    pub clean: bool,
}

/// Full two-level integrity check.
///
/// Level 1 — per-entry: recompute SHA-256(raw), compare to stored `hash`.
/// Level 2 — aggregate: recompute Merkle root from stored hashes, compare
///            to the root saved in the state file.
///
/// An attacker who updates only the raw field is caught by level 1.
/// An attacker who also updates the hash field is caught by level 2
/// (or by seq checks if they also rewrote seq numbers).
pub fn check_journal(paths: &DataPaths) -> Result<VerifyResult, crate::journal::JournalError> {
    let state = load_state(&paths.state)?;
    let entries = read_entries(&paths.journal)?;

    let entry_count = entries.len();
    let merkle_root_stored = state.merkle_root.clone();

    let mut tampered_entries = Vec::new();

    // Level 1: per-entry hash check + seq order check.
    for (position, entry) in entries.iter().enumerate() {
        // Seq must equal position (journal is append-only, zero-based).
        if entry.seq != position {
            tampered_entries.push(Tamper::SeqMismatch {
                position,
                stored_seq: entry.seq,
            });
        }

        let recomputed = to_hex(hash_bytes(entry.raw.as_bytes()));
        if recomputed != entry.hash {
            tampered_entries.push(Tamper::EntryHashMismatch {
                seq: entry.seq,
                stored: entry.hash.clone(),
                recomputed,
            });
        }
    }

    // Level 2: Merkle root check.
    let merkle_root_recomputed = if entries.is_empty() {
        None
    } else {
        let leaves = leaf_hashes(&entries)?;
        compute_root(&leaves).map(to_hex)
    };

    let root_matches = merkle_root_stored == merkle_root_recomputed;

    // A root mismatch with no per-entry inconsistency means the damage is not
    // inside any single entry: the state file was edited, or whole entries were
    // added, dropped or reordered while each remaining one stayed self-consistent.
    // That is reported as exactly what it is, with no seq attached, rather than
    // guessed at.  Localising it further would require an independent record of
    // the expected entry set, which a single journal plus its own state file
    // cannot provide.
    if !root_matches {
        let per_entry_inconsistency = tampered_entries
            .iter()
            .any(|t| matches!(t, Tamper::EntryHashMismatch { .. }));
        if !per_entry_inconsistency {
            tampered_entries.push(Tamper::RootMismatch);
        }
    }

    let clean = tampered_entries.is_empty() && root_matches;

    Ok(VerifyResult {
        entry_count,
        merkle_root_stored,
        merkle_root_recomputed,
        root_matches,
        tampered_entries,
        clean,
    })
}

/// Quick summary for use in tests: returns true only when the journal is
/// completely clean.
pub fn is_clean(paths: &DataPaths) -> Result<bool, crate::journal::JournalError> {
    Ok(check_journal(paths)?.clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{append_entry, DataPaths};
    use crate::journal::tests::tmp;
    use std::fs;

    fn ingest_n(paths: &DataPaths, n: usize) {
        for i in 0..n {
            append_entry(&format!("log line {i}"), &paths.journal, &paths.state).unwrap();
        }
    }

    #[test]
    fn clean_journal_passes() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());
        ingest_n(&paths, 5);
        assert!(is_clean(&paths).unwrap());
    }

    #[test]
    fn empty_journal_is_clean() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());
        assert!(is_clean(&paths).unwrap());
    }

    #[test]
    fn tampering_raw_field_is_detected() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());
        ingest_n(&paths, 3);

        // Read the journal as raw text lines, modify one raw field.
        let content = fs::read_to_string(&paths.journal).unwrap();
        let lines: Vec<String> = content.lines().map(String::from).collect();

        let tampered: Vec<String> = lines
            .into_iter()
            .enumerate()
            .map(|(i, line)| {
                if i == 1 {
                    // Parse as JSON, change the raw field.
                    let mut entry: serde_json::Value = serde_json::from_str(&line).unwrap();
                    entry["raw"] = serde_json::Value::String("TAMPERED raw content".to_string());
                    serde_json::to_string(&entry).unwrap()
                } else {
                    line
                }
            })
            .collect();

        fs::write(&paths.journal, tampered.join("\n") + "\n").unwrap();

        let result = check_journal(&paths).unwrap();
        assert!(!result.clean, "verify must report dirty after raw tampering");
        // Root may still match (root is computed from stored hashes, not raw);
        // the tampering is caught at level 1 (raw → stored_hash mismatch).
        assert!(
            result.tampered_entries.iter().any(|t| matches!(t, Tamper::EntryHashMismatch { seq: 1, .. })),
            "should flag seq=1 as EntryHashMismatch"
        );
    }

    #[test]
    fn tampering_hash_field_is_detected() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());
        ingest_n(&paths, 4);

        // Change the hash field of entry seq=2 without changing the raw field.
        let content = fs::read_to_string(&paths.journal).unwrap();
        let lines: Vec<String> = content.lines().map(String::from).collect();

        let tampered: Vec<String> = lines
            .into_iter()
            .enumerate()
            .map(|(i, line)| {
                if i == 2 {
                    let mut entry: serde_json::Value = serde_json::from_str(&line).unwrap();
                    entry["hash"] = serde_json::Value::String(
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    );
                    serde_json::to_string(&entry).unwrap()
                } else {
                    line
                }
            })
            .collect();

        fs::write(&paths.journal, tampered.join("\n") + "\n").unwrap();

        let result = check_journal(&paths).unwrap();
        assert!(!result.clean);
        assert!(!result.root_matches, "root should mismatch when hash field is changed");
    }

    #[test]
    fn single_entry_journal_is_clean() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());
        append_entry("only one line", &paths.journal, &paths.state).unwrap();
        assert!(is_clean(&paths).unwrap());
    }

    #[test]
    fn verify_result_has_correct_entry_count() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());
        ingest_n(&paths, 7);
        let result = check_journal(&paths).unwrap();
        assert_eq!(result.entry_count, 7);
    }

    #[test]
    fn roots_match_on_clean_journal() {
        let dir = tmp();
        let paths = DataPaths::from_dir(dir.path());
        ingest_n(&paths, 6);
        let result = check_journal(&paths).unwrap();
        assert!(result.root_matches);
        assert_eq!(result.merkle_root_stored, result.merkle_root_recomputed);
    }
}
