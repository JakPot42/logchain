use crate::hasher::{hash_bytes, hash_leaf, to_hex};
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
    /// Every entry's stored hash matches the FORMAT VERSION 1 leaf rule
    /// (bare `SHA-256(raw)`) rather than version 2's `SHA-256(0x00 || raw)`.
    ///
    /// Reported instead of a wall of `EntryHashMismatch`, which is what a v1
    /// journal would otherwise produce and which would misdescribe the problem:
    /// nothing was tampered with, the file is simply an older format whose roots
    /// are not comparable with version 2 roots.
    LegacyV1Journal { entry_count: usize },
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
    check_journal_against(paths, None)
}

/// As `check_journal`, but compares against `root_override` when one is given.
///
/// This is the form that means something. Checking a journal against the
/// `merkle_root` in its own state file only proves the two files agree, and the
/// operator who can edit one can edit the other. A root held by someone who
/// cannot write to this directory is what makes level 2 evidence.
pub fn check_journal_against(
    paths: &DataPaths,
    root_override: Option<&str>,
) -> Result<VerifyResult, crate::journal::JournalError> {
    // With an external root supplied, the state file need not exist or be
    // readable - the whole point is not to depend on it.
    let merkle_root_stored = match root_override {
        Some(r) => Some(r.to_ascii_lowercase()),
        None => load_state(&paths.state)?.merkle_root,
    };
    let entries = read_entries(&paths.journal)?;

    let entry_count = entries.len();

    let mut tampered_entries = Vec::new();

    // A version 1 journal read with version 2 rules would report every entry as
    // mismatched. Detect it first and say what it actually is.
    if !entries.is_empty()
        && entries
            .iter()
            .all(|e| e.hash == to_hex(hash_bytes(e.raw.as_bytes())))
    {
        return Ok(VerifyResult {
            entry_count,
            merkle_root_stored,
            merkle_root_recomputed: None,
            root_matches: false,
            tampered_entries: vec![Tamper::LegacyV1Journal { entry_count }],
            clean: false,
        });
    }

    // Level 1: per-entry hash check + seq order check.
    for (position, entry) in entries.iter().enumerate() {
        // Seq must equal position (journal is append-only, zero-based).
        if entry.seq != position {
            tampered_entries.push(Tamper::SeqMismatch {
                position,
                stored_seq: entry.seq,
            });
        }

        let recomputed = to_hex(hash_leaf(entry.raw.as_bytes()));
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
