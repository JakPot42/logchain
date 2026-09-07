//! Cross-implementation agreement: Rust verifier vs the Python reference verifier.
//!
//! The premise of this project is that a third party can check a journal. That is
//! only true if the format is checkable by something other than the binary that
//! wrote it. These tests build the same fixtures the other Rust tests use, run
//! BOTH verifiers over them, and require the findings to match exactly - the
//! recomputed root, the root-match verdict, the clean verdict, and the ordered
//! list of findings with their field values.
//!
//! `reference/verify_journal.py` imports nothing from this crate. If the two ever
//! disagree, one of them is wrong about the format and that is the finding.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use logchain::hasher::{hash_bytes, to_hex};
use logchain::journal::{append_entry, DataPaths};
use logchain::verify::{check_journal, Tamper, VerifyResult};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Find a Python 3 interpreter. Absence is a hard failure, not a skip: a test
/// that silently does nothing would leave the central claim unchecked.
fn python() -> &'static str {
    for candidate in ["python", "python3", "py"] {
        if let Ok(out) = Command::new(candidate).arg("--version").output()
            && out.status.success()
        {
            return candidate;
        }
    }
    panic!(
        "no Python 3 interpreter found on PATH (tried python, python3, py). \
         The cross-implementation tests need one; they are the reason this repo \
         claims to be independently verifiable."
    );
}

/// Run the reference verifier and return its parsed JSON result.
fn run_reference(paths: &DataPaths) -> serde_json::Value {
    let script = repo_root().join("reference").join("verify_journal.py");
    let out = Command::new(python())
        .arg(&script)
        .arg("--journal")
        .arg(&paths.journal)
        .arg("--state")
        .arg(&paths.state)
        .arg("--json")
        .output()
        .expect("failed to run reference verifier");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "reference verifier produced no output; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("reference verifier output was not JSON ({e}):\n{stdout}");
    })
}

/// Canonical, comparable rendering of the Rust findings.
fn rust_findings(result: &VerifyResult) -> Vec<String> {
    result
        .tampered_entries
        .iter()
        .map(|t| match t {
            Tamper::EntryHashMismatch { seq, stored, recomputed } => {
                format!("EntryHashMismatch seq={seq} stored={stored} recomputed={recomputed}")
            }
            Tamper::RootMismatch => "RootMismatch".to_string(),
            Tamper::SeqMismatch { position, stored_seq } => {
                format!("SeqMismatch position={position} stored_seq={stored_seq}")
            }
        })
        .collect()
}

/// The same rendering, built from the Python verifier's JSON output.
fn reference_findings(value: &serde_json::Value) -> Vec<String> {
    value["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| match f["finding"].as_str().expect("finding name") {
            "EntryHashMismatch" => format!(
                "EntryHashMismatch seq={} stored={} recomputed={}",
                f["seq"],
                f["stored"].as_str().unwrap(),
                f["recomputed"].as_str().unwrap()
            ),
            "RootMismatch" => "RootMismatch".to_string(),
            "SeqMismatch" => format!(
                "SeqMismatch position={} stored_seq={}",
                f["position"], f["stored_seq"]
            ),
            other => panic!("unknown finding from reference verifier: {other}"),
        })
        .collect()
}

/// Run both verifiers over the same on-disk fixture and require full agreement.
fn assert_implementations_agree(paths: &DataPaths, case: &str) -> VerifyResult {
    let rust = check_journal(paths).expect("rust verifier");
    let py = run_reference(paths);

    let rust_root = rust.merkle_root_recomputed.clone();
    let py_root = py["merkle_root_recomputed"].as_str().map(String::from);

    assert_eq!(
        rust_root, py_root,
        "[{case}] recomputed Merkle root differs between implementations"
    );
    assert_eq!(
        rust.entry_count,
        py["entry_count"].as_u64().unwrap() as usize,
        "[{case}] entry count differs"
    );
    assert_eq!(
        rust.root_matches,
        py["root_matches"].as_bool().unwrap(),
        "[{case}] root-match verdict differs"
    );
    assert_eq!(
        rust.clean,
        py["clean"].as_bool().unwrap(),
        "[{case}] clean verdict differs"
    );
    assert_eq!(
        rust_findings(&rust),
        reference_findings(&py),
        "[{case}] findings differ between implementations"
    );

    rust
}

// -- fixture builders --------------------------------------------------------

fn tmp() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn ingest(paths: &DataPaths, n: usize, prefix: &str) {
    for i in 0..n {
        append_entry(&format!("{prefix} {i}"), &paths.journal, &paths.state).unwrap();
    }
}

/// Rewrite the journal line at `index` after applying `edit` to its JSON object.
fn edit_line(journal: &Path, index: usize, edit: impl Fn(&mut serde_json::Value)) {
    let content = fs::read_to_string(journal).unwrap();
    let rewritten: String = content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == index {
                let mut entry: serde_json::Value = serde_json::from_str(line).unwrap();
                edit(&mut entry);
                serde_json::to_string(&entry).unwrap()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(journal, rewritten).unwrap();
}

// -- clean cases -------------------------------------------------------------

#[test]
fn agree_on_clean_journal() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 5, "log line");
    let r = assert_implementations_agree(&p, "clean 5 entries");
    assert!(r.clean);
}

#[test]
fn agree_on_single_entry() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    append_entry("2026-06-30T12:00:00Z INFO  system ready", &p.journal, &p.state).unwrap();
    let r = assert_implementations_agree(&p, "single entry");
    assert!(r.clean);
    // For one entry the root IS the leaf; both sides must land on that.
    assert_eq!(
        r.merkle_root_recomputed,
        Some(to_hex(hash_bytes(b"2026-06-30T12:00:00Z INFO  system ready")))
    );
}

#[test]
fn agree_on_empty_journal() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    fs::write(&p.journal, "").unwrap();
    logchain::journal::save_state(&p.state, &Default::default()).unwrap();
    let r = assert_implementations_agree(&p, "empty journal");
    assert!(r.clean);
}

/// The odd-node convention is the rule most likely to be implemented differently
/// by two people. Every odd leaf count up to 9 is checked, so a disagreement
/// about duplication would surface as a differing root hex.
#[test]
fn agree_on_odd_leaf_counts() {
    for n in [3usize, 5, 7, 9] {
        let dir = tmp();
        let p = DataPaths::from_dir(dir.path());
        ingest(&p, n, "odd count entry");
        let r = assert_implementations_agree(&p, &format!("clean {n} entries"));
        assert!(r.clean, "{n}-entry journal should be clean");
    }
}

// -- tampered fixtures, mirroring the existing Rust tests --------------------

/// Same fixture as `integration::tamper_raw_field_is_caught`.
#[test]
fn agree_on_raw_field_tamper() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 6, "log line");
    edit_line(&p.journal, 3, |e| {
        e["raw"] = serde_json::Value::String("ATTACKER INJECTED THIS".to_string());
    });

    let r = assert_implementations_agree(&p, "raw field tampered at seq=3");
    assert!(!r.clean);
    assert!(r
        .tampered_entries
        .iter()
        .any(|t| matches!(t, Tamper::EntryHashMismatch { seq: 3, .. })));
}

/// Same fixture as `integration::tamper_hash_field_is_caught`.
#[test]
fn agree_on_hash_field_tamper() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 4, "entry");
    edit_line(&p.journal, 1, |e| {
        e["hash"] = serde_json::Value::String(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
    });

    let r = assert_implementations_agree(&p, "hash field tampered at seq=1");
    assert!(!r.clean);
    assert!(!r.root_matches);
}

/// Same fixture as `integration::tampering_the_state_root_alone_is_caught...`.
/// The journal is untouched, so both implementations must report exactly one
/// `RootMismatch` and neither may invent an entry-level finding.
#[test]
fn agree_on_state_root_tamper() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 4, "entry");

    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&p.state).unwrap()).unwrap();
    state["merkle_root"] = serde_json::Value::String(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
    );
    fs::write(&p.state, serde_json::to_string_pretty(&state).unwrap()).unwrap();

    let r = assert_implementations_agree(&p, "state root rewritten");
    assert_eq!(r.tampered_entries.len(), 1);
    assert!(matches!(r.tampered_entries[0], Tamper::RootMismatch));
}

/// Same fixture as `integration::merkle_root_changes_after_tamper`: the attacker
/// rewrites the entry AND its hash so level 1 stays quiet. Only the root catches
/// it, and both implementations must catch it the same way.
#[test]
fn agree_on_consistent_entry_rewrite() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 5, "line");
    edit_line(&p.journal, 2, |e| {
        e["raw"] = serde_json::Value::String("tampered".to_string());
        e["hash"] = serde_json::Value::String(to_hex(hash_bytes(b"tampered")));
    });

    let r = assert_implementations_agree(&p, "entry and hash rewritten together");
    assert!(!r.clean);
    assert!(!r.root_matches);
    assert_eq!(r.tampered_entries.len(), 1);
    assert!(matches!(r.tampered_entries[0], Tamper::RootMismatch));
}

/// Deleting a whole entry: every surviving entry stays self-consistent, so this
/// surfaces as `SeqMismatch` on the shifted entries plus a `RootMismatch`.
/// No existing Rust test covered a deletion; here neither implementation is
/// treated as the reference - they are checked against each other.
#[test]
fn agree_on_deleted_entry() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 5, "line");

    let content = fs::read_to_string(&p.journal).unwrap();
    let kept: Vec<&str> = content
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, l)| l)
        .collect();
    fs::write(&p.journal, kept.join("\n") + "\n").unwrap();

    let r = assert_implementations_agree(&p, "entry deleted");
    assert!(!r.clean);
    assert!(r
        .tampered_entries
        .iter()
        .any(|t| matches!(t, Tamper::SeqMismatch { .. })));
    assert!(r
        .tampered_entries
        .iter()
        .any(|t| matches!(t, Tamper::RootMismatch)));
}

// -- known format defect, pinned ---------------------------------------------

/// A KNOWN DEFECT of format version 1, recorded here so it cannot change silently
/// and cannot be mistaken for a passing security property. See docs/FORMAT.md §7.
///
/// Because odd nodes are paired with themselves, appending a duplicate of the last
/// entry to an odd-length journal leaves the root unchanged. With the added line's
/// `seq` renumbered to match its position, no core finding fires in either
/// implementation: the forged journal verifies clean against the genuine root.
///
/// This test asserts the defect is real and that BOTH implementations exhibit it —
/// they agree, so this is a property of the format, not of either verifier. It then
/// asserts the documented mitigation actually works: the published entry count, which
/// the root cannot carry, catches it.
#[test]
fn duplicated_last_entry_collides_with_the_genuine_root() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 7, "line"); // odd count is what makes the collision possible

    let genuine_root = check_journal(&p).unwrap().merkle_root_recomputed.unwrap();

    // Append a copy of the last entry, renumbered so seq still matches position.
    let content = fs::read_to_string(&p.journal).unwrap();
    let mut last: serde_json::Value =
        serde_json::from_str(content.lines().last().unwrap()).unwrap();
    last["seq"] = serde_json::Value::from(7u64);
    fs::write(
        &p.journal,
        format!("{}{}\n", content, serde_json::to_string(&last).unwrap()),
    )
    .unwrap();

    // The forged journal has 8 entries and the SAME root, and both implementations
    // call it clean. That is the defect.
    let r = assert_implementations_agree(&p, "duplicated last entry");
    assert_eq!(r.entry_count, 8, "the forged journal really does have 8 entries");
    assert_eq!(
        r.merkle_root_recomputed.as_deref(),
        Some(genuine_root.as_str()),
        "the 8-entry forgery must reproduce the 7-entry root, or this defect is gone \
         and docs/FORMAT.md §7 needs rewriting"
    );
    assert!(r.clean, "known defect: the forgery passes every core check");

    // The documented mitigation: publish the entry count with the root.
    let script = repo_root().join("reference").join("verify_journal.py");
    let out = Command::new(python())
        .arg(&script)
        .arg("--journal")
        .arg(&p.journal)
        .arg("--root")
        .arg(&genuine_root)
        .arg("--expect-entries")
        .arg("7")
        .arg("--json")
        .output()
        .expect("run reference verifier with a published count");
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["clean"], false, "the published count must catch the forgery");
    assert_eq!(v["findings"][0]["finding"], "EntryCountMismatch");
    assert_eq!(v["findings"][0]["expected"], 7);
    assert_eq!(v["findings"][0]["actual"], 8);
}

// -- inclusion proofs across implementations ---------------------------------

/// Every proof the Rust side emits must check out under the Python verifier,
/// and the same proof pointed at a different root must be rejected there.
#[test]
fn reference_verifier_checks_rust_generated_proofs() {
    let dir = tmp();
    let p = DataPaths::from_dir(dir.path());
    ingest(&p, 7, "provable entry");

    let entries = logchain::journal::read_entries(&p.journal).unwrap();
    let leaves = logchain::journal::leaf_hashes(&entries).unwrap();
    let script = repo_root().join("reference").join("verify_journal.py");

    for seq in 0..entries.len() {
        let proof = logchain::report::build_inclusion_proof(seq, &entries, &leaves).unwrap();
        let proof_path = dir.path().join(format!("proof-{seq}.json"));
        fs::write(&proof_path, serde_json::to_string_pretty(&proof).unwrap()).unwrap();

        let out = Command::new(python())
            .arg(&script)
            .arg("--proof")
            .arg(&proof_path)
            .arg("--journal")
            .arg(&p.journal)
            .arg("--json")
            .output()
            .expect("run reference proof check");
        let v: serde_json::Value =
            serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
        assert_eq!(
            v["proof_valid"], true,
            "seq={seq} proof rejected by the reference verifier"
        );

        // Same proof, wrong root: must be rejected.
        let bad = Command::new(python())
            .arg(&script)
            .arg("--proof")
            .arg(&proof_path)
            .arg("--root")
            .arg("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
            .arg("--json")
            .output()
            .expect("run reference proof check");
        let v: serde_json::Value =
            serde_json::from_str(&String::from_utf8_lossy(&bad.stdout)).unwrap();
        assert_eq!(
            v["proof_valid"], false,
            "seq={seq} proof accepted against a wrong root"
        );
    }
}
