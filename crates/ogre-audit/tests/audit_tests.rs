use chrono::Utc;
use ogre_audit::*;
use ogre_core::ids::ActionId;
use std::fs;
use tempfile::tempdir;

fn make_entry(action_id: &str, decision: Decision) -> AuditEntry {
    AuditEntry {
        sequence: 0, // will be set by append
        timestamp: Utc::now(),
        action_id: ActionId::new(action_id),
        connector_id: Some("sqlite".into()),
        capability: Some("query_read".into()),
        classification: Some(ogre_core::ActionLevel::Read),
        signers_present: vec!["ogre".into(), "reviewer".into()],
        rules_evaluated: vec![],
        step_reached: ProxyStep::Executed,
        decision,
        result_summary: Some("ok".into()),
        previous_hash: [0u8; 32], // will be set by append
        entry_hash: [0u8; 32],    // will be set by append
    }
}

#[test]
fn append_and_query() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();

    let entry = make_entry("action-1", Decision::Approved);
    log.append(entry).unwrap();

    let results = log.query(&AuditFilter::default()).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].action_id.as_str(), "action-1");
    assert_eq!(results[0].sequence, 0);
}

#[test]
fn hash_chain_integrity() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();

    for i in 0..5 {
        let entry = make_entry(&format!("action-{i}"), Decision::Approved);
        log.append(entry).unwrap();
    }

    let verification = log.verify_chain().unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_checked, 5);
    assert!(verification.first_broken.is_none());
}

#[test]
fn detect_tampered_entry() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();

    for i in 0..3 {
        let entry = make_entry(&format!("action-{i}"), Decision::Approved);
        log.append(entry).unwrap();
    }

    // Tamper with the file: modify the second line
    let content = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = content.lines().map(String::from).collect();
    // Change action_id in line 1 (second entry)
    lines[1] = lines[1].replace("action-1", "action-TAMPERED");
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    // Re-open and verify
    let log2 = FileAuditLog::open(&path).unwrap();
    let verification = log2.verify_chain().unwrap();
    assert!(!verification.valid);
}

#[test]
fn recovery_after_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");

    // Write 3 entries
    {
        let log = FileAuditLog::open(&path).unwrap();
        for i in 0..3 {
            let entry = make_entry(&format!("action-{i}"), Decision::Approved);
            log.append(entry).unwrap();
        }
    }

    // Re-open and continue
    let log = FileAuditLog::open(&path).unwrap();
    assert_eq!(log.len().unwrap(), 3);

    let entry = make_entry("action-3", Decision::Approved);
    log.append(entry).unwrap();
    assert_eq!(log.len().unwrap(), 4);

    // Chain should still be valid
    let verification = log.verify_chain().unwrap();
    assert!(verification.valid);
}

#[test]
fn filter_by_action_id() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();

    for i in 0..5 {
        let entry = make_entry(&format!("action-{i}"), Decision::Approved);
        log.append(entry).unwrap();
    }

    let filter = AuditFilter {
        action_id: Some(ActionId::new("action-2")),
        ..Default::default()
    };
    let results = log.query(&filter).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].action_id.as_str(), "action-2");
}

#[test]
fn sequential_hashes_differ() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = FileAuditLog::open(&path).unwrap();

    let e1 = make_entry("action-1", Decision::Approved);
    let e2 = make_entry("action-2", Decision::Approved);
    log.append(e1).unwrap();
    log.append(e2).unwrap();

    let entries = log.query(&AuditFilter::default()).unwrap();
    assert_ne!(entries[0].entry_hash, entries[1].entry_hash);
    assert_eq!(entries[1].previous_hash, entries[0].entry_hash);
}
