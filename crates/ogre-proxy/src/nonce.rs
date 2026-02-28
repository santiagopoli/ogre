use std::collections::HashSet;
use std::sync::Mutex;

/// Tracks seen nonces to prevent replay attacks.
pub struct NonceTracker {
    seen: Mutex<HashSet<[u8; 32]>>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Returns true if the nonce is new (not seen before).
    /// Returns false if this is a replay.
    pub fn check_and_record(&self, nonce: &[u8; 32]) -> bool {
        let mut seen = self.seen.lock().expect("nonce lock poisoned");
        seen.insert(*nonce)
    }
}
