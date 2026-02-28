use chrono::{DateTime, Duration, Utc};
use ogre_core::ids::ActionId;
use ogre_core::ActionLevel;
use ogre_crypto::signed_request::{AgentApproved, SignedRequest};
use std::collections::HashMap;
use std::sync::Mutex;

/// A destructive action awaiting user signature.
pub struct PendingAction {
    pub action_id: ActionId,
    pub request: SignedRequest<AgentApproved>,
    pub classification: ActionLevel,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// In-memory store for pending destructive actions.
pub struct PendingActionStore {
    actions: Mutex<HashMap<String, PendingAction>>,
    ttl: Duration,
}

impl PendingActionStore {
    pub fn new(ttl_minutes: i64) -> Self {
        Self {
            actions: Mutex::new(HashMap::new()),
            ttl: Duration::minutes(ttl_minutes),
        }
    }

    pub fn insert(&self, request: SignedRequest<AgentApproved>, classification: ActionLevel) -> ActionId {
        let action_id = request.payload().id.clone();
        let now = Utc::now();
        let pending = PendingAction {
            action_id: action_id.clone(),
            request,
            classification,
            created_at: now,
            expires_at: now + self.ttl,
        };

        let mut store = self.actions.lock().expect("pending lock poisoned");
        store.insert(action_id.as_str().to_string(), pending);
        action_id
    }

    pub fn get(&self, action_id: &str) -> Option<bool> {
        let store = self.actions.lock().expect("pending lock poisoned");
        store.get(action_id).map(|p| p.expires_at > Utc::now())
    }

    pub fn remove(&self, action_id: &str) -> Option<PendingAction> {
        let mut store = self.actions.lock().expect("pending lock poisoned");
        store.remove(action_id)
    }

    /// Remove all expired actions. Returns the count removed.
    pub fn reap_expired(&self) -> usize {
        let mut store = self.actions.lock().expect("pending lock poisoned");
        let now = Utc::now();
        let before = store.len();
        store.retain(|_, p| p.expires_at > now);
        before - store.len()
    }

    pub fn list_pending(&self) -> Vec<ActionId> {
        let store = self.actions.lock().expect("pending lock poisoned");
        let now = Utc::now();
        store
            .values()
            .filter(|p| p.expires_at > now)
            .map(|p| p.action_id.clone())
            .collect()
    }
}
