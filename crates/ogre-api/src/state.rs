use ogre_audit::AuditLog;
use ogre_proxy::Proxy;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct AppState {
    pub proxy: Arc<RwLock<Proxy>>,
    pub audit: Arc<dyn AuditLog>,
}
