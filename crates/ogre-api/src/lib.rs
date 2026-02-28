mod handlers;
mod state;
mod types;

pub use state::AppState;
pub use types::*;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Actions
        .route("/api/v1/actions", post(handlers::actions::submit_action))
        .route("/api/v1/actions/pending", get(handlers::actions::list_pending))
        .route("/api/v1/actions/:id", get(handlers::actions::get_action))
        .route("/api/v1/actions/:id/approve", post(handlers::actions::approve_action))
        // Rules
        .route("/api/v1/rules", get(handlers::rules::list_rules))
        .route("/api/v1/rules", post(handlers::rules::create_rule))
        // Audit
        .route("/api/v1/audit", get(handlers::audit::query_audit))
        .route("/api/v1/audit/verify", get(handlers::audit::verify_chain))
        // Connectors
        .route("/api/v1/connectors", get(handlers::connectors::list_connectors))
        .route("/api/v1/connectors/:id/capabilities", get(handlers::connectors::list_capabilities))
        // Keys
        .route("/api/v1/keys", get(handlers::keys::list_keys))
        .route("/api/v1/keys/generate", post(handlers::keys::generate_keys))
        // Dashboard
        .route("/api/v1/dashboard/summary", get(handlers::dashboard::summary))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
