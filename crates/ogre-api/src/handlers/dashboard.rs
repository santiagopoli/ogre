use crate::state::AppState;
use crate::types::*;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub async fn summary(
    State(state): State<AppState>,
) -> Result<Json<DashboardSummary>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    let total_actions = state.audit.len().unwrap_or(0);
    let pending_actions = proxy.pending_store().list_pending().len();
    let chain_valid = state
        .audit
        .verify_chain()
        .map(|v| v.valid)
        .unwrap_or(false);
    let connectors_count = proxy.connectors().len();
    let rules_count = proxy.rules_engine().rules().len();

    Ok(Json(DashboardSummary {
        total_actions,
        pending_actions,
        chain_valid,
        connectors_count,
        rules_count,
    }))
}
