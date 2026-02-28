use crate::state::AppState;
use crate::types::*;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use ogre_audit::AuditFilter;
use ogre_core::ids::ActionId;

pub async fn query_audit(
    State(state): State<AppState>,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<Vec<AuditEntryResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let filter = AuditFilter {
        action_id: params.action_id.map(ActionId::new),
        connector_id: params.connector_id,
        limit: params.limit,
        offset: params.offset,
        ..Default::default()
    };

    let entries = state.audit.query(&filter).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    let responses: Vec<AuditEntryResponse> = entries
        .into_iter()
        .map(|e| AuditEntryResponse {
            sequence: e.sequence,
            timestamp: e.timestamp,
            action_id: e.action_id.as_str().to_string(),
            classification: e.classification.map(|c| c.to_string()),
            decision: format!("{:?}", e.decision),
            step_reached: format!("{:?}", e.step_reached),
        })
        .collect();

    Ok(Json(responses))
}

pub async fn verify_chain(
    State(state): State<AppState>,
) -> Result<Json<ChainVerificationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let result = state.audit.verify_chain().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(ChainVerificationResponse {
        valid: result.valid,
        entries_checked: result.entries_checked,
        first_broken: result.first_broken,
    }))
}
