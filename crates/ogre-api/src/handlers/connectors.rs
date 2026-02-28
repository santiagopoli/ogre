use crate::state::AppState;
use crate::types::*;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

pub async fn list_connectors(
    State(state): State<AppState>,
) -> Result<Json<Vec<ConnectorResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    let connectors: Vec<ConnectorResponse> = proxy
        .connectors()
        .iter()
        .map(|(id, c)| ConnectorResponse {
            id: id.clone(),
            name: c.name().to_string(),
        })
        .collect();

    Ok(Json(connectors))
}

pub async fn list_capabilities(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<CapabilityResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    let connector = proxy.connectors().get(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("connector {id} not found"),
            }),
        )
    })?;

    let capabilities: Vec<CapabilityResponse> = connector
        .capabilities()
        .into_iter()
        .map(|c| CapabilityResponse {
            id: c.id.as_str().to_string(),
            name: c.name,
            description: c.description,
            level: c.level.to_string(),
        })
        .collect();

    Ok(Json(capabilities))
}
