use crate::state::AppState;
use crate::types::*;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub async fn list_agents(
    State(state): State<AppState>,
) -> Result<Json<Vec<AgentResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    let agents: Vec<AgentResponse> = proxy
        .agents()
        .into_iter()
        .map(|id| AgentResponse { agent_id: id })
        .collect();

    Ok(Json(agents))
}

pub async fn register_agent(
    State(state): State<AppState>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<(StatusCode, Json<AgentResponse>), (StatusCode, Json<ErrorResponse>)> {
    if req.agent_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "agent_id cannot be empty".into(),
            }),
        ));
    }

    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    proxy.register_agent(&req.agent_id);

    Ok((
        StatusCode::CREATED,
        Json(AgentResponse {
            agent_id: req.agent_id,
        }),
    ))
}
