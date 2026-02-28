use crate::state::AppState;
use crate::types::*;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub async fn list_rules(
    State(state): State<AppState>,
) -> Result<Json<Vec<RuleResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    let rules: Vec<RuleResponse> = proxy
        .rules_engine()
        .rules()
        .iter()
        .map(|r| RuleResponse {
            id: r.id.as_str().to_string(),
            description: r.description.clone(),
            effect: format!("{:?}", r.effect).to_lowercase(),
            priority: r.priority,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(rules))
}

pub async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<RuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    let condition: ogre_rules::Condition =
        serde_json::from_value(req.condition).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid condition: {e}"),
                }),
            )
        })?;

    let effect = match req.effect.as_str() {
        "allow" => ogre_rules::RuleEffect::Allow,
        "deny" => ogre_rules::RuleEffect::Deny,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("invalid effect: {other}"),
                }),
            ))
        }
    };

    let rule = ogre_rules::Rule {
        id: ogre_core::ids::RuleId::generate(),
        version: 1,
        description: req.description.clone(),
        condition,
        effect,
        priority: req.priority,
        created_at: chrono::Utc::now(),
        signature: req.signature,
    };

    let response = RuleResponse {
        id: rule.id.as_str().to_string(),
        description: rule.description.clone(),
        effect: req.effect,
        priority: rule.priority,
        created_at: rule.created_at,
    };

    let mut proxy = state.proxy.write().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    proxy.rules_engine_mut().add_rule(rule).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(response))
}
