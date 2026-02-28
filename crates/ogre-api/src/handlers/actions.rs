use crate::state::AppState;
use crate::types::*;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use ogre_core::ids::{ActionId, CapabilityId, ConnectorId};
use ogre_core::ActionPayload;
use ogre_crypto::signature::{Signature, SignerRole};
use ogre_proxy::ProcessResult;

pub async fn submit_action(
    State(state): State<AppState>,
    Json(req): Json<SubmitActionRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let payload = ActionPayload {
        id: ActionId::generate(),
        nonce: rand::random(),
        timestamp: Utc::now(),
        capability: CapabilityId::new(&req.capability),
        connector_id: ConnectorId::new(&req.connector_id),
        parameters: req.parameters,
    };

    let signatures: Result<Vec<Signature>, _> = req
        .signatures
        .iter()
        .map(|s| parse_signature(s))
        .collect();

    let signatures = signatures.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let action_id = payload.id.as_str().to_string();
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    match proxy.process(payload, &signatures) {
        Ok(ProcessResult::Executed(result)) => Ok(Json(ActionResponse {
            action_id,
            status: "executed".into(),
            data: result.data,
        })),
        Ok(ProcessResult::PendingApproval(id)) => Ok(Json(ActionResponse {
            action_id: id.as_str().to_string(),
            status: "pending_user_approval".into(),
            data: None,
        })),
        Err(e) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

pub async fn get_action(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    match proxy.pending_store().get(&id) {
        Some(true) => Ok(Json(ActionResponse {
            action_id: id,
            status: "pending_user_approval".into(),
            data: None,
        })),
        Some(false) => Ok(Json(ActionResponse {
            action_id: id,
            status: "expired".into(),
            data: None,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("action {id} not found"),
            }),
        )),
    }
}

pub async fn list_pending(
    State(state): State<AppState>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    let ids: Vec<String> = proxy
        .pending_store()
        .list_pending()
        .into_iter()
        .map(|id| id.as_str().to_string())
        .collect();

    Ok(Json(ids))
}

pub async fn approve_action(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ApproveActionRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let signature = parse_signature(&req.signature).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: e }),
        )
    })?;

    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    match proxy.approve_pending(&id, signature) {
        Ok(result) => Ok(Json(ActionResponse {
            action_id: id,
            status: "executed".into(),
            data: result.data,
        })),
        Err(e) => Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
    }
}

fn parse_signature(s: &SignaturePayload) -> Result<Signature, String> {
    let signer = match s.signer.as_str() {
        "ogre" => SignerRole::Ogre,
        "reviewer" => SignerRole::Reviewer,
        "user" => SignerRole::User,
        other => return Err(format!("unknown signer role: {other}")),
    };

    let bytes = hex_decode(&s.bytes_hex)?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;

    Ok(Signature {
        signer,
        bytes: ed25519_dalek::Signature::from_bytes(&arr),
    })
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
