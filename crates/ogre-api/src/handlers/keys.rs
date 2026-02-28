use crate::state::AppState;
use crate::types::*;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

pub async fn list_keys(
    State(state): State<AppState>,
) -> Result<Json<KeysResponse>, (StatusCode, Json<ErrorResponse>)> {
    let proxy = state.proxy.read().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "proxy lock poisoned".into(),
            }),
        )
    })?;

    let keys = proxy.verifier().public_keys();
    let hex = |bytes: &[u8; 32]| -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    };

    Ok(Json(KeysResponse {
        ogre: Some(hex(&keys.ogre.to_bytes())),
        reviewer: Some(hex(&keys.reviewer.to_bytes())),
        user: Some(hex(&keys.user.to_bytes())),
    }))
}

pub async fn generate_keys() -> Result<Json<KeysResponse>, (StatusCode, Json<ErrorResponse>)> {
    let bundle = ogre_crypto::keys::KeyBundle::generate();
    let hex = |bytes: [u8; 32]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };

    Ok(Json(KeysResponse {
        ogre: Some(hex(bundle.ogre.verifying_key().to_bytes())),
        reviewer: Some(hex(bundle.reviewer.verifying_key().to_bytes())),
        user: Some(hex(bundle.user.verifying_key().to_bytes())),
    }))
}
