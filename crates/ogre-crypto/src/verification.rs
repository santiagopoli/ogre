use crate::keys::PublicKeySet;
use crate::signature::{Signature, SignerRole};
use crate::signed_request::{AgentApproved, FullyApproved, SignedRequest};
use ed25519_dalek::Verifier;
use ogre_core::ActionPayload;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("missing signature from {0}")]
    MissingSigner(SignerRole),

    #[error("invalid signature from {signer}: {reason}")]
    InvalidSignature { signer: SignerRole, reason: String },

    #[error("unexpected signer role: {0}")]
    UnexpectedSigner(SignerRole),
}

/// Verifies signatures against known public keys.
///
/// Used by the proxy to reconstruct typed SignedRequest values from
/// raw payloads and signature bytes received over the wire.
pub struct SignatureVerifier {
    keys: PublicKeySet,
}

impl SignatureVerifier {
    pub fn new(keys: PublicKeySet) -> Self {
        Self { keys }
    }

    pub fn public_keys(&self) -> &PublicKeySet {
        &self.keys
    }

    /// Verify a single signature against the payload.
    fn verify_one(
        &self,
        payload_bytes: &[u8],
        signature: &Signature,
    ) -> Result<(), VerificationError> {
        let verifying_key = match signature.signer {
            SignerRole::Ogre => &self.keys.ogre,
            SignerRole::Reviewer => &self.keys.reviewer,
            SignerRole::User => &self.keys.user,
        };
        verifying_key
            .verify(payload_bytes, &signature.bytes)
            .map_err(|e| VerificationError::InvalidSignature {
                signer: signature.signer,
                reason: e.to_string(),
            })
    }

    /// Verify that a payload has valid Ogre + Reviewer signatures.
    /// Returns a SignedRequest<AgentApproved> — sufficient for Read and Write.
    pub fn verify_agent_approved(
        &self,
        payload: ActionPayload,
        signatures: &[Signature],
    ) -> Result<SignedRequest<AgentApproved>, VerificationError> {
        let payload_bytes = payload.canonical_bytes();

        let ogre_sig = signatures
            .iter()
            .find(|s| s.signer == SignerRole::Ogre)
            .ok_or(VerificationError::MissingSigner(SignerRole::Ogre))?;
        self.verify_one(&payload_bytes, ogre_sig)?;

        let reviewer_sig = signatures
            .iter()
            .find(|s| s.signer == SignerRole::Reviewer)
            .ok_or(VerificationError::MissingSigner(SignerRole::Reviewer))?;
        self.verify_one(&payload_bytes, reviewer_sig)?;

        // Construct the typed request through the normal state transitions.
        // We re-wrap rather than constructing AgentApproved directly to keep
        // the state fields pub(crate).
        Ok(SignedRequest::__from_verified_agent_approved(
            payload,
            ogre_sig.clone(),
            reviewer_sig.clone(),
        ))
    }

    /// Verify that a payload has valid Ogre + Reviewer + User signatures.
    /// Returns a SignedRequest<FullyApproved> — required for Destructive.
    pub fn verify_fully_approved(
        &self,
        payload: ActionPayload,
        signatures: &[Signature],
    ) -> Result<SignedRequest<FullyApproved>, VerificationError> {
        let payload_bytes = payload.canonical_bytes();

        let ogre_sig = signatures
            .iter()
            .find(|s| s.signer == SignerRole::Ogre)
            .ok_or(VerificationError::MissingSigner(SignerRole::Ogre))?;
        self.verify_one(&payload_bytes, ogre_sig)?;

        let reviewer_sig = signatures
            .iter()
            .find(|s| s.signer == SignerRole::Reviewer)
            .ok_or(VerificationError::MissingSigner(SignerRole::Reviewer))?;
        self.verify_one(&payload_bytes, reviewer_sig)?;

        let user_sig = signatures
            .iter()
            .find(|s| s.signer == SignerRole::User)
            .ok_or(VerificationError::MissingSigner(SignerRole::User))?;
        self.verify_one(&payload_bytes, user_sig)?;

        Ok(SignedRequest::__from_verified_fully_approved(
            payload,
            ogre_sig.clone(),
            reviewer_sig.clone(),
            user_sig.clone(),
        ))
    }
}
