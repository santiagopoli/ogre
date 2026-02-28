use crate::keys::{OgreKeyPair, ReviewerKeyPair, UserKeyPair};
use crate::signature::{Signature, SignerRole};
use ed25519_dalek::Signer;
use ogre_core::ActionPayload;

// =============================================================================
// Type-state markers.
//
// These encode the signature progression at the type level:
//   Unsigned -> OgreSigned -> AgentApproved -> FullyApproved
//
// The proxy's execute methods accept only the appropriate state, making it a
// COMPILE-TIME ERROR to execute a destructive action without all 3 signatures.
// =============================================================================

/// No signatures yet.
#[derive(Debug, Clone)]
pub struct Unsigned;

/// Signed by the Ogre agent only.
#[derive(Debug, Clone)]
pub struct OgreSigned {
    pub(crate) ogre_signature: Signature,
}

/// Signed by both Ogre and Reviewer agents. Sufficient for Read and Write.
#[derive(Debug, Clone)]
pub struct AgentApproved {
    pub(crate) ogre_signature: Signature,
    pub(crate) reviewer_signature: Signature,
}

/// Signed by Ogre, Reviewer, and User. Required for Destructive actions.
#[derive(Debug, Clone)]
pub struct FullyApproved {
    pub(crate) ogre_signature: Signature,
    pub(crate) reviewer_signature: Signature,
    pub(crate) user_signature: Signature,
}

/// An action request parameterized by its signature state.
///
/// Transitions consume self, so a previous state cannot be reused.
/// Each transition requires the corresponding private key.
#[derive(Debug, Clone)]
pub struct SignedRequest<State> {
    payload: ActionPayload,
    state: State,
}

// -- Construction -------------------------------------------------------------

impl SignedRequest<Unsigned> {
    pub fn new(payload: ActionPayload) -> Self {
        Self {
            payload,
            state: Unsigned,
        }
    }
}

// -- Transitions (consume self) -----------------------------------------------

impl SignedRequest<Unsigned> {
    /// The Ogre agent signs the request.
    pub fn sign_ogre(self, key: &OgreKeyPair) -> SignedRequest<OgreSigned> {
        let bytes = self.payload.canonical_bytes();
        let sig = key.signing_key().sign(&bytes);
        SignedRequest {
            payload: self.payload,
            state: OgreSigned {
                ogre_signature: Signature {
                    signer: SignerRole::Ogre,
                    bytes: sig,
                },
            },
        }
    }
}

impl SignedRequest<OgreSigned> {
    /// The Reviewer agent signs the request.
    pub fn sign_reviewer(self, key: &ReviewerKeyPair) -> SignedRequest<AgentApproved> {
        let bytes = self.payload.canonical_bytes();
        let sig = key.signing_key().sign(&bytes);
        SignedRequest {
            payload: self.payload,
            state: AgentApproved {
                ogre_signature: self.state.ogre_signature,
                reviewer_signature: Signature {
                    signer: SignerRole::Reviewer,
                    bytes: sig,
                },
            },
        }
    }
}

impl SignedRequest<AgentApproved> {
    /// The user signs the request. Required for destructive actions.
    pub fn sign_user(self, key: &UserKeyPair) -> SignedRequest<FullyApproved> {
        let bytes = self.payload.canonical_bytes();
        let sig = key.signing_key().sign(&bytes);
        SignedRequest {
            payload: self.payload,
            state: FullyApproved {
                ogre_signature: self.state.ogre_signature,
                reviewer_signature: self.state.reviewer_signature,
                user_signature: Signature {
                    signer: SignerRole::User,
                    bytes: sig,
                },
            },
        }
    }
}

// -- Accessors (available at every state) -------------------------------------

impl<S> SignedRequest<S> {
    pub fn payload(&self) -> &ActionPayload {
        &self.payload
    }

    pub fn into_payload(self) -> ActionPayload {
        self.payload
    }
}

// -- Signature accessors per state --------------------------------------------

impl SignedRequest<OgreSigned> {
    pub fn ogre_signature(&self) -> &Signature {
        &self.state.ogre_signature
    }
}

impl SignedRequest<AgentApproved> {
    pub fn ogre_signature(&self) -> &Signature {
        &self.state.ogre_signature
    }

    pub fn reviewer_signature(&self) -> &Signature {
        &self.state.reviewer_signature
    }

    pub fn signatures(&self) -> [&Signature; 2] {
        [&self.state.ogre_signature, &self.state.reviewer_signature]
    }
}

impl SignedRequest<FullyApproved> {
    pub fn ogre_signature(&self) -> &Signature {
        &self.state.ogre_signature
    }

    pub fn reviewer_signature(&self) -> &Signature {
        &self.state.reviewer_signature
    }

    pub fn user_signature(&self) -> &Signature {
        &self.state.user_signature
    }

    pub fn signatures(&self) -> [&Signature; 3] {
        [
            &self.state.ogre_signature,
            &self.state.reviewer_signature,
            &self.state.user_signature,
        ]
    }
}

// -- Verification constructors (crate-private) --------------------------------
// These are used by SignatureVerifier to construct typed requests after
// verifying signatures. They are NOT public — only the crypto crate can call them.

impl SignedRequest<AgentApproved> {
    #[doc(hidden)]
    pub fn __from_verified_agent_approved(
        payload: ActionPayload,
        ogre_sig: Signature,
        reviewer_sig: Signature,
    ) -> Self {
        Self {
            payload,
            state: AgentApproved {
                ogre_signature: ogre_sig,
                reviewer_signature: reviewer_sig,
            },
        }
    }
}

impl SignedRequest<FullyApproved> {
    #[doc(hidden)]
    pub fn __from_verified_fully_approved(
        payload: ActionPayload,
        ogre_sig: Signature,
        reviewer_sig: Signature,
        user_sig: Signature,
    ) -> Self {
        Self {
            payload,
            state: FullyApproved {
                ogre_signature: ogre_sig,
                reviewer_signature: reviewer_sig,
                user_signature: user_sig,
            },
        }
    }
}
