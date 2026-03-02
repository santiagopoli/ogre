use chrono::Utc;
use ogre_core::{ActionId, ActionPayload, AgentId, CapabilityId, ConnectorId};
use ogre_crypto::keys::{KeyBundle, PublicKeySet};
use ogre_crypto::signature::SignerRole;
use ogre_crypto::signed_request::SignedRequest;
use ogre_crypto::verification::SignatureVerifier;

fn test_payload() -> ActionPayload {
    ActionPayload {
        id: ActionId::generate(),
        nonce: rand::random(),
        timestamp: Utc::now(),
        capability: CapabilityId::new("query_read"),
        connector_id: ConnectorId::new("sqlite"),
        parameters: serde_json::json!({"query": "SELECT 1"}),
        agent_id: AgentId::new("test-agent"),
    }
}

#[test]
fn sign_and_verify_agent_approved() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    // Extract signatures for verification
    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let payload = request.into_payload();

    let verified = verifier.verify_agent_approved(payload, &sigs);
    assert!(verified.is_ok());
}

#[test]
fn sign_and_verify_fully_approved() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer)
        .sign_user(&bundle.user);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let payload = request.into_payload();

    let verified = verifier.verify_fully_approved(payload, &sigs);
    assert!(verified.is_ok());
}

#[test]
fn reject_missing_ogre_signature() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();

    // Only provide reviewer sig, no ogre
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let reviewer_sig = request.reviewer_signature().clone();
    let payload = request.into_payload();

    let result = verifier.verify_agent_approved(payload, &[reviewer_sig]);
    assert!(result.is_err());
}

#[test]
fn reject_missing_reviewer_signature() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let ogre_sig = request.ogre_signature().clone();
    let payload = request.into_payload();

    let result = verifier.verify_agent_approved(payload, &[ogre_sig]);
    assert!(result.is_err());
}

#[test]
fn reject_missing_user_signature_for_fully_approved() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let payload = request.into_payload();

    // Try to get fully_approved with only 2 sigs
    let result = verifier.verify_fully_approved(payload, &sigs);
    assert!(result.is_err());
}

#[test]
fn reject_wrong_key() {
    let bundle = KeyBundle::generate();
    let other_bundle = KeyBundle::generate(); // different keys
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();
    // Sign with the OTHER bundle's keys
    let request = SignedRequest::new(payload)
        .sign_ogre(&other_bundle.ogre)
        .sign_reviewer(&other_bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();
    let payload = request.into_payload();

    let result = verifier.verify_agent_approved(payload, &sigs);
    assert!(result.is_err());
}

#[test]
fn reject_tampered_payload() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();
    let request = SignedRequest::new(payload)
        .sign_ogre(&bundle.ogre)
        .sign_reviewer(&bundle.reviewer);

    let sigs: Vec<_> = request.signatures().into_iter().cloned().collect();

    // Create a DIFFERENT payload (different nonce)
    let tampered_payload = test_payload();

    let result = verifier.verify_agent_approved(tampered_payload, &sigs);
    assert!(result.is_err());
}

#[test]
fn typestate_progression() {
    let bundle = KeyBundle::generate();
    let payload = test_payload();

    // Unsigned -> OgreSigned -> AgentApproved -> FullyApproved
    let unsigned = SignedRequest::new(payload);
    let ogre_signed = unsigned.sign_ogre(&bundle.ogre);
    let agent_approved = ogre_signed.sign_reviewer(&bundle.reviewer);
    let fully_approved = agent_approved.sign_user(&bundle.user);

    // Verify we can access all 3 signatures
    assert_eq!(fully_approved.ogre_signature().signer, SignerRole::Ogre);
    assert_eq!(
        fully_approved.reviewer_signature().signer,
        SignerRole::Reviewer
    );
    assert_eq!(fully_approved.user_signature().signer, SignerRole::User);
}

#[test]
fn key_bundle_bootstrap() {
    let bundle = KeyBundle::generate();

    // All three keys should be different
    let ogre_pub = bundle.ogre.verifying_key();
    let reviewer_pub = bundle.reviewer.verifying_key();
    let user_pub = bundle.user.verifying_key();

    assert_ne!(ogre_pub.to_bytes(), reviewer_pub.to_bytes());
    assert_ne!(ogre_pub.to_bytes(), user_pub.to_bytes());
    assert_ne!(reviewer_pub.to_bytes(), user_pub.to_bytes());
}

#[test]
fn key_roundtrip() {
    let bundle = KeyBundle::generate();
    let bytes = bundle.ogre.to_bytes();
    let restored = ogre_crypto::keys::OgreKeyPair::from_bytes(&bytes);
    assert_eq!(
        bundle.ogre.verifying_key().to_bytes(),
        restored.verifying_key().to_bytes()
    );
}

#[test]
fn public_key_set_serialization() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);

    let json = serde_json::to_string(&keys).unwrap();
    let restored: PublicKeySet = serde_json::from_str(&json).unwrap();

    assert_eq!(keys.ogre.to_bytes(), restored.ogre.to_bytes());
    assert_eq!(keys.reviewer.to_bytes(), restored.reviewer.to_bytes());
    assert_eq!(keys.user.to_bytes(), restored.user.to_bytes());
}

#[test]
fn empty_signatures_rejected() {
    let bundle = KeyBundle::generate();
    let keys = PublicKeySet::from_bundle(&bundle);
    let verifier = SignatureVerifier::new(keys);

    let payload = test_payload();
    let result = verifier.verify_agent_approved(payload, &[]);
    assert!(result.is_err());
}
