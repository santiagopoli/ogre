/// This test proves that a function requiring FullyApproved cannot accept AgentApproved.
/// It must FAIL to compile — that's the type-level security guarantee.
use ogre_crypto::signed_request::{AgentApproved, FullyApproved, SignedRequest};

fn requires_fully_approved(_req: SignedRequest<FullyApproved>) {}

fn main() {
    // We use unreachable to get a value of the wrong type without needing real keys.
    // The compiler rejects the type mismatch before evaluating anything.
    let request: SignedRequest<AgentApproved> = unreachable!();
    requires_fully_approved(request);
}
