/// This test proves that a function requiring AgentApproved cannot accept Unsigned.
use ogre_crypto::signed_request::{AgentApproved, SignedRequest, Unsigned};

fn requires_agent_approved(_req: SignedRequest<AgentApproved>) {}

fn main() {
    let request: SignedRequest<Unsigned> = unreachable!();
    requires_agent_approved(request);
}
