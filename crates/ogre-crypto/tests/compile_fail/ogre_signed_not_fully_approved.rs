/// This test proves that a function requiring FullyApproved cannot accept OgreSigned.
use ogre_crypto::signed_request::{FullyApproved, OgreSigned, SignedRequest};

fn requires_fully_approved(_req: SignedRequest<FullyApproved>) {}

fn main() {
    let request: SignedRequest<OgreSigned> = unreachable!();
    requires_fully_approved(request);
}
