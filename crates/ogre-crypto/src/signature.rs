use ed25519_dalek::Signature as DalekSignature;
use serde::{Deserialize, Serialize};

/// A wrapper around an Ed25519 signature with signer identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub signer: SignerRole,
    #[serde(with = "signature_serde")]
    pub bytes: DalekSignature,
}

/// Which role produced a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    Ogre,
    Reviewer,
    User,
}

impl std::fmt::Display for SignerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerRole::Ogre => write!(f, "ogre"),
            SignerRole::Reviewer => write!(f, "reviewer"),
            SignerRole::User => write!(f, "user"),
        }
    }
}

mod signature_serde {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Signature, D::Error> {
        let hex = String::deserialize(deserializer)?;
        if hex.len() != 128 {
            return Err(serde::de::Error::custom("signature hex must be 128 chars"));
        }
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect::<Result<_, _>>()?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid signature length"))?;
        Ok(Signature::from_bytes(&arr))
    }
}
