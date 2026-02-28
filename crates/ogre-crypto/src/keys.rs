use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// A keypair wrapper that holds both signing (private) and verifying (public) keys.
macro_rules! define_keypair {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            signing: SigningKey,
        }

        impl $name {
            pub fn generate() -> Self {
                Self {
                    signing: SigningKey::generate(&mut OsRng),
                }
            }

            pub fn from_bytes(bytes: &[u8; 32]) -> Self {
                Self {
                    signing: SigningKey::from_bytes(bytes),
                }
            }

            pub fn signing_key(&self) -> &SigningKey {
                &self.signing
            }

            pub fn verifying_key(&self) -> VerifyingKey {
                self.signing.verifying_key()
            }

            pub fn to_bytes(&self) -> [u8; 32] {
                self.signing.to_bytes()
            }
        }
    };
}

define_keypair!(OgreKeyPair, "The Ogre agent's keypair.");
define_keypair!(ReviewerKeyPair, "The Reviewer agent's keypair.");
define_keypair!(UserKeyPair, "The user's keypair.");

/// All three keypairs generated during bootstrap.
pub struct KeyBundle {
    pub ogre: OgreKeyPair,
    pub reviewer: ReviewerKeyPair,
    pub user: UserKeyPair,
}

impl KeyBundle {
    /// Generate all three keypairs at once. Called during system bootstrap.
    pub fn generate() -> Self {
        Self {
            ogre: OgreKeyPair::generate(),
            reviewer: ReviewerKeyPair::generate(),
            user: UserKeyPair::generate(),
        }
    }
}

/// The public keys for all signers, used by the proxy for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeySet {
    #[serde(with = "verifying_key_serde")]
    pub ogre: VerifyingKey,
    #[serde(with = "verifying_key_serde")]
    pub reviewer: VerifyingKey,
    #[serde(with = "verifying_key_serde")]
    pub user: VerifyingKey,
}

impl PublicKeySet {
    pub fn from_bundle(bundle: &KeyBundle) -> Self {
        Self {
            ogre: bundle.ogre.verifying_key(),
            reviewer: bundle.reviewer.verifying_key(),
            user: bundle.user.verifying_key(),
        }
    }
}

mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = key.to_bytes();
        let hex = hex_encode(&bytes);
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<VerifyingKey, D::Error> {
        let hex = String::deserialize(deserializer)?;
        let bytes = hex_decode(&hex).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))?;
        VerifyingKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
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
}
