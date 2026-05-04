use std::fmt;

use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{KeyGenError, noise::noise_params};

#[derive(Debug, thiserror::Error)]
#[error("malformed transport key")]
pub struct MalformedKeyError;

// ===========================================================================
// TransportPublicKey
// ===========================================================================

/// The X25519 public key used to authenticate Noise handshakes between nodes.
///
/// Serializes as a lowercase hex string in human-readable formats (TOML, JSON)
/// and as raw 32 bytes in binary formats (postcard).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct TransportPublicKey(pub [u8; 32]);

impl TransportPublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&str> for TransportPublicKey {
    type Error = MalformedKeyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value).map_err(|_| MalformedKeyError)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| MalformedKeyError)?;
        Ok(TransportPublicKey::from(arr))
    }
}

impl From<[u8; 32]> for TransportPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for TransportPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransportPublicKey({})", hex::encode(self.0))
    }
}

impl fmt::Display for TransportPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Serialize for TransportPublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0).serialize(s)
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for TransportPublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let bytes = hex::decode(&s).map_err(de::Error::custom)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| de::Error::custom("TransportPublicKey must be 32 bytes"))?;
            Ok(Self(arr))
        } else {
            Ok(Self(<[u8; 32]>::deserialize(d)?))
        }
    }
}

// ===========================================================================
// TransportPrivateKey
// ===========================================================================

/// The X25519 private key used in Noise handshakes.
///
/// Backed by `secrecy::Secret` which:
///   - Zeroes memory on drop via `zeroize`
///   - Prints `***` in `Debug` output, preventing accidental log leakage
///   - Requires explicit `.expose_secret()` calls at use sites, making
///     key material access visible in code review
///
/// Serializes as a lowercase hex string in human-readable formats (TOML, JSON)
/// and as raw 32 bytes in binary formats (postcard). Serialization is gated
/// behind `ExposeSecret` — only call it when writing config files.
/// 
#[derive(Clone)]
pub struct TransportPrivateKey(Secret<[u8; 32]>);

impl TransportPrivateKey {
    /// Access the raw key bytes. Use sites should be minimal and obvious.
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Encode the key as a lowercase hex string for writing to config files.
    /// Named explicitly to make it obvious at call sites that key material
    /// is being exposed in human-readable form.
    pub fn expose_to_human_string(&self) -> String {
        hex::encode(self.0.expose_secret())
    }
}

impl TryFrom<&str> for TransportPrivateKey {
    type Error = MalformedKeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value).map_err(|_| MalformedKeyError)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| MalformedKeyError)?;
        Ok(TransportPrivateKey::from(arr))
    }
}

impl From<[u8; 32]> for TransportPrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }
}

impl fmt::Debug for TransportPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TransportPrivateKey([redacted])")
    }
}

impl Serialize for TransportPrivateKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0.expose_secret()).serialize(s)
        } else {
            self.0.expose_secret().serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for TransportPrivateKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let bytes = hex::decode(&s).map_err(de::Error::custom)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| de::Error::custom("TransportPrivateKey must be 32 bytes"))?;
            Ok(Self(Secret::new(arr)))
        } else {
            Ok(Self(Secret::new(<[u8; 32]>::deserialize(d)?)))
        }
    }
}

// ===========================================================================
// TransportKeypair
// ===========================================================================

/// A freshly generated X25519 keypair for use in Noise handshakes.
pub struct TransportKeypair {
    pub public: TransportPublicKey,
    pub private: TransportPrivateKey,
}

impl TransportKeypair {
    /// Generate a fresh X25519 keypair. This is the only way to create new
    /// key material — loading existing keys from config goes through the
    /// serde impls on the individual key types.
    pub fn generate() -> Result<Self, KeyGenError> {
        let keypair = snow::Builder::new(noise_params())
            .generate_keypair()
            .map_err(|e| KeyGenError(format!("failed to generate X25519 keypair: {e}")))?;

        let public_bytes: [u8; 32] = keypair
            .public
            .try_into()
            .map_err(|_| KeyGenError("unexpected public key length".to_string()))?;

        let private_bytes: [u8; 32] = keypair
            .private
            .try_into()
            .map_err(|_| KeyGenError("unexpected private key length".to_string()))?;

        Ok(Self {
            public: TransportPublicKey::from(public_bytes),
            private: TransportPrivateKey::from(private_bytes),
        })
    }
}
