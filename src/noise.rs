use std::fmt;
use std::sync::OnceLock;

use secrecy::{ExposeSecret, Secret};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use snow::params::NoiseParams;

use crate::{KeyGenError, MalformedKeyError};

// ---------------------------------------------------------------------------
// Noise protocol parameters
// ---------------------------------------------------------------------------

const NOISE_PARAMS: &str = "Noise_XX_25519_AESGCM_BLAKE2b";

static NOISE_PARAMS_PARSED: OnceLock<NoiseParams> = OnceLock::new();

pub(crate) fn noise_params() -> NoiseParams {
    NOISE_PARAMS_PARSED
        .get_or_init(|| NOISE_PARAMS.parse().unwrap())
        .clone()
}

// ===========================================================================
// TransportPublicKey
// ===========================================================================

/// The X25519 public key used to authenticate Noise handshakes between nodes.
///
/// Serializes as a lowercase hex string in human-readable formats (TOML, JSON)
/// and as raw 32 bytes in binary formats.
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

#[cfg(feature = "serde")]
impl Serialize for TransportPublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0).serialize(s)
        } else {
            self.0.serialize(s)
        }
    }
}

#[cfg(feature = "serde")]
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
///   - Prints `[redacted]` in `Debug` output, preventing accidental log leakage
///   - Requires explicit `.expose_secret()` calls at use sites, making
///     key material access visible in code review
///
/// Serializes as a lowercase hex string in human-readable formats (TOML, JSON)
/// and as raw 32 bytes in binary formats. Serialization is gated
/// behind `ExposeSecret` — only call it when writing config files.
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

#[cfg(feature = "serde")]
impl Serialize for TransportPrivateKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0.expose_secret()).serialize(s)
        } else {
            self.0.expose_secret().serialize(s)
        }
    }
}

#[cfg(feature = "serde")]
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
    /// key material — loading existing keys from config goes through
    /// `TryFrom<&str>` or (with the `serde` feature) the serde impls.
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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // TransportKeypair
    // -----------------------------------------------------------------------

    #[test]
    fn generate_produces_distinct_keypairs() {
        let a = TransportKeypair::generate().unwrap();
        let b = TransportKeypair::generate().unwrap();
        assert_ne!(a.public.0, b.public.0);
    }

    #[test]
    fn generate_produces_non_zero_keys() {
        let kp = TransportKeypair::generate().unwrap();
        assert_ne!(kp.public.0, [0u8; 32]);
        assert_ne!(*kp.private.expose(), [0u8; 32]);
    }

    // -----------------------------------------------------------------------
    // TransportPublicKey
    // -----------------------------------------------------------------------

    #[test]
    fn public_key_from_array_round_trips_via_as_bytes() {
        let bytes = [0x42u8; 32];
        let key = TransportPublicKey::from(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn public_key_display_is_lowercase_hex() {
        let key = TransportPublicKey::from([0xABu8; 32]);
        let s = key.to_string();
        assert_eq!(s.len(), 64);
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn public_key_debug_includes_hex() {
        let key = TransportPublicKey::from([0x01u8; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("TransportPublicKey("));
        assert!(debug.contains("0101"));
    }

    #[test]
    fn public_key_try_from_str_round_trip() {
        let key = TransportPublicKey::from([0x12u8; 32]);
        let restored = TransportPublicKey::try_from(key.to_string().as_str()).unwrap();
        assert_eq!(restored, key);
    }

    #[test]
    fn public_key_try_from_str_rejects_bad_hex() {
        assert!(TransportPublicKey::try_from("not-hex").is_err());
    }

    #[test]
    fn public_key_try_from_str_rejects_wrong_length() {
        assert!(TransportPublicKey::try_from("ab".repeat(31).as_str()).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn public_key_json_round_trip() {
        let key = TransportPublicKey::from([0x99u8; 32]);
        let json = serde_json::to_string(&key).unwrap();
        let hex_str: String = serde_json::from_str(&json).unwrap();
        assert_eq!(hex_str, "99".repeat(32));
        let restored: TransportPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, key);
    }

    // -----------------------------------------------------------------------
    // TransportPrivateKey
    // -----------------------------------------------------------------------

    #[test]
    fn private_key_expose_returns_original_bytes() {
        let bytes = [0x77u8; 32];
        let key = TransportPrivateKey::from(bytes);
        assert_eq!(key.expose(), &bytes);
    }

    #[test]
    fn private_key_expose_to_human_string_is_lowercase_hex() {
        let key = TransportPrivateKey::from([0xFFu8; 32]);
        assert_eq!(key.expose_to_human_string(), "ff".repeat(32));
    }

    #[test]
    fn private_key_debug_redacts_key_material() {
        let key = TransportPrivateKey::from([0x55u8; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("55"));
    }

    #[test]
    fn private_key_try_from_str_round_trip() {
        let bytes = [0xCCu8; 32];
        let key = TransportPrivateKey::from(bytes);
        let restored = TransportPrivateKey::try_from(key.expose_to_human_string().as_str()).unwrap();
        assert_eq!(restored.expose(), &bytes);
    }

    #[test]
    fn private_key_try_from_str_rejects_bad_hex() {
        assert!(TransportPrivateKey::try_from("gg").is_err());
    }

    #[test]
    fn private_key_try_from_str_rejects_wrong_length() {
        assert!(TransportPrivateKey::try_from("aa".repeat(31).as_str()).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn private_key_json_round_trip() {
        let bytes = [0x11u8; 32];
        let key = TransportPrivateKey::from(bytes);
        let json = serde_json::to_string(&key).unwrap();
        let restored: TransportPrivateKey = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.expose(), &bytes);
    }
}
