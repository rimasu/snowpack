use std::fmt;

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use rand_core::OsRng;
use secrecy::{ExposeSecret, Secret};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{KeyGenError, MalformedKeyError};

/// An error verifying a signed record.
///
/// Returned by [`SignatureVerificationKey::verify_payload`].
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum SignatureValidationErr {
    /// The input is shorter than a signature (64 bytes), so there is no
    /// payload to verify.
    #[error("malformed record")]
    MalformedRecord,

    /// The Ed25519 signature did not verify against the provided key.
    #[error("bad signature")]
    BadSignature,
}

const SIGNATURE_LEN: usize = 64;

// ===========================================================================
// SignatureVerificationKey
// ===========================================================================

/// The ED25519 public key used to verify signed records.
///
/// Serializes as a lowercase hex string in human-readable formats (TOML, JSON)
/// and as raw 32 bytes in binary formats.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SignatureVerificationKey(VerifyingKey);

impl SignatureVerificationKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Verify signature and return the raw payload bytes.
    pub fn verify_payload<'a>(&self, record: &'a [u8]) -> Result<&'a [u8], SignatureValidationErr> {
        if record.len() < SIGNATURE_LEN {
            return Err(SignatureValidationErr::MalformedRecord);
        }
        let payload_len = record.len() - SIGNATURE_LEN;
        let payload = &record[..payload_len];
        let signature_data = &record[payload_len..];
        let signature = Signature::from_slice(signature_data)
            .map_err(|_| SignatureValidationErr::MalformedRecord)?;
        self.0
            .verify_strict(payload, &signature)
            .map_err(|_| SignatureValidationErr::BadSignature)?;
        Ok(payload)
    }
}

impl TryFrom<&str> for SignatureVerificationKey {
    type Error = MalformedKeyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value).map_err(|_| MalformedKeyError)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| MalformedKeyError)?;
        Self::try_from(arr)
    }
}

impl TryFrom<[u8; 32]> for SignatureVerificationKey {
    type Error = MalformedKeyError;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerifyingKey::from_bytes(&bytes)
            .map(SignatureVerificationKey)
            .map_err(|_| MalformedKeyError)
    }
}

impl fmt::Debug for SignatureVerificationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignatureVerificationKey({})",
            hex::encode(self.0.as_bytes())
        )
    }
}

impl fmt::Display for SignatureVerificationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

#[cfg(feature = "serde")]
impl Serialize for SignatureVerificationKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0.as_bytes()).serialize(s)
        } else {
            self.0.as_bytes().serialize(s)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SignatureVerificationKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let arr: [u8; 32] = if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let bytes = hex::decode(&s).map_err(de::Error::custom)?;
            bytes
                .try_into()
                .map_err(|_| de::Error::custom("SignatureVerificationKey must be 32 bytes"))?
        } else {
            <[u8; 32]>::deserialize(d)?
        };

        Self::try_from(arr).map_err(|_| de::Error::custom("malformed key"))
    }
}

// ===========================================================================
// SignatureSigningKey
// ===========================================================================

/// The ED25519 signing key used to produce signed records.
///
/// Backed by `secrecy::Secret` which:
///   - Zeroes memory on drop via `zeroize`
///   - Prints `[redacted]` in `Debug` output, preventing accidental log leakage
///   - Requires explicit `.expose_secret()` calls at use sites, making
///     key material access visible in code review
///
/// Only the 32-byte secret scalar is stored and serialized; the public key is
/// derived from it on construction. Serializes as a lowercase hex string in
/// human-readable formats (TOML, JSON) and as raw 32 bytes in binary formats.
///
/// Clone is intentionally not derived — key material should not be casually
/// copied. Load once from config and pass by reference.
pub struct SignatureSigningKey(Secret<[u8; 32]>);

impl SignatureSigningKey {
    /// Access the raw secret key bytes. Use sites should be minimal and obvious.
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Encode the key as a lowercase hex string for writing to config files.
    /// Named explicitly to make it obvious at call sites that key material
    /// is being exposed in human-readable form.
    pub fn expose_to_human_string(&self) -> String {
        hex::encode(self.0.expose_secret())
    }

    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(self.0.expose_secret());
        let sig = signing_key.sign(payload);
        let mut result = payload.to_vec();
        result.extend(sig.to_bytes());
        result
    }
}

impl From<[u8; 32]> for SignatureSigningKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }
}

impl TryFrom<&str> for SignatureSigningKey {
    type Error = MalformedKeyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value).map_err(|_| MalformedKeyError)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| MalformedKeyError)?;
        Ok(SignatureSigningKey::from(arr))
    }
}

impl fmt::Debug for SignatureSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureSigningKey([redacted])")
    }
}

#[cfg(feature = "serde")]
impl Serialize for SignatureSigningKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0.expose_secret()).serialize(s)
        } else {
            self.0.expose_secret().serialize(s)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SignatureSigningKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let arr: [u8; 32] = if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let bytes = hex::decode(&s).map_err(de::Error::custom)?;
            bytes
                .try_into()
                .map_err(|_| de::Error::custom("SignatureSigningKey must be 32 bytes"))?
        } else {
            <[u8; 32]>::deserialize(d)?
        };

        Ok(Self::from(arr))
    }
}

// ===========================================================================
// SignatureKeypair
// ===========================================================================

/// A freshly generated ED25519 keypair for record signing and verification.
pub struct SignatureKeypair {
    pub public: SignatureVerificationKey,
    pub private: SignatureSigningKey,
}

impl SignatureKeypair {
    /// Generate a fresh ED25519 keypair. This is the only way to create new
    /// key material — loading existing keys from config goes through
    /// `TryFrom<&str>` or (with the `serde` feature) the serde impls.
    pub fn generate() -> Result<Self, KeyGenError> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        let secret_bytes: [u8; 32] = signing_key.to_bytes();

        let public = SignatureVerificationKey::try_from(public_bytes)
            .map_err(|e| KeyGenError(e.to_string()))?;

        Ok(Self {
            public,
            private: SignatureSigningKey::from(secret_bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> SignatureKeypair {
        SignatureKeypair::generate().expect("keypair generation failed")
    }

    // -----------------------------------------------------------------------
    // SignatureKeypair::generate
    // -----------------------------------------------------------------------

    #[test]
    fn generate_produces_distinct_keypairs() {
        let a = keypair();
        let b = keypair();
        assert_ne!(
            a.public.as_bytes(),
            b.public.as_bytes(),
            "freshly generated keypairs must have distinct public keys"
        );
    }

    #[test]
    fn generated_public_key_matches_private() {
        let kp = keypair();
        let derived = SigningKey::from_bytes(kp.private.expose());
        assert_eq!(
            derived.verifying_key().as_bytes(),
            kp.public.as_bytes(),
            "public key derived from secret seed must match stored verification key"
        );
    }

    // -----------------------------------------------------------------------
    // sign / verify_payload — happy path
    // -----------------------------------------------------------------------

    #[test]
    fn sign_verify_payload_round_trip() {
        let kp = keypair();
        let payload = b"hello world";
        let signed = kp.private.sign(payload);
        let recovered = kp.public.verify_payload(&signed).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn sign_length_is_payload_plus_signature() {
        let kp = keypair();
        let payload = b"test";
        let signed = kp.private.sign(payload);
        assert_eq!(signed.len(), payload.len() + SIGNATURE_LEN);
    }

    #[test]
    fn sign_empty_payload() {
        let kp = keypair();
        let signed = kp.private.sign(&[]);
        assert_eq!(signed.len(), SIGNATURE_LEN);
        let recovered = kp.public.verify_payload(&signed).unwrap();
        assert_eq!(recovered, &[] as &[u8]);
    }

    // -----------------------------------------------------------------------
    // verify_payload — rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn verify_payload_rejects_wrong_key() {
        let signer = keypair();
        let other = keypair();
        let signed = signer.private.sign(b"data");
        let result = other.public.verify_payload(&signed);
        assert!(
            matches!(result, Err(SignatureValidationErr::BadSignature)),
            "wrong key must return BadSignature, got: {result:?}"
        );
    }

    #[test]
    fn verify_payload_rejects_empty_input() {
        let kp = keypair();
        assert!(matches!(
            kp.public.verify_payload(&[]),
            Err(SignatureValidationErr::MalformedRecord)
        ));
    }

    #[test]
    fn verify_payload_rejects_input_shorter_than_signature() {
        let kp = keypair();
        let short = vec![0u8; SIGNATURE_LEN - 1];
        assert!(matches!(
            kp.public.verify_payload(&short),
            Err(SignatureValidationErr::MalformedRecord)
        ));
    }

    #[test]
    fn verify_payload_rejects_payload_bit_flip() {
        let kp = keypair();
        let mut signed = kp.private.sign(b"flip");
        signed[0] ^= 0xFF;
        assert!(
            matches!(kp.public.verify_payload(&signed), Err(SignatureValidationErr::BadSignature)),
            "tampered payload must return BadSignature"
        );
    }

    #[test]
    fn verify_payload_rejects_signature_bit_flip() {
        let kp = keypair();
        let mut signed = kp.private.sign(b"flipsig");
        *signed.last_mut().unwrap() ^= 0xFF;
        assert!(matches!(
            kp.public.verify_payload(&signed),
            Err(SignatureValidationErr::BadSignature)
        ));
    }

    // -----------------------------------------------------------------------
    // SignatureVerificationKey — serde
    // -----------------------------------------------------------------------

    #[cfg(feature = "serde")]
    #[test]
    fn verification_key_json_round_trip() {
        let kp = keypair();
        let json = serde_json::to_string(&kp.public).unwrap();

        // Human-readable form must be a 64-char lowercase hex string.
        let hex_str: String = serde_json::from_str(&json).unwrap();
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));

        let restored: SignatureVerificationKey = serde_json::from_str(&json).unwrap();
        assert_eq!(kp.public, restored);
    }

    #[test]
    fn verification_key_from_str_round_trip() {
        let kp = keypair();
        let hex = kp.public.to_string();
        let restored = SignatureVerificationKey::try_from(hex.as_str())
            .expect("TryFrom<&str> failed on valid hex");
        assert_eq!(kp.public, restored);
    }

    #[test]
    fn verification_key_from_str_rejects_bad_hex() {
        assert!(SignatureVerificationKey::try_from("not-hex").is_err());
    }

    #[test]
    fn verification_key_from_str_rejects_wrong_length() {
        let short = "aa".repeat(31);
        assert!(SignatureVerificationKey::try_from(short.as_str()).is_err());
    }

    // -----------------------------------------------------------------------
    // SignatureSigningKey — serde
    // -----------------------------------------------------------------------

    #[cfg(feature = "serde")]
    #[test]
    fn signing_key_json_round_trip() {
        let kp = keypair();
        let json = serde_json::to_string(&kp.private).unwrap();

        // Human-readable form is 64-char hex (32-byte secret only).
        let hex_str: String = serde_json::from_str(&json).unwrap();
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify the restored key produces a blob the original public key accepts.
        let restored: SignatureSigningKey = serde_json::from_str(&json).unwrap();
        let signed = restored.sign(b"test");
        kp.public.verify_payload(&signed).unwrap();
    }

    #[test]
    fn signing_key_expose_to_human_string_round_trip() {
        let kp = keypair();
        let hex = kp.private.expose_to_human_string();
        assert_eq!(hex.len(), 64);
        let restored = SignatureSigningKey::try_from(hex.as_str())
            .expect("TryFrom<&str> failed on valid hex");
        let signed = restored.sign(b"test");
        kp.public.verify_payload(&signed).unwrap();
    }

    #[test]
    fn signing_key_debug_redacts_key_material() {
        let kp = keypair();
        let debug = format!("{:?}", kp.private);
        assert!(
            debug.contains("[redacted]"),
            "debug output must not expose key bytes, got: {debug}"
        );
        let key_hex = kp.private.expose_to_human_string();
        assert!(!debug.contains(&key_hex));
    }
}
