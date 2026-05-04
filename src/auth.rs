use std::{fmt, sync::Arc};

use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    NodeId,
    keys::TransportPublicKey,
    sign::{SignatureSigningKey, SignatureValidationErr, SignatureVerificationKey, SigningErr},
};

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum BadAuth {
    #[error(transparent)]
    Signature(#[from] SignatureValidationErr),

    #[error("public key mismatch (expected: {expected} actual: {actual})")]
    PublicKeyMismatch {
        expected: TransportPublicKey,
        actual: TransportPublicKey,
    },

    #[error("node id mismatch (expected: {expected:?} actual: {actual:?})")]
    NodeIdMismatch { expected: NodeId, actual: NodeId },
}

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
#[error("malformed auth header")]
pub struct MalformedAuthHeader;

/// Auth header
///
/// The signed version of this is used for authentication of the transport connection.
///
/// To support live upgrade, changes to this struct
/// should be performed in a backwards compatible manner.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct AuthHeader {
    node_id: NodeId,
    public_key: TransportPublicKey,
}

impl AuthHeader {
    pub fn new<N: Into<NodeId>>(node_id: N, public_key: &TransportPublicKey) -> Self {
        Self {
            node_id: node_id.into(),
            public_key: public_key.clone(),
        }
    }

    pub fn validate_public_key(&self, key: &TransportPublicKey) -> Result<(), BadAuth> {
        if &self.public_key == key {
            Ok(())
        } else {
            Err(BadAuth::PublicKeyMismatch {
                actual: key.clone(),
                expected: self.public_key.clone(),
            })
        }
    }

    pub fn validate_node_id<N: Into<NodeId>>(&self, node_id: N) -> Result<(), BadAuth> {
        let expected = node_id.into();
        if self.node_id == expected {
            Ok(())
        } else {
            Err(BadAuth::NodeIdMismatch {
                actual: expected,
                expected: self.node_id.clone(),
            })
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}

impl AuthHeader {
    pub fn sign(&self, signing_key: &SignatureSigningKey) -> Result<SignedAuthHeader, SigningErr> {
        signing_key
            .sign(self)
            .map(|raw| SignedAuthHeader(Arc::new(SecretVec::new(raw))))
    }
}

#[derive(Clone)]
pub struct SignedAuthHeader(Arc<SecretVec<u8>>);

impl SignedAuthHeader {
    pub fn verify(&self, key: &SignatureVerificationKey) -> Result<AuthHeader, BadAuth> {
        Self::verify_raw(key, self.0.expose_secret())
    }

    /// Verifies a raw byte slice directly, for use when the signed header
    /// arrives as a noise handshake payload buffer rather than a typed instance.
    pub fn verify_raw(key: &SignatureVerificationKey, data: &[u8]) -> Result<AuthHeader, BadAuth> {
        Ok(key.verify(data)?)
    }

    pub fn expose(&self) -> &[u8] {
        self.0.expose_secret()
    }
    
    /// Returns the signed header as a lowercase hex string for storing in a
    /// human-readable config file.
    ///
    /// This is a credential — store and transmit it with appropriate care.
    pub fn expose_to_human_string(&self) -> String {
        hex::encode(self.0.expose_secret())
    }
}

impl TryFrom<&str> for SignedAuthHeader {
    type Error = MalformedAuthHeader;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        hex::decode(value)
            .map(|a| SignedAuthHeader(Arc::new(SecretVec::new(a))))
            .map_err(|_| MalformedAuthHeader)
    }
}

impl fmt::Debug for SignedAuthHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignedAuthHeader([redacted])")
    }
}

impl Serialize for SignedAuthHeader {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0.expose_secret()).serialize(s)
        } else {
            self.0.expose_secret().serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for SignedAuthHeader {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let bytes = hex::decode(&s).map_err(de::Error::custom)?;
            Ok(Self(Arc::new(SecretVec::new(bytes))))
        } else {
            let bytes = Vec::<u8>::deserialize(d)?;
            Ok(Self(Arc::new(SecretVec::new(bytes))))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        NodeId,
        auth::{AuthHeader, BadAuth, MalformedAuthHeader, SignedAuthHeader},
        keys::TransportPublicKey,
        sign::{SignatureKeypair, SignatureValidationErr},
    };

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn cluster_keypair() -> SignatureKeypair {
        SignatureKeypair::generate().unwrap()
    }

    fn transport_public_key() -> TransportPublicKey {
        TransportPublicKey::from([1u8; 32])
    }

    fn auth_header(node_id: u32) -> AuthHeader {
        AuthHeader::new(node_id, &transport_public_key())
    }

    fn signed(node_id: u32) -> (SignatureKeypair, SignedAuthHeader) {
        let kp = cluster_keypair();
        let header = auth_header(node_id);
        let signed = header.sign(&kp.private).expect("sign failed");
        (kp, signed)
    }

    // -----------------------------------------------------------------------
    // AuthHeader::validate_public_key
    // -----------------------------------------------------------------------

    #[test]
    fn validate_public_key_accepts_matching_key() {
        let key = transport_public_key();
        let header = auth_header(1);
        assert!(header.validate_public_key(&key).is_ok());
    }

    #[test]
    fn validate_public_key_rejects_wrong_key() {
        let header = auth_header(1);
        let wrong = TransportPublicKey::from([2u8; 32]);

        let err = header.validate_public_key(&wrong).unwrap_err();
        assert!(
            matches!(err, BadAuth::PublicKeyMismatch { .. }),
            "expected PublicKeyMismatch, got: {err:?}"
        );
    }

    #[test]
    fn validate_public_key_mismatch_contains_both_keys() {
        let header = auth_header(1);
        let wrong = TransportPublicKey::from([2u8; 32]);

        let BadAuth::PublicKeyMismatch { expected, actual } =
            header.validate_public_key(&wrong).unwrap_err()
        else {
            panic!("expected PublicKeyMismatch variant");
        };

        assert_eq!(expected, transport_public_key());
        assert_eq!(actual, wrong);
    }

    // -----------------------------------------------------------------------
    // AuthHeader::validate_node_id
    // -----------------------------------------------------------------------

    #[test]
    fn validate_node_id_accepts_matching_id() {
        let header = auth_header(42);
        assert!(header.validate_node_id(42u32).is_ok());
    }

    #[test]
    fn validate_node_id_rejects_wrong_id() {
        let header = auth_header(42);

        let err = header.validate_node_id(99u32).unwrap_err();
        assert!(
            matches!(err, BadAuth::NodeIdMismatch { .. }),
            "expected NodeIdMismatch, got: {err:?}"
        );
    }

    #[test]
    fn validate_node_id_mismatch_contains_both_ids() {
        let header = auth_header(42);

        let BadAuth::NodeIdMismatch { expected, actual } =
            header.validate_node_id(99u32).unwrap_err()
        else {
            panic!("expected NodeIdMismatch variant");
        };

        assert_eq!(expected, NodeId::from(42u32));
        assert_eq!(actual, NodeId::from(99u32));
    }

    // -----------------------------------------------------------------------
    // AuthHeader::node_id
    // -----------------------------------------------------------------------

    #[test]
    fn node_id_returns_correct_value() {
        assert_eq!(auth_header(7u32).node_id(), &NodeId::from(7u32));
    }

    // -----------------------------------------------------------------------
    // AuthHeader::sign + SignedAuthHeader::verify — happy path
    // -----------------------------------------------------------------------

    #[test]
    fn sign_and_verify_round_trip() {
        let (kp, signed) = signed(1);
        let recovered = signed.verify(&kp.public).expect("verify failed");

        assert_eq!(recovered.node_id(), &NodeId::from(1u32));
        assert!(
            recovered
                .validate_public_key(&transport_public_key())
                .is_ok()
        );
    }

    #[test]
    fn verify_raw_round_trip() {
        let (kp, signed) = signed(2);
        let raw = signed.expose().to_vec();

        let recovered = SignedAuthHeader::verify_raw(&kp.public, &raw).expect("verify_raw failed");
        assert_eq!(recovered.node_id(), &NodeId::from(2u32));
    }

    #[test]
    fn verify_raw_and_verify_are_equivalent() {
        let (kp, signed) = signed(3);
        let raw = signed.expose().to_vec();

        let via_method = signed.verify(&kp.public).unwrap();
        let via_raw = SignedAuthHeader::verify_raw(&kp.public, &raw).unwrap();

        assert_eq!(via_method.node_id(), via_raw.node_id());
    }

    // -----------------------------------------------------------------------
    // SignedAuthHeader::verify — rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn verify_rejects_wrong_cluster_key() {
        let (_, signed) = signed(1);
        let other_kp = cluster_keypair();

        let err = signed.verify(&other_kp.public).unwrap_err();
        assert!(
            matches!(
                err,
                BadAuth::Signature(SignatureValidationErr::BadSignature)
            ),
            "wrong key must produce BadSignature, got: {err:?}"
        );
    }

    #[test]
    fn verify_raw_rejects_empty_input() {
        let (kp, _) = signed(1);
        let err = SignedAuthHeader::verify_raw(&kp.public, &[]).unwrap_err();
        assert!(
            matches!(
                err,
                BadAuth::Signature(SignatureValidationErr::MalformedRecord)
            ),
            "empty input must produce MalformedRecord, got: {err:?}"
        );
    }

    #[test]
    fn verify_raw_rejects_payload_bit_flip() {
        let (kp, signed) = signed(1);
        let mut raw = signed.expose().to_vec();
        raw[0] ^= 0xFF;

        let err = SignedAuthHeader::verify_raw(&kp.public, &raw).unwrap_err();
        assert!(
            matches!(
                err,
                BadAuth::Signature(SignatureValidationErr::BadSignature)
            ),
            "tampered payload must produce BadSignature, got: {err:?}"
        );
    }

    #[test]
    fn verify_raw_rejects_signature_bit_flip() {
        let (kp, signed) = signed(1);
        let mut raw = signed.expose().to_vec();
        *raw.last_mut().unwrap() ^= 0xFF;

        let err = SignedAuthHeader::verify_raw(&kp.public, &raw).unwrap_err();
        assert!(
            matches!(
                err,
                BadAuth::Signature(SignatureValidationErr::BadSignature)
            ),
            "tampered signature must produce BadSignature, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // SignedAuthHeader::expose
    // -----------------------------------------------------------------------

    #[test]
    fn expose_returns_non_empty_bytes() {
        let (_, signed) = signed(1);
        assert!(!signed.expose().is_empty());
    }

    #[test]
    fn expose_bytes_are_stable_across_calls() {
        let (_, signed) = signed(1);
        assert_eq!(signed.expose(), signed.expose());
    }

    // -----------------------------------------------------------------------
    // SignedAuthHeader::Debug redaction
    // -----------------------------------------------------------------------

    #[test]
    fn debug_redacts_credential_bytes() {
        let (_, signed) = signed(1);
        let debug = format!("{signed:?}");

        assert!(
            debug.contains("[redacted]"),
            "debug must not expose credential bytes, got: {debug}"
        );
        assert!(
            !debug.contains(&hex::encode(signed.expose())),
            "hex of credential bytes must not appear in debug output"
        );
    }

    // -----------------------------------------------------------------------
    // SignedAuthHeader serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn signed_auth_header_json_round_trip() {
        let (kp, signed) = signed(1);
        let original_bytes = signed.expose().to_vec();

        let json = serde_json::to_string(&signed).expect("serialize failed");

        // Human-readable form must be a lowercase hex string.
        let hex_str: String = serde_json::from_str(&json).unwrap();
        assert!(
            hex_str.chars().all(|c| c.is_ascii_hexdigit()),
            "JSON form must be hex, got: {hex_str}"
        );

        let restored: SignedAuthHeader = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(restored.expose(), original_bytes);

        // Restored credential must still verify correctly.
        restored
            .verify(&kp.public)
            .expect("restored credential failed to verify");
    }

    #[test]
    fn signed_auth_header_postcard_round_trip() {
        let (kp, signed) = signed(1);
        let original_bytes = signed.expose().to_vec();

        let encoded = postcard::to_allocvec(&signed).expect("serialize failed");
        let restored: SignedAuthHeader =
            postcard::from_bytes(&encoded).expect("deserialize failed");

        assert_eq!(restored.expose(), original_bytes);
        restored
            .verify(&kp.public)
            .expect("restored credential failed to verify");
    }

    // -----------------------------------------------------------------------
    // TryFrom<&str>
    // -----------------------------------------------------------------------

    #[test]
    fn try_from_str_round_trip() {
        let (kp, signed) = signed(1);
        let hex = hex::encode(signed.expose());

        let restored =
            SignedAuthHeader::try_from(hex.as_str()).expect("TryFrom<&str> failed on valid hex");

        restored
            .verify(&kp.public)
            .expect("restored credential failed to verify");
    }

    #[test]
    fn try_from_str_rejects_bad_hex() {
        let err = SignedAuthHeader::try_from("not-valid-hex").unwrap_err();
        assert_eq!(err, MalformedAuthHeader);
    }

    #[test]
    fn try_from_str_rejects_empty_string() {
        // Empty hex decodes to empty bytes — valid hex but will fail at verify
        // time, not construction time. Construction itself should succeed.
        let result = SignedAuthHeader::try_from("");
        assert!(
            result.is_ok(),
            "empty string is valid hex (decodes to empty vec)"
        );
    }

    // -----------------------------------------------------------------------
    // Cross-node scenario: different node IDs in same cluster
    // -----------------------------------------------------------------------

    #[test]
    fn different_node_ids_produce_distinct_credentials() {
        let kp = cluster_keypair();
        let key = transport_public_key();

        let header_a = AuthHeader::new(NodeId::from(1u32), &key);
        let header_b = AuthHeader::new(NodeId::from(2u32), &key);

        let signed_a = header_a.sign(&kp.private).unwrap();
        let signed_b = header_b.sign(&kp.private).unwrap();

        // Credentials must differ even with the same transport key.
        assert_ne!(signed_a.expose(), signed_b.expose());

        // Each verifies to the correct node id.
        assert_eq!(
            signed_a.verify(&kp.public).unwrap().node_id(),
            &NodeId::from(1u32)
        );
        assert_eq!(
            signed_b.verify(&kp.public).unwrap().node_id(),
            &NodeId::from(2u32)
        );
    }

    #[test]
    fn credential_from_node_a_does_not_validate_as_node_b() {
        let kp = cluster_keypair();
        let key = transport_public_key();

        let signed_a = AuthHeader::new(NodeId::from(1u32), &key)
            .sign(&kp.private)
            .unwrap();
        let recovered = signed_a.verify(&kp.public).unwrap();

        // Verifies fine, but node id check catches the mismatch.
        assert_eq!(
            recovered.validate_node_id(NodeId::from(2u32)),
            Err(BadAuth::NodeIdMismatch {
                expected: 1u32.into(),
                actual: 2u32.into()
            })
        );
    }
}
