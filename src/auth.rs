use std::{fmt, sync::Arc};

use secrecy::{ExposeSecret, SecretVec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use yatlv::{FrameBuilder, FrameBuilderLike, FrameParser};

use crate::{
    NodeId,
    noise::TransportPublicKey,
    sign::{SignatureSigningKey, SignatureValidationErr, SignatureVerificationKey},
};

const TAG_NODE_ID: u16 = 1;
const TAG_PUBLIC_KEY: u16 = 2;
const TAG_ROLE: u16 = 3;

/// An authentication failure during the Noise XX handshake.
///
/// Covers three distinct failure modes: a bad cluster signature, a static-key
/// mismatch (the Noise static key does not match the key declared in the auth
/// header), and a node-identity mismatch (the authenticated peer is not who
/// the caller expected).
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

/// Returned when a hex string cannot be decoded into a [`SignedAuthHeader`].
///
/// The bytes are not validated at construction time — signature and identity
/// checks are deferred to [`SignedAuthHeader::verify`].
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
#[error("malformed auth header")]
pub struct MalformedAuthHeader;


/// Details returned when a successful connection is established.
///
/// The caller is responsible for making appropriate checks on these details
/// before trusting the connection. During discovery this may be how the peer's
/// identity is first learned; when reconnecting the caller should verify it
/// matches the expected peer.
#[must_use = "check the authenticated peer details before using the connection"]
#[derive(Debug, PartialEq)]
pub struct AuthDetails {
    pub node_id: NodeId,
    pub role: Option<Vec<u8>>,
}

impl AuthDetails {
    /// Verify the authenticated peer's node id matches `expected`.
    ///
    /// Use this when reconnecting to a known peer. During initial discovery,
    /// read [`node_id`][AuthDetails::node_id] directly to learn the peer's identity.
    pub fn check_node_id<N: Into<NodeId>>(&self, expected: N) -> Result<(), BadAuth> {
        let expected = expected.into();
        if self.node_id == expected {
            Ok(())
        } else {
            Err(BadAuth::NodeIdMismatch {
                expected,
                actual: self.node_id.clone(),
            })
        }
    }
}

impl From<AuthHeader> for AuthDetails {
    fn from(value: AuthHeader) -> Self {
        AuthDetails {
            node_id: value.node_id,
            role: value.role,
        }
    }
}

/// The identity and transport public key of a node, used to authenticate Noise handshakes.
///
/// Built by the node operator and signed with the cluster's [`SignatureSigningKey`] via
/// [`sign`][AuthHeader::sign] to produce a [`SignedAuthHeader`]. The signed header is
/// carried as a payload in the Noise XX handshake; the receiving peer verifies the
/// signature against the cluster [`SignatureVerificationKey`] and confirms the declared
/// public key matches the Noise static key to rule out header replay.
///
/// Serialized as a yatlv frame (tag 1 = node_id bytes, tag 2 = public key bytes).
/// Adding new tags in future is forwards-compatible; existing signed headers remain valid.
#[derive(Eq, PartialEq, Debug)]
pub struct AuthHeader {
    node_id: NodeId,
    role: Option<Vec<u8>>,
    public_key: TransportPublicKey,
}

impl AuthHeader {
    pub fn new<N: Into<NodeId>>(node_id: N, role: Option<&[u8]>, public_key: &TransportPublicKey) -> Self {
        Self {
            node_id: node_id.into(),
            role: role.map(|r| r.to_vec()),
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
}

impl AuthHeader {
    fn to_yatlv(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut bld = FrameBuilder::new(&mut buf);
            bld.add_data(TAG_NODE_ID, self.node_id.as_bytes());
            bld.add_data(TAG_PUBLIC_KEY, self.public_key.as_bytes());
            if let Some(role) = &self.role {
                bld.add_data(TAG_ROLE, role)
            }
        }
        buf
    }

    fn from_yatlv(data: &[u8]) -> Result<Self, MalformedAuthHeader> {
        let parser = FrameParser::new(data).map_err(|_| MalformedAuthHeader)?;
        let node_id_bytes = parser.get_data(TAG_NODE_ID).map_err(|_| MalformedAuthHeader)?;
        let public_key_bytes = parser.get_data(TAG_PUBLIC_KEY).map_err(|_| MalformedAuthHeader)?;
        let role = parser.get_optional_data(TAG_ROLE).map(|r| r.to_vec());
        let node_id = NodeId::try_from_bytes(node_id_bytes.to_vec()).map_err(|_| MalformedAuthHeader)?;
        let public_key_arr: [u8; 32] = public_key_bytes.try_into().map_err(|_| MalformedAuthHeader)?;
        Ok(AuthHeader {
            node_id,
            role,
            public_key: TransportPublicKey(public_key_arr),
        })
    }

    pub fn sign(&self, signing_key: &SignatureSigningKey) -> SignedAuthHeader {
        let payload = self.to_yatlv();
        let raw = signing_key.sign(&payload);
        SignedAuthHeader(Arc::new(SecretVec::new(raw)))
    }
}

/// A signed [`AuthHeader`] carried as the payload of a Noise XX handshake message.
///
/// Produced by [`AuthHeader::sign`] and verified by [`SignedAuthHeader::verify`].
/// The raw bytes are wrapped in [`secrecy::SecretVec`] and redacted in `Debug`
/// output; use [`expose`][SignedAuthHeader::expose] or
/// [`expose_to_human_string`][SignedAuthHeader::expose_to_human_string]
/// where the bytes must be accessed explicitly.
#[derive(Clone)]
pub struct SignedAuthHeader(Arc<SecretVec<u8>>);

impl SignedAuthHeader {
    pub fn verify(&self, key: &SignatureVerificationKey) -> Result<AuthHeader, BadAuth> {
        Self::verify_raw(key, self.0.expose_secret())
    }

    /// Verifies a raw byte slice directly, for use when the signed header
    /// arrives as a noise handshake payload buffer rather than a typed instance.
    pub fn verify_raw(key: &SignatureVerificationKey, data: &[u8]) -> Result<AuthHeader, BadAuth> {
        let payload = key.verify_payload(data)?;
        AuthHeader::from_yatlv(payload)
            .map_err(|_| BadAuth::Signature(SignatureValidationErr::MalformedRecord))
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

#[cfg(feature = "serde")]
impl Serialize for SignedAuthHeader {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0.expose_secret()).serialize(s)
        } else {
            self.0.expose_secret().serialize(s)
        }
    }
}

#[cfg(feature = "serde")]
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
        auth::{AuthDetails, AuthHeader, BadAuth, MalformedAuthHeader, SignedAuthHeader},
        noise::TransportPublicKey,
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
        AuthHeader::new(node_id, None, &transport_public_key())
    }

    fn auth_header_with_role(node_id: u32, role: &[u8]) -> AuthHeader {
        AuthHeader::new(node_id, Some(role), &transport_public_key())
    }

    fn signed(node_id: u32) -> (SignatureKeypair, SignedAuthHeader) {
        let kp = cluster_keypair();
        let header = auth_header(node_id);
        let signed = header.sign(&kp.private);
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
    // AuthHeader::node_id
    // -----------------------------------------------------------------------

    #[test]
    fn node_id_returns_correct_value() {
        let header = auth_header(7u32);
        let details: AuthDetails = header.into();
        assert_eq!(details.node_id, NodeId::from(7u32));
    }


    #[test]
    fn role_returns_correct_value_when_empty() {
        let header = auth_header(7u32);
        let details: AuthDetails = header.into();
        assert_eq!(details.role, None);
    }

    #[test]
    fn role_returns_correct_value_when_set() {
        let header = auth_header_with_role(7u32, &[9u8]);
        let details: AuthDetails = header.into();
        assert_eq!(details.role, Some(vec![9u8]));
    }


    // -----------------------------------------------------------------------
    // AuthHeader::sign + SignedAuthHeader::verify — happy path
    // -----------------------------------------------------------------------

    #[test]
    fn sign_and_verify_round_trip() {
        let (kp, signed) = signed(1);
        let recovered = signed.verify(&kp.public).expect("verify failed");
        
        assert!(
            recovered
                .validate_public_key(&transport_public_key())
                .is_ok()
        );

        let details: AuthDetails = recovered.into();
        assert_eq!(details.node_id, NodeId::from(1u32));
    }

    #[test]
    fn verify_raw_round_trip() {
        let (kp, signed) = signed(2);
        let raw = signed.expose().to_vec();

        let recovered = SignedAuthHeader::verify_raw(&kp.public, &raw).expect("verify_raw failed");

        let details: AuthDetails = recovered.into();
        assert_eq!(details.node_id, NodeId::from(2u32));
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

    #[cfg(feature = "serde")]
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

        let header_a = AuthHeader::new(NodeId::from(1u32), None, &key);
        let header_b = AuthHeader::new(NodeId::from(2u32), None, &key);

        let signed_a = header_a.sign(&kp.private);
        let signed_b = header_b.sign(&kp.private);

        // Credentials must differ even with the same transport key.
        assert_ne!(signed_a.expose(), signed_b.expose());

        let auth_a: AuthDetails = signed_a.verify(&kp.public).unwrap().into();
        let auth_b: AuthDetails = signed_b.verify(&kp.public).unwrap().into();

        // Each verifies to the correct node id.
        assert_eq!(
            auth_a.node_id,
            NodeId::from(1u32)
        );
        assert_eq!(
            auth_b.node_id,
            NodeId::from(2u32)
        );
    }

    #[test]
    fn check_node_id_rejects_wrong_peer() {
        let kp = cluster_keypair();
        let key = transport_public_key();

        let signed_a = AuthHeader::new(NodeId::from(1u32), None, &key)
            .sign(&kp.private);
        let details: AuthDetails = signed_a.verify(&kp.public).unwrap().into();

        assert_eq!(
            details.check_node_id(NodeId::from(2u32)),
            Err(BadAuth::NodeIdMismatch {
                expected: 2u32.into(),
                actual: 1u32.into(),
            })
        );
    }

    #[test]
    fn check_node_id_accepts_correct_peer() {
        let kp = cluster_keypair();
        let key = transport_public_key();

        let signed_a = AuthHeader::new(NodeId::from(1u32),  None, &key)
            .sign(&kp.private);
        let details: AuthDetails = signed_a.verify(&kp.public).unwrap().into();

        assert!(details.check_node_id(NodeId::from(1u32)).is_ok());
    }
}
