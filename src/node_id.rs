use serde::{Deserialize, Serialize};



/// Maximum length of a serialized NodeId. This is not a security boundary —
/// the Noise handshake caps message size at 65535 bytes regardless — but
/// prevents accidental misconfiguration with oversized identities.
pub const MAX_NODE_ID_LEN: usize = 512;

/// Returned by [`NodeId::try_from_bytes`] when the byte vector exceeds
/// [`MAX_NODE_ID_LEN`]. The inner value is the rejected length.
#[derive(thiserror::Error, Debug)]
#[error("node id too long: {0}")]
pub struct NodeIdTooLong(usize);

/// Opaque byte string that uniquely identifies a node in the cluster.
///
/// Constructed from a raw byte vector via [`NodeId::try_from_bytes`] (bounded
/// to [`MAX_NODE_ID_LEN`] bytes), or from integer types via the `From<u32>` and
/// `From<u64>` impls (big-endian encoded). Snowpack treats the bytes as opaque;
/// callers are responsible for choosing a globally unique identity scheme.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct NodeId(Vec<u8>);


impl NodeId {
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, NodeIdTooLong> {
        if bytes.len() > MAX_NODE_ID_LEN {
            Err(NodeIdTooLong(bytes.len()))
        } else {
            Ok(Self(bytes))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<u64> for NodeId {
    fn from(value: u64) -> Self {
        NodeId(value.to_be_bytes().to_vec())
    }
}

impl From<u32> for NodeId {
    fn from(value: u32) -> Self {
        NodeId(value.to_be_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_bytes_accepts_empty() {
        assert!(NodeId::try_from_bytes(vec![]).is_ok());
    }

    #[test]
    fn try_from_bytes_accepts_max_length() {
        let bytes = vec![0xABu8; MAX_NODE_ID_LEN];
        let id = NodeId::try_from_bytes(bytes.clone()).unwrap();
        assert_eq!(id.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn try_from_bytes_rejects_over_max() {
        let err = NodeId::try_from_bytes(vec![0u8; MAX_NODE_ID_LEN + 1]).unwrap_err();
        assert_eq!(err.0, MAX_NODE_ID_LEN + 1);
    }

    #[test]
    fn as_bytes_returns_original() {
        let bytes = vec![1u8, 2, 3, 4];
        let id = NodeId::try_from_bytes(bytes.clone()).unwrap();
        assert_eq!(id.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn from_u64_is_big_endian() {
        let id = NodeId::from(0x0102030405060708u64);
        assert_eq!(id.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn from_u32_is_big_endian() {
        let id = NodeId::from(0x01020304u32);
        assert_eq!(id.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn equality_same_bytes() {
        assert_eq!(NodeId::from(42u32), NodeId::from(42u32));
    }

    #[test]
    fn equality_different_bytes() {
        assert_ne!(NodeId::from(1u32), NodeId::from(2u32));
    }

    #[test]
    fn u32_and_u64_with_same_numeric_value_differ() {
        // 1u32 → 4 bytes, 1u64 → 8 bytes — must not be equal
        assert_ne!(NodeId::from(1u32), NodeId::from(1u64));
    }
}