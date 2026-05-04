use serde::{Deserialize, Serialize};



/// Maximum length of a serialized NodeId. This is not a security boundary —
/// the Noise handshake caps message size at 65535 bytes regardless — but
/// prevents accidental misconfiguration with oversized identities.
pub const MAX_NODE_ID_LEN: usize = 512;

#[derive(thiserror::Error, Debug)]
#[error("node id too long: {0}")]
pub struct NodeIdTooLong (usize);

/// Unique identifier for a node (either local or remote).
/// 
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