//! # snowpack
//!
//! An authenticated, encrypted transport for long-lived connections between
//! known peers, built on the [Noise protocol framework][noise] (XX pattern,
//! X25519 + AES-GCM + BLAKE2b).
//!
//! ## What snowpack provides
//!
//! - A **Noise XX handshake** that mutually authenticates both peers using
//!   ED25519-signed auth headers carried as handshake payloads. Each peer
//!   proves it holds the private key matching the public key it declares,
//!   and that declaration is signed by a shared cluster key.
//! - A **framed message transport** layered on top of the encrypted channel.
//!   Messages are split into packets of up to 65519 bytes, each tagged with
//!   a 6-bit type discriminant. Up to 64 message types are supported.
//! - **Key and signing utilities** for generating and managing the X25519
//!   transport keypairs and ED25519 cluster signing keypairs needed to
//!   operate the handshake.
//!
//! ## What snowpack does not provide
//!
//! - Multiplexing: one connection carries one ordered stream of messages.
//! - Request/response matching: the caller is responsible for protocol logic
//!   above the message layer.
//! - A specific node identity type: [`NodeId`] is an opaque byte vector.
//!   Callers map their own identity type to and from `NodeId` via [`Into`]
//!   and [`TryFrom`].
//!
//! ## Handshake and identity model
//!
//! Every node has:
//! - An **X25519 transport keypair** ([`TransportKeypair`]) used in the Noise
//!   handshake.
//! - A **signed auth header** ([`SignedAuthHeader`]) containing the node's
//!   [`NodeId`] and transport public key, signed by the cluster's
//!   [`SignatureSigningKey`].
//!
//! During the XX handshake, each peer sends its signed auth header as the
//! handshake payload and verifies the other's against the shared
//! [`SignatureVerificationKey`]. The Noise layer additionally confirms that
//! the static key used in the handshake matches the public key declared in
//! the auth header, preventing impersonation even if an auth header is stolen.
//!
//! ## Quick start
//!
//! ```no_run
//! use snowpack::{
//!     accept, connect,
//!     AuthHeader, SignedAuthHeader,
//!     NodeId, TransportKeypair, SignatureKeypair, SignatureVerificationKey,
//! };
//! use tokio::net::{TcpListener, TcpStream};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate keys (in practice, load these from config).
//! let cluster_keys = SignatureKeypair::generate()?;
//! let transport_keys = TransportKeypair::generate()?;
//! let my_id = NodeId::try_from_bytes(b"node-1".to_vec())?;
//!
//! // Build a signed auth header for this node.
//! let auth = AuthHeader::new(my_id, &transport_keys.public)
//!     .sign(&cluster_keys.private)?;
//!
//! // Server side: accept a connection and recover the peer's NodeId.
//! let listener = TcpListener::bind("0.0.0.0:7000").await?;
//! let (stream, _) = listener.accept().await?;
//! let ((mut tx, mut rx), peer_id): (_, NodeId) = accept(
//!     stream,
//!     &transport_keys.private,
//!     &auth,
//!     &cluster_keys.public,
//! ).await?;
//!
//! // Client side: connect and assert the peer is who we expect.
//! let stream = TcpStream::connect("peer:7000").await?;
//! let expected_peer = NodeId::try_from_bytes(b"node-2".to_vec())?;
//! let (mut tx, mut rx) = connect(
//!     stream,
//!     expected_peer,
//!     &transport_keys.private,
//!     &auth,
//!     &cluster_keys.public,
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security notes
//!
//! - The Noise XX pattern provides mutual authentication and forward secrecy.
//! - Auth header payloads are opaque to snowpack; the caller is responsible
//!   for the contents of [`NodeId`].
//! - Private key material ([`TransportPrivateKey`], [`SignatureSigningKey`])
//!   is wrapped in [`secrecy::Secret`], which zeroes memory on drop and
//!   redacts values in `Debug` output.
//!
//! [noise]: https://noiseprotocol.org

mod auth;
mod messages;
mod node_id;
mod noise;
mod packet_state;
mod packets;
mod sign;

pub use auth::{AuthHeader, BadAuth, MalformedAuthHeader, SignedAuthHeader};
pub use noise::{TransportKeypair, TransportPrivateKey, TransportPublicKey};
pub use messages::{Message, MessagePackets, MessageRx, MessageTx};
pub use node_id::{NodeId, NodeIdTooLong, MAX_NODE_ID_LEN};
pub use packet_state::PacketBuildError;
pub use packet_state::PacketReadError;
pub use packets::ConnectionError;
pub use sign::{SignatureKeypair, SignatureSigningKey, SignatureVerificationKey, SigningErr};

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

/// Complete a Noise XX handshake as the **responder** (server side).
///
/// Verifies the initiator's signed auth header against `verification_key`,
/// confirms the Noise static key matches the one declared in the header,
/// and converts the remote [`NodeId`] to `N` via [`TryFrom`].
///
/// Returns the authenticated message transport halves and the peer's identity.
pub async fn accept<S, N>(
    stream: S,
    local_private: &TransportPrivateKey,
    local_auth_header: &SignedAuthHeader,
    verification_key: &SignatureVerificationKey,
) -> Result<((MessageTx<WriteHalf<S>>, MessageRx<ReadHalf<S>>), N), ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    N: TryFrom<NodeId>,
    N::Error: std::error::Error + Send + Sync + 'static,
{
    let ((tx, rx), node_id) =
        packets::accept(stream, local_private, local_auth_header, verification_key).await?;

    let n = N::try_from(node_id)
        .map_err(|e| ConnectionError::InvalidNodeId(e.to_string()))?;

    Ok(((MessageTx::new(tx), MessageRx::new(rx)), n))
}

/// Complete a Noise XX handshake as the **initiator** (client side).
///
/// Verifies the responder's signed auth header against `verification_key`,
/// confirms the Noise static key matches the one declared in the header,
/// and asserts the authenticated peer identity equals `target`.
///
/// Returns the authenticated message transport halves.
pub async fn connect<S, N>(
    stream: S,
    target: N,
    local_private: &TransportPrivateKey,
    local_auth_header: &SignedAuthHeader,
    verification_key: &SignatureVerificationKey,
) -> Result<(MessageTx<WriteHalf<S>>, MessageRx<ReadHalf<S>>), ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    N: Into<NodeId>,
{
    let (tx, rx) = packets::connect(
        stream,
        target,
        local_private,
        local_auth_header,
        verification_key,
    )
    .await?;
    Ok((MessageTx::new(tx), MessageRx::new(rx)))
}

/// Returned when a key cannot be parsed.
///
/// Produced by the `TryFrom` impls on [`TransportPublicKey`], [`TransportPrivateKey`],
/// [`SignatureVerificationKey`], and [`SignatureSigningKey`] when the hex string is
/// invalid, the byte length is wrong, or (for ED25519 keys) the bytes are not a
/// valid curve point.
#[derive(thiserror::Error, Debug)]
#[error("malformed key")]
pub struct MalformedKeyError;

/// Returned when keypair generation fails.
///
/// Produced by [`TransportKeypair::generate`] and [`SignatureKeypair::generate`].
/// In practice this can only happen if the OS RNG is unavailable or if the
/// Noise builder rejects the generated key material.
#[derive(thiserror::Error, Debug)]
#[error("key gen: {0}")]
pub struct KeyGenError(pub(crate) String);