//! # snowpack
//!
//! An authenticated, encrypted transport for long-lived connections between
//! known peers, built on the [Noise protocol framework][noise] (XX pattern,
//! X25519 + AES-GCM + BLAKE2b).
//!
//! ## Design intent
//!
//! Snowpack is built for **inter-node links in a cluster or mesh** — situations
//! where a fixed set of nodes all need to talk to each other and every node is
//! both a potential initiator and responder. This is a different problem from
//! the typical client-server model:
//!
//! - **Mutual authentication**: every connection authenticates both ends. There
//!   is no notion of an anonymous client; an unrecognised peer cannot connect.
//! - **No CA infrastructure**: authentication is built on a single
//!   [`SignatureKeypair`] the cluster operator generates. The [`SignatureVerificationKey`]
//!   (public half) is distributed to every node. The signing key (private half)
//!   can be handled in two ways depending on your security requirements:
//!   - *Shared signing key* — distribute the signing key to every node so each
//!     can sign its own headers and new nodes can be added without operator
//!     involvement. Simpler to operate; a compromised node can mint credentials
//!     for arbitrary identities.
//!   - *Offline signing* — the operator signs an [`AuthHeader`] for each node
//!     offline and distributes only the resulting [`SignedAuthHeader`]. The
//!     signing key never reaches any node. Harder to rotate membership; a
//!     compromised node cannot forge new credentials.
//! - **Stable long-lived connections**: the framed transport is designed for
//!   persistent connections that carry many messages over their lifetime, not
//!   short request/response exchanges.
//!
//! If you need to authenticate arbitrary external clients, or if you want
//! browser/TLS compatibility, snowpack is the wrong tool — reach for TLS with
//! a proper PKI instead.
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
//! - A **[`ConnectionPool`]** that maintains one authenticated,
//!   auto-reconnecting connection per peer, with a commit/reset [`Guard`]
//!   that handles mid-RPC cancellation safely.
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
//!     AuthDetails, AuthHeader, SignedAuthHeader,
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
//! let auth = AuthHeader::new(my_id, None, &transport_keys.public)
//!     .sign(&cluster_keys.private);
//!
//! // Server side: accept a connection and recover the peer's NodeId.
//! let listener = TcpListener::bind("0.0.0.0:7000").await?;
//! let (stream, _) = listener.accept().await?;
//! let ((mut tx, mut rx), peer_id): (_, AuthDetails) = accept(
//!     stream,
//!     &transport_keys.private,
//!     &auth,
//!     &cluster_keys.public,
//! ).await?;
//!
//! // Client side: connect and verify the peer's identity from AuthDetails.
//! let stream = TcpStream::connect("peer:7000").await?;
//! let ((mut tx, mut rx), peer) = connect(
//!     stream,
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
mod pool;
mod sign;

pub use auth::{AuthDetails, AuthHeader, BadAuth, MalformedAuthHeader, SignedAuthHeader};
pub use noise::{TransportKeypair, TransportPrivateKey, TransportPublicKey};
pub use messages::{Message, MessagePackets, MessageRx, MessageTx};
pub use node_id::{NodeId, NodeIdTooLong, MAX_NODE_ID_LEN};
pub use packet_state::PacketBuildError;
pub use packet_state::PacketReadError;
pub use packets::ConnectionError;
pub use pool::{Connection, ConnectionPool, Connector, Credentials, Guard, NotReady, TcpConnector};
pub use sign::{SignatureKeypair, SignatureSigningKey, SignatureVerificationKey};

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};


/// Complete a Noise XX handshake as the **responder** (server side).
///
/// Verifies the initiator's signed auth header against `verification_key` and
/// confirms the Noise static key matches the one declared in the header.
///
/// Returns the authenticated message transport halves and [`AuthDetails`].
/// The caller is responsible for making appropriate checks on the peer's
/// identity — during discovery this may be how the peer's node id is first
/// learned; when accepting from a known set, verify it is a permitted peer.
pub async fn accept<S>(
    stream: S,
    local_private: &TransportPrivateKey,
    local_auth_header: &SignedAuthHeader,
    verification_key: &SignatureVerificationKey,
) -> Result<((MessageTx<WriteHalf<S>>, MessageRx<ReadHalf<S>>), AuthDetails), ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin
{
    let ((tx, rx), auth_details) =
        packets::accept(stream, local_private, local_auth_header, verification_key).await?;


    Ok(((MessageTx::new(tx), MessageRx::new(rx)), auth_details))
}

/// Complete a Noise XX handshake as the **initiator** (client side).
///
/// Verifies the responder's signed auth header against `verification_key` and
/// confirms the Noise static key matches the one declared in the header.
///
/// Returns the authenticated message transport halves and [`AuthDetails`].
/// The caller is responsible for making appropriate checks on the peer's
/// identity — during discovery this establishes who was reached; when
/// reconnecting, verify it matches the expected peer.
pub async fn connect<S>(
    stream: S,
    local_private: &TransportPrivateKey,
    local_auth_header: &SignedAuthHeader,
    verification_key: &SignatureVerificationKey,
) -> Result<((MessageTx<WriteHalf<S>>, MessageRx<ReadHalf<S>>), AuthDetails), ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ((tx, rx), auth_details) = packets::connect(
        stream,
        local_private,
        local_auth_header,
        verification_key,
    )
    .await?;
    Ok(((MessageTx::new(tx), MessageRx::new(rx)), auth_details))
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