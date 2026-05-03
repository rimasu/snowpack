use std::io;
use snow::TransportState;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::{AsyncReadExt, AsyncWriteExt};


use crate::NodeId;
use crate::auth::BadAuth;
use crate::auth::SignedAuthHeader;
use crate::keys::TransportPrivateKey;
use crate::keys::TransportPublicKey;
use crate::noise::noise_params;
use crate::packet::MAX_CIPHERTEXT_SIZE;
use crate::packet::MAX_PACKET_SIZE;
use crate::packet::Packet;
use crate::packet::PacketBuildError;
use crate::packet::PacketBuilder;
use crate::packet::PacketReadError;
use crate::packet::PacketReader;
use crate::sign::SignatureVerificationKey;





/// All errors that can occur during transport operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// An underlying I/O error from the stream.
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// The Noise handshake or encryption/decryption failed.
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),

    /// A framed packet violated the packet protocol.
    #[error("packet: {0}")]
    Packet(#[from] PacketReadError),

    #[error("packet: {0}")]
    PacketBuilder(#[from] PacketBuildError),

    /// A packet payload exceeded the maximum allowed size.
    #[error("packet overflow")]
    PacketOverflow,

    /// The remote peer's static key was not present after the handshake.
    #[error("no remote static key after handshake")]
    MissingRemoteStatic,

    /// The remote peer's static key had an unexpected length.
    #[error("remote static key has wrong length")]
    RemoteStaticKeyLength,

    #[error("invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("invalid node id: {0}")]
    InvalidNodeId(String),

    #[error("message serialization: {0}")]
    MessageSerialization(String),

    #[error(transparent)]
    BadAuth(#[from] BadAuth),
}


// ---------------------------------------------------------------------------
// Framing helpers (private)
//
// Every message on the wire is a 2-byte big-endian length prefix followed by
// that many bytes of payload. Used for both handshake and transport messages.
// ---------------------------------------------------------------------------

async fn read_frame<S>(stream: &mut S, frame: &mut Vec<u8>) -> Result<(), TransportError>
where
    S: AsyncRead + Unpin,
{
    let len = stream.read_u16().await? as usize;
    frame.resize(len, 0);
    stream.read_exact(frame).await?;
    Ok(())
}

async fn write_frame<S>(stream: &mut S, data: &[u8]) -> Result<(), TransportError>
where
    S: AsyncWrite + Unpin,
{
    let len: u16 = data
        .len()
        .try_into()
        .map_err(|_| TransportError::PacketOverflow)?;
    stream.write_u16(len).await?;
    stream.write_all(data).await?;
    stream.flush().await.map_err(TransportError::from)
}

// ---------------------------------------------------------------------------
// HandshakeContext
//
// Owns the stream, the snow HandshakeState, and its associated buffers for
// the duration of the XX handshake. Consumed by `into_transport` once
// complete, which returns a fully constructed PacketTransport.
// ---------------------------------------------------------------------------

struct HandshakeContext<S> {
    handshake: snow::HandshakeState,
    frame: Vec<u8>,
    noise_buf: Vec<u8>,
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HandshakeContext<S> {
    fn new_initiator(
        stream: S,
        local_private: &TransportPrivateKey,
    ) -> Result<Self, TransportError> {
        let handshake = snow::Builder::new(noise_params())
            .local_private_key(local_private.expose())
            .build_initiator()?;
        Ok(Self {
            handshake,
            stream,
            frame: Vec::new(),
            noise_buf: vec![0u8; MAX_CIPHERTEXT_SIZE],
        })
    }

    fn new_responder(
        stream: S,
        local_private: &TransportPrivateKey,
    ) -> Result<Self, TransportError> {
        let handshake = snow::Builder::new(noise_params())
            .local_private_key(local_private.expose())
            .build_responder()?;
        Ok(Self {
            handshake,
            stream,
            frame: Vec::new(),
            noise_buf: vec![0u8; MAX_CIPHERTEXT_SIZE],
        })
    }

    /// Read one handshake frame and return a view of the decrypted payload.
    /// The slice is valid until the next call to `recv`.
    async fn recv(&mut self) -> Result<&[u8], TransportError> {
        read_frame(&mut self.stream, &mut self.frame).await?;

        let n = self
            .handshake
            .read_message(&self.frame, &mut self.noise_buf)?;

        Ok(&self.noise_buf[..n])
    }

    /// Encrypt `payload` and write one handshake frame.
    async fn send(&mut self, payload: &[u8]) -> Result<(), TransportError> {
        let n = self.handshake.write_message(payload, &mut self.noise_buf)?;
        write_frame(&mut self.stream, &self.noise_buf[..n]).await
    }

    fn remote_static(&self) -> Result<TransportPublicKey, TransportError> {
        let raw = self
            .handshake
            .get_remote_static()
            .ok_or(TransportError::MissingRemoteStatic)?;

        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| TransportError::RemoteStaticKeyLength)?;

        Ok(TransportPublicKey::from(arr))
    }

    fn into_transport(self) -> Result<PacketTransport<S>, TransportError> {
        let state = self.handshake.into_transport_mode()?;
        Ok(PacketTransport::new(self.stream, state))
    }
}

// ===========================================================================
// PacketTransport
//
// Owns the stream and its buffers. Intended to be long-lived — buffers are
// allocated once during the handshake and reused across RPCs.
// ===========================================================================

/// Created by completing a Noise XX handshake via [`PacketTransport::accept`]
/// or [`PacketTransport::connect`]. Owns the underlying stream and reuses
/// internal buffers across reads to avoid per-RPC allocation.
pub struct PacketTransport<S> {
    state: snow::TransportState,
    packet_reader: PacketReader,
    packet_builder: PacketBuilder,
    stream: S,

    /// Receives raw ciphertext frames off the wire; resized as needed.
    ciphertext_buf: Vec<u8>,

    /// Receives decrypted plaintext (header byte + payload); resized as needed.
    plaintext_buf: Vec<u8>,

    /// Scratch buffer for outbound ciphertext; grown as needed, never shrunk.
    write_buf: Vec<u8>,
}

const EMPTY_PAYLOAD: &[u8] = &[];

impl<S> PacketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // -----------------------------------------------------------------------
    // Handshake constructors
    // -----------------------------------------------------------------------

    /// Complete a Noise XX handshake as the **responder** (server side).
    ///
    /// Verifies the initiator's signed auth header with `verification_key` and
    /// confirms that the Noise static key matches the one in the header.
    ///
    /// Returns the transport and the authenticated remote [`NodeId`].
    pub async fn accept(
        stream: S,
        local_private: &TransportPrivateKey,
        local_auth_header: &SignedAuthHeader,
        verification_key: &SignatureVerificationKey,
    ) -> Result<(Self, NodeId), TransportError> {
        let mut hs = HandshakeContext::new_responder(stream, local_private)?;

        // XX msg 1: → e
        hs.recv().await?;

        // XX msg 2: ← e, ee, s, es  (carry our signed auth header as payload)
        hs.send(local_auth_header.expose()).await?;

        // XX msg 3: → s, se  (initiator's static key is now authenticated)
        let payload = hs.recv().await?;
        let remote_auth_header = SignedAuthHeader::verify_raw(verification_key, payload)?;

        remote_auth_header.validate_public_key(&hs.remote_static()?)?;

        let node_id = remote_auth_header.node_id();
        Ok((hs.into_transport()?, node_id.clone()))
    }

    /// Complete a Noise XX handshake as the **initiator** (client side).
    ///
    /// Verifies the responder's signed auth header with `verification_key`,
    /// confirms the static key matches, and asserts that the authenticated
    /// [`NodeId`] equals `target`.
    pub async fn connect<N>(
        stream: S,
        target: N,
        local_private: &TransportPrivateKey,
        local_auth_header: &SignedAuthHeader,
        verification_key: &SignatureVerificationKey,
    ) -> Result<Self, TransportError> where N: Into<NodeId> {
        let mut hs = HandshakeContext::new_initiator(stream, local_private)?;

        // XX msg 1: → e
        hs.send(&[]).await?;

        // XX msg 2: ← e, ee, s, es  (responder's static key is now authenticated)
        let payload = hs.recv().await?;
        let remote_auth_header = SignedAuthHeader::verify_raw(verification_key, payload)?;

        remote_auth_header.validate_public_key(&hs.remote_static()?)?;
        remote_auth_header.validate_node_id(target)?;

        // XX msg 3: → s, se  (carry our signed auth header as payload)
        hs.send(local_auth_header.expose()).await?;

        hs.into_transport()
    }

    fn new(stream: S, state: TransportState) -> Self {
        Self {
            state,
            packet_reader: PacketReader::new(),
            packet_builder: PacketBuilder::new(),
            stream,
            write_buf: Vec::new(),
            ciphertext_buf: Vec::new(),
            plaintext_buf: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Transport I/O
    // -----------------------------------------------------------------------

    /// Read one framed, decrypted packet. Returns the [`PacketHeader`] and a
    /// slice of the payload — valid until the next call to `read_packet`.
    pub async fn read_packet(&mut self) -> Result<Packet, TransportError> {
        read_frame(&mut self.stream, &mut self.ciphertext_buf).await?;

        self.plaintext_buf.resize(self.ciphertext_buf.len(), 0);

        let n = self
            .state
            .read_message(&self.ciphertext_buf, &mut self.plaintext_buf)?;

        let packet = self.packet_reader.read(&self.plaintext_buf[..n])?;
        Ok(packet)
    }

    pub fn packet_data(&self, packet: &Packet)-> &[u8] {
        if packet.to > packet.from {
            &self.plaintext_buf[packet.from..packet.to]
        } else {
            EMPTY_PAYLOAD
        }
    }

    pub fn prepare_message<T>(&mut self, msg_type: T) -> Result<(), TransportError>
    where
        T: Into<u8>,
    {
        Ok(self.packet_builder.prepare(msg_type.into())?)
    }

    /// Write one framed, encrypted packet.
    /// `payload` must not exceed [`MAX_PACKET_LEN`] bytes.
    pub async fn send_packet(&mut self, payload: &[u8], last: bool) -> Result<(), TransportError> {
        let plaintext = self.packet_builder.pack(payload, last)?;

        let ciphertext_len = plaintext.len() + 16;
        if self.write_buf.len() < ciphertext_len {
            self.write_buf.resize(ciphertext_len, 0);
        }

        let n = self.state.write_message(plaintext, &mut self.write_buf)?;
        write_frame(&mut self.stream, &self.write_buf[..n]).await
    }

    /// Split `data` across as many packets as needed and send them all.
    /// `last_slice` is forwarded to the final packet's header.
    pub async fn send_slice(
        &mut self,
        data: &[u8],
        last_slice: bool,
    ) -> Result<(), TransportError> {
        let mut chunks = data.chunks(MAX_PACKET_SIZE).peekable();

        // Empty data: send a single empty, terminal packet.
        if chunks.peek().is_none() {
            return self.send_packet(&[], last_slice).await;
        }

        while let Some(chunk) = chunks.next() {
            let is_last = chunks.peek().is_none();
            self.send_packet(chunk, is_last && last_slice).await?;
        }

        Ok(())
    }

    pub async fn send_reader<R>(
        &mut self,
        mut reader: R,
    ) -> Result<(), TransportError>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let mut filled = 0;
        let mut sent_any = false;

        loop {
            let space = MAX_PACKET_SIZE - filled;

            // flush full packet
            if space == 0 {
                self.send_packet(&buf[..filled], false).await?;
                filled = 0;
            }

            let n = reader.read(&mut buf[filled..]).await?;

            if n == 0 {
                break;
            }

            sent_any = true;
            filled += n;
        }

        // flush remainder
        if filled > 0 {
            self.send_packet(&buf[..filled], true).await?;
        } else if !sent_any {
            self.send_packet(&[], true).await?;
        }

        Ok(())
    }


}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use crate::{
        NodeId, auth::{AuthHeader, BadAuth, SignedAuthHeader}, keys::TransportKeypair, packet::MAX_PACKET_SIZE, packet_transport::{EMPTY_PAYLOAD, PacketTransport, TransportError}, sign::{SignatureKeypair, SignatureVerificationKey}
    };

    struct NodeFixture {
        node_id: NodeId,
        transport: TransportKeypair,
        auth_header: SignedAuthHeader,
    }

    impl NodeFixture {
        fn new(node_id: u64, cluster_kp: &SignatureKeypair) -> Self {
            let transport = TransportKeypair::generate().expect("keygen failed");
            let auth_header = AuthHeader::new(NodeId::from(node_id), &transport.public)
                .sign(&cluster_kp.private)
                .expect("sign failed");
            Self {
                node_id: NodeId::from(node_id),
                transport,
                auth_header,
            }
        }
    }

    // -----------------------------------------------------------------------
    // Handshake harness
    //
    // Both sides are spawned as separate tasks so the tokio runtime can
    // interleave their reads and writes. Driving them sequentially on one
    // thread would deadlock at the first blocking recv.
    //
    // The duplex buffer is 65535 so a single maximum-size handshake message
    // always fits without the other side needing to be scheduled first.
    //
    // `flavor = "multi_thread"` is required on every test that uses this
    // harness — the default single-threaded runtime brings the deadlock risk
    // back even with spawn.
    // -----------------------------------------------------------------------

    type Transport = PacketTransport<tokio::io::DuplexStream>;

    async fn connect_pair(
        server: NodeFixture,
        client: NodeFixture,
        verification_key: SignatureVerificationKey,
    ) -> ((Transport, NodeId), Transport) {
        let (client_stream, server_stream) = duplex(65537);

        let vk_server = verification_key.clone();
        let vk_client = verification_key.clone();

        let server_task = tokio::spawn(async move {
            PacketTransport::accept(
                server_stream,
                &server.transport.private,
                &server.auth_header,
                &vk_server,
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            PacketTransport::connect(
                client_stream,
                server.node_id,
                &client.transport.private,
                &client.auth_header,
                &vk_client,
            )
            .await
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);

        let server_transport = server_result
            .expect("server task panicked")
            .expect("server handshake failed");
        let client_transport = client_result
            .expect("client task panicked")
            .expect("client handshake failed");

        (server_transport, client_transport)
    }

    // -----------------------------------------------------------------------
    // Handshake — happy path
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_completes() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        // reaching here without panic means both sides completed the handshake
        connect_pair(server, client, cluster_kp.public).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accept_returns_correct_remote_node_id() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let expected_client_id = client.node_id.clone();

        let ((_, remote_node_id), _) = connect_pair(server, client, cluster_kp.public).await;
        assert_eq!(remote_node_id, expected_client_id);
    }

    // -----------------------------------------------------------------------
    // Handshake — rejection: wrong cluster signing key
    //
    // The server signs its auth header with a rogue keypair. The client
    // should reject it during the handshake.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_rejects_auth_header_signed_with_wrong_key() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let rogue_kp = SignatureKeypair::generate().unwrap();

        let server_transport = TransportKeypair::generate().unwrap();
        let server_auth = AuthHeader::new(NodeId::from(1u32), &server_transport.public)
            .sign(&rogue_kp.private)
            .expect("sign failed");

        let client = NodeFixture::new(2, &cluster_kp);
        let client_node_id = client.node_id;

        let (client_stream, server_stream) = duplex(65535);
        let vk_client = cluster_kp.public.clone();

        let server_task = tokio::spawn(async move {
            PacketTransport::accept(
                server_stream,
                &server_transport.private,
                &server_auth,
                &cluster_kp.public,
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            PacketTransport::connect(
                client_stream,
                client_node_id,
                &client.transport.private,
                &client.auth_header,
                &vk_client,
            )
            .await
        });

        let (_, client_result) = tokio::join!(server_task, client_task);
        let err = client_result
            .expect("client task panicked")
            .err()
            .expect("expected auth failure");
        assert!(matches!(err, TransportError::BadAuth(_)), "got: {err:?}");
    }

    // -----------------------------------------------------------------------
    // Handshake — rejection: correct signature but wrong NodeId
    //
    // Client connects expecting node 1 but the server identifies as node 99.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_rejects_mismatched_node_id() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(99, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let wrong_target = NodeId::from(1u32);

        let (client_stream, server_stream) = duplex(65535);
        let vk_server = cluster_kp.public.clone();
        let vk_client = cluster_kp.public.clone();

        let server_task = tokio::spawn(async move {
            PacketTransport::accept(
                server_stream,
                &server.transport.private,
                &server.auth_header,
                &vk_server,
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            PacketTransport::connect(
                client_stream,
                wrong_target,
                &client.transport.private,
                &client.auth_header,
                &vk_client,
            )
            .await
        });

        let (_, client_result) = tokio::join!(server_task, client_task);
        let err = client_result
            .expect("client task panicked")
            .err()
            .expect("expected node id mismatch");
        assert!(
            matches!(err, TransportError::BadAuth(BadAuth::NodeIdMismatch { .. })),
            "got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Handshake — rejection: static key mismatch
    //
    // The server presents a valid auth header claiming one public key but
    // performs the Noise handshake with a different private key. The client
    // should catch the mismatch between the Noise static key and the public
    // key declared in the auth header.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_rejects_static_key_mismatch() {
        let cluster_kp = SignatureKeypair::generate().unwrap();

        let declared_transport = TransportKeypair::generate().unwrap();
        let server_auth = AuthHeader::new(1u32, &declared_transport.public)
            .sign(&cluster_kp.private)
            .expect("sign failed");

        // Actual handshake uses a different private key than the one declared.
        let actual_transport = TransportKeypair::generate().unwrap();

        let client = NodeFixture::new(2, &cluster_kp);
        let client_node_id = client.node_id;

        let (client_stream, server_stream) = duplex(65535);
        let vk_server = cluster_kp.public.clone();
        let vk_client = cluster_kp.public.clone();

        let server_task = tokio::spawn(async move {
            PacketTransport::accept(
                server_stream,
                &actual_transport.private,
                &server_auth,
                &vk_server,
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            PacketTransport::connect(
                client_stream,
                client_node_id,
                &client.transport.private,
                &client.auth_header,
                &vk_client,
            )
            .await
        });

        let (_, client_result) = tokio::join!(server_task, client_task);
        let err = client_result
            .expect("client task panicked")
            .err()
            .expect("expected key mismatch");
        assert!(
            matches!(
                err,
                TransportError::BadAuth(BadAuth::PublicKeyMismatch { .. })
            ),
            "got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Transport I/O — small payload roundtrip
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn roundtrip_small_payload() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((mut server_transport, _), mut client_transport) =
            connect_pair(server, client, cluster_kp.public).await;

        client_transport.prepare_message(1u8).unwrap();
        client_transport
            .send_slice(b"hello world", true)
            .await
            .unwrap();

        let packet = server_transport.read_packet().await.unwrap();
        assert!(packet.first);
        assert!(packet.last);
        assert_eq!(packet.msg_type, 1);
        assert_eq!(server_transport.packet_data(&packet), b"hello world");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn roundtrip_empty_payload() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((mut server_transport, _), mut client_transport) =
            connect_pair(server, client, cluster_kp.public).await;

        client_transport.prepare_message(0u8).unwrap();
        client_transport.send_slice(&[], true).await.unwrap();

        let packet = server_transport.read_packet().await.unwrap();
        assert!(packet.first);
        assert!(packet.last);
        assert_eq!(client_transport.packet_data(&packet), EMPTY_PAYLOAD);
    }

    // -----------------------------------------------------------------------
    // Transport I/O — large payload chunking
    //
    // A payload larger than MAX_PACKET_LEN must be split into multiple
    // packets. We verify the reassembled data matches and that first/last
    // flags are set correctly only on the first and final packets.
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn roundtrip_large_payload_chunks_correctly() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((mut server_transport, _), mut client_transport) =
            connect_pair(server, client, cluster_kp.public).await;

        // Three full chunks plus a partial remainder.
        let data: Vec<u8> = (0u8..=255)
            .cycle()
            .take(MAX_PACKET_SIZE * 3 + 100)
            .collect();
        let to_send = data.clone();

        let client_task = tokio::spawn(async move {
            client_transport.prepare_message(2u8).unwrap();
            client_transport.send_slice(&to_send, true).await.unwrap();
        });

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut packet_count = 0usize;
            loop {
                let packet = server_transport.read_packet().await.unwrap();
                if packet_count == 0 {
                    assert!(packet.first, "first packet must have first flag set");
                } else {
                    assert!(
                        !packet.first,
                        "only the first packet should have first flag set"
                    );
                }
                let data = server_transport.packet_data(&packet);
                received.extend_from_slice(data);
                packet_count += 1;
                if packet.last {
                    break;
                }
            }

            (packet_count, received)
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);

        let (packet_count, received) = server_result.expect("server task panicked");

        assert_eq!(packet_count, 4, "expected 4 packets for this payload size");
        assert_eq!(received, data);

        client_result.expect("client task panicked");
    }

    // -----------------------------------------------------------------------
    // Transport I/O — bidirectional
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn bidirectional_roundtrip() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((mut server_transport, _), mut client_transport) =
            connect_pair(server, client, cluster_kp.public).await;

        client_transport.prepare_message(1u8).unwrap();
        client_transport.send_slice(b"ping", true).await.unwrap();

        let ping = server_transport.read_packet().await.unwrap();
        assert_eq!(server_transport.packet_data(&ping), b"ping");

        server_transport.prepare_message(2u8).unwrap();
        server_transport.send_slice(b"pong", true).await.unwrap();

        let pong = client_transport.read_packet().await.unwrap();
        assert_eq!(client_transport.packet_data(&pong), b"pong")
    }

    // -----------------------------------------------------------------------
    // Transport I/O — multiple sequential messages
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_sequential_messages() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((mut server_transport, _), mut client_transport) =
            connect_pair(server, client, cluster_kp.public).await;

        for i in 0u8..5 {
            client_transport.prepare_message(i).unwrap();
            let payload = vec![i; 64];
            client_transport.send_slice(&payload, true).await.unwrap();

            let packet = server_transport.read_packet().await.unwrap();
            assert_eq!(packet.msg_type, i);
            assert_eq!(server_transport.packet_data(&packet), payload.as_slice());
        }
    }
}
