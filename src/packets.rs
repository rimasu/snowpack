use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadHalf;
use tokio::io::WriteHalf;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

use crate::auth::AuthDetails;
use crate::auth::BadAuth;
use crate::auth::SignedAuthHeader;
use crate::noise::TransportPrivateKey;
use crate::noise::TransportPublicKey;
use crate::noise::noise_params;
use crate::packet_state::MAX_CIPHERTEXT_SIZE;
use crate::packet_state::MAX_PACKET_SIZE;
use crate::packet_state::PacketBuildError;
use crate::packet_state::PacketBuilder;
use crate::packet_state::PacketHeader;
use crate::packet_state::PacketReadError;
use crate::packet_state::PacketReader;
use crate::sign::SignatureVerificationKey;

/// All errors that can occur during connection operations.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
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

    #[error("handshake timed out")]
    HandshakeTimeout,

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

async fn read_frame<S>(stream: &mut S, frame: &mut Vec<u8>) -> Result<(), ConnectionError>
where
    S: AsyncRead + Unpin,
{
    let len = stream.read_u16().await? as usize;
    frame.resize(len, 0);
    stream.read_exact(frame).await?;
    Ok(())
}

async fn write_frame<S>(stream: &mut S, data: &[u8]) -> Result<(), ConnectionError>
where
    S: AsyncWrite + Unpin,
{
    let len: u16 = data
        .len()
        .try_into()
        .map_err(|_| ConnectionError::PacketOverflow)?;
    stream.write_u16(len).await?;
    stream.write_all(data).await?;
    stream.flush().await.map_err(ConnectionError::from)
}

// ---------------------------------------------------------------------------
// HandshakeContext
//
// Owns the stream, the snow HandshakeState, and its associated buffers for
// the duration of the XX handshake. Consumed by `into_split` once complete,
// which splits the stream and returns the ready PacketTx/PacketRx pair.
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
    ) -> Result<Self, ConnectionError> {
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
    ) -> Result<Self, ConnectionError> {
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
    async fn recv(&mut self) -> Result<&[u8], ConnectionError> {
        read_frame(&mut self.stream, &mut self.frame).await?;
        let n = self
            .handshake
            .read_message(&self.frame, &mut self.noise_buf)?;
        Ok(&self.noise_buf[..n])
    }

    /// Encrypt `payload` and write one handshake frame.
    async fn send(&mut self, payload: &[u8]) -> Result<(), ConnectionError> {
        let n = self.handshake.write_message(payload, &mut self.noise_buf)?;
        write_frame(&mut self.stream, &self.noise_buf[..n]).await
    }

    fn remote_static(&self) -> Result<TransportPublicKey, ConnectionError> {
        let raw = self
            .handshake
            .get_remote_static()
            .ok_or(ConnectionError::MissingRemoteStatic)?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| ConnectionError::RemoteStaticKeyLength)?;
        Ok(TransportPublicKey::from(arr))
    }

    // S is always split into WriteHalf/ReadHalf by design; a type alias would
    // obscure the relationship between the stream type and the two halves.
    #[allow(clippy::type_complexity)]
    fn into_split(self) -> Result<(PacketTx<WriteHalf<S>>, PacketRx<ReadHalf<S>>), ConnectionError> {
        let state = Arc::new(Mutex::new(self.handshake.into_transport_mode()?));
        let (read, write) = split(self.stream);

        let tx = PacketTx {
            state: state.clone(),
            packet_builder: PacketBuilder::new(),
            write,
            write_buf: Vec::new(),
        };
        let rx = PacketRx {
            state,
            packet_reader: PacketReader::new(),
            read,
            ciphertext_buf: self.frame,
            plaintext_buf: self.noise_buf,
            payload_end: 0,
        };
        Ok((tx, rx))
    }
}

// ---------------------------------------------------------------------------
// Handshake entry points
// ---------------------------------------------------------------------------

/// Complete a Noise XX handshake as the **responder** (server side).
///
/// Verifies the initiator's signed auth header with `verification_key` and
/// confirms that the Noise static key matches the one in the header.
///
/// Returns the split transport pair and the authenticated details.
pub(crate) async fn accept<S>(
    stream: S,
    local_private: &TransportPrivateKey,
    local_auth_header: &SignedAuthHeader,
    verification_key: &SignatureVerificationKey,
) -> Result<((PacketTx<WriteHalf<S>>, PacketRx<ReadHalf<S>>), AuthDetails), ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut hs = HandshakeContext::new_responder(stream, local_private)?;

        // XX msg 1: → e
        hs.recv().await?;

        // XX msg 2: ← e, ee, s, es  (carry our signed auth header as payload)
        hs.send(local_auth_header.expose()).await?;

        // XX msg 3: → s, se  (initiator's static key is now authenticated)
        let payload = hs.recv().await?;
        let remote_auth_header = SignedAuthHeader::verify_raw(verification_key, payload)?;

        remote_auth_header.validate_public_key(&hs.remote_static()?)?;

        let details = remote_auth_header.into();

        Ok((hs.into_split()?, details))
    })
    .await
    .map_err(|_| ConnectionError::HandshakeTimeout)?
}

/// Complete a Noise XX handshake as the **initiator** (client side).
///
/// Verifies the responder's signed auth header with `verification_key` and
/// confirms the static key matches.
///
/// Returns the split transport pair and the authenticated details.
pub(crate) async fn connect<S>(
    stream: S,
    local_private: &TransportPrivateKey,
    local_auth_header: &SignedAuthHeader,
    verification_key: &SignatureVerificationKey,
) -> Result<((PacketTx<WriteHalf<S>>, PacketRx<ReadHalf<S>>), AuthDetails), ConnectionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, async {
        let mut hs = HandshakeContext::new_initiator(stream, local_private)?;

        // XX msg 1: → e
        hs.send(&[]).await?;

        // XX msg 2: ← e, ee, s, es  (responder's static key is now authenticated)
        let payload = hs.recv().await?;
        let remote_auth_header = SignedAuthHeader::verify_raw(verification_key, payload)?;

        remote_auth_header.validate_public_key(&hs.remote_static()?)?;

        // XX msg 3: → s, se  (carry our signed auth header as payload)
        hs.send(local_auth_header.expose()).await?;

        let details = remote_auth_header.into();
        Ok((hs.into_split()?, details))
    })
    .await
    .map_err(|_| ConnectionError::HandshakeTimeout)?
}

// ---------------------------------------------------------------------------
// PacketRx / PacketTx
// ---------------------------------------------------------------------------

pub(crate) const EMPTY_PAYLOAD: &[u8] = &[];

pub(crate) struct PacketRx<R: AsyncRead + Unpin> {
    state: Arc<Mutex<snow::TransportState>>,
    packet_reader: PacketReader,
    read: R,
    ciphertext_buf: Vec<u8>,
    plaintext_buf: Vec<u8>,
    payload_end: usize,
}

impl<R: AsyncRead + Unpin> PacketRx<R> {
    pub(crate) async fn read_packet(&mut self) -> Result<PacketHeader, ConnectionError> {
        read_frame(&mut self.read, &mut self.ciphertext_buf).await?;

        self.plaintext_buf.resize(self.ciphertext_buf.len(), 0);

        let n = {
            let mut t = self.state.lock().expect("snow cipher state poisoned");
            t.read_message(&self.ciphertext_buf, &mut self.plaintext_buf)?
        };

        self.payload_end = n;
        let header = self.packet_reader.read(&self.plaintext_buf[..n])?;
        Ok(header)
    }

    pub(crate) fn payload(&self) -> &[u8] {
        if self.payload_end > 1 {
            &self.plaintext_buf[1..self.payload_end]
        } else {
            EMPTY_PAYLOAD
        }
    }
}

pub(crate) struct PacketTx<W: AsyncWrite + Unpin> {
    state: Arc<Mutex<snow::TransportState>>,
    packet_builder: PacketBuilder,
    write: W,
    write_buf: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> PacketTx<W> {
    pub(crate) fn prepare_message<T: Into<u8>>(&mut self, msg_type: T) -> Result<(), ConnectionError> {
        Ok(self.packet_builder.prepare(msg_type.into())?)
    }

    pub(crate) async fn send_packet(&mut self, payload: &[u8], last: bool) -> Result<(), ConnectionError> {
        let plaintext = self.packet_builder.pack(payload, last)?;

        let ciphertext_len = plaintext.len() + 16;
        if self.write_buf.len() < ciphertext_len {
            self.write_buf.resize(ciphertext_len, 0);
        }

        let len = {
            let mut t = self.state.lock().expect("snow cipher state poisoned");
            t.write_message(plaintext, &mut self.write_buf)?
        };

        write_frame(&mut self.write, &self.write_buf[..len]).await
    }

    pub(crate) async fn send_slice(
        &mut self,
        data: &[u8],
        last_slice: bool,
    ) -> Result<(), ConnectionError> {
        let mut chunks = data.chunks(MAX_PACKET_SIZE).peekable();

        if chunks.peek().is_none() {
            return self.send_packet(&[], last_slice).await;
        }

        while let Some(chunk) = chunks.next() {
            let is_last = chunks.peek().is_none();
            self.send_packet(chunk, is_last && last_slice).await?;
        }

        Ok(())
    }

    pub(crate) async fn send_reader<R>(&mut self, mut reader: R) -> Result<(), ConnectionError>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let mut filled = 0;
        let mut sent_any = false;

        loop {
            let space = MAX_PACKET_SIZE - filled;

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
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex};

    use crate::{
        NodeId,
        auth::{AuthHeader, BadAuth, SignedAuthHeader},
        noise::TransportKeypair,
        packet_state::MAX_PACKET_SIZE,
        packets::{EMPTY_PAYLOAD, PacketRx, PacketTx, ConnectionError, accept, connect},
        sign::{SignatureKeypair, SignatureVerificationKey},
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
                .sign(&cluster_kp.private);
            Self {
                node_id: NodeId::from(node_id),
                transport,
                auth_header,
            }
        }
    }

    // -----------------------------------------------------------------------
    // Handshake harness
    // -----------------------------------------------------------------------

    type Tx = PacketTx<WriteHalf<DuplexStream>>;
    type Rx = PacketRx<ReadHalf<DuplexStream>>;

    async fn connect_pair(
        server: NodeFixture,
        client: NodeFixture,
        verification_key: SignatureVerificationKey,
    ) -> ((Tx, Rx, NodeId), (Tx, Rx)) {
        let (client_stream, server_stream) = duplex(65537);

        let vk_server = verification_key.clone();
        let vk_client = verification_key.clone();

        let server_task = tokio::spawn(async move {
            accept(
                server_stream,
                &server.transport.private,
                &server.auth_header,
                &vk_server,
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            connect(
                client_stream,
                &client.transport.private,
                &client.auth_header,
                &vk_client,
            )
            .await
        });

        let (server_result, client_result) = tokio::join!(server_task, client_task);

        let ((server_tx, server_rx), auth_details) = server_result
            .expect("server task panicked")
            .expect("server handshake failed");
        let ((client_tx, client_rx), _) = client_result
            .expect("client task panicked")
            .expect("client handshake failed");

        ((server_tx, server_rx, auth_details.node_id), (client_tx, client_rx))
    }

    // -----------------------------------------------------------------------
    // Handshake — happy path
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_completes() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        connect_pair(server, client, cluster_kp.public).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accept_returns_correct_remote_node_id() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let expected_client_id = client.node_id.clone();

        let ((_, _, remote_node_id), _) = connect_pair(server, client, cluster_kp.public).await;
        assert_eq!(remote_node_id, expected_client_id);
    }

    // -----------------------------------------------------------------------
    // Handshake — rejection tests
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_rejects_auth_header_signed_with_wrong_key() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let rogue_kp = SignatureKeypair::generate().unwrap();

        let server_transport = TransportKeypair::generate().unwrap();
        let server_auth = AuthHeader::new(NodeId::from(1u32), &server_transport.public)
            .sign(&rogue_kp.private);

        let client = NodeFixture::new(2, &cluster_kp);

        let (client_stream, server_stream) = duplex(65535);
        let vk_client = cluster_kp.public.clone();

        let server_task = tokio::spawn(async move {
            accept(
                server_stream,
                &server_transport.private,
                &server_auth,
                &cluster_kp.public,
            )
            .await
        });

        let client_task = tokio::spawn(async move {
            connect(
                client_stream,
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
        assert!(matches!(err, ConnectionError::BadAuth(_)), "got: {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_rejects_static_key_mismatch() {
        let cluster_kp = SignatureKeypair::generate().unwrap();

        let declared_transport = TransportKeypair::generate().unwrap();
        let server_auth = AuthHeader::new(1u32, &declared_transport.public)
            .sign(&cluster_kp.private);

        let actual_transport = TransportKeypair::generate().unwrap();

        let client = NodeFixture::new(2, &cluster_kp);

        let (client_stream, server_stream) = duplex(65535);
        let vk_server = cluster_kp.public.clone();
        let vk_client = cluster_kp.public.clone();

        let server_task = tokio::spawn(async move {
            accept(server_stream, &actual_transport.private, &server_auth, &vk_server).await
        });

        let client_task = tokio::spawn(async move {
            connect(client_stream, &client.transport.private, &client.auth_header, &vk_client).await
        });

        let (_, client_result) = tokio::join!(server_task, client_task);
        let err = client_result
            .expect("client task panicked")
            .err()
            .expect("expected key mismatch");
        assert!(
            matches!(err, ConnectionError::BadAuth(BadAuth::PublicKeyMismatch { .. })),
            "got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Transport I/O
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn roundtrip_small_payload() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((_, mut server_rx, _), (mut client_tx, _)) =
            connect_pair(server, client, cluster_kp.public).await;

        client_tx.prepare_message(1u8).unwrap();
        client_tx.send_slice(b"hello world", true).await.unwrap();

        let header = server_rx.read_packet().await.unwrap();
        assert!(header.first);
        assert!(header.last);
        assert_eq!(header.msg_type, 1);
        assert_eq!(server_rx.payload(), b"hello world");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn roundtrip_empty_payload() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((_, mut server_rx, _), (mut client_tx, _)) =
            connect_pair(server, client, cluster_kp.public).await;

        client_tx.prepare_message(0u8).unwrap();
        client_tx.send_slice(&[], true).await.unwrap();

        let header = server_rx.read_packet().await.unwrap();
        assert!(header.first && header.last);
        assert_eq!(server_rx.payload(), EMPTY_PAYLOAD);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn roundtrip_large_payload_chunks_correctly() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((_, mut server_rx, _), (mut client_tx, _)) =
            connect_pair(server, client, cluster_kp.public).await;

        let data: Vec<u8> = (0u8..=255)
            .cycle()
            .take(MAX_PACKET_SIZE * 3 + 100)
            .collect();
        let to_send = data.clone();

        let client_task = tokio::spawn(async move {
            client_tx.prepare_message(2u8).unwrap();
            client_tx.send_slice(&to_send, true).await.unwrap();
        });

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut packet_count = 0usize;
            loop {
                let header = server_rx.read_packet().await.unwrap();
                if packet_count == 0 {
                    assert!(header.first, "first packet must have first flag set");
                } else {
                    assert!(!header.first, "only the first packet should have first flag set");
                }
                received.extend_from_slice(server_rx.payload());
                packet_count += 1;
                if header.last {
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

    #[tokio::test(flavor = "multi_thread")]
    async fn bidirectional_roundtrip() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((mut server_tx, mut server_rx, _), (mut client_tx, mut client_rx)) =
            connect_pair(server, client, cluster_kp.public).await;

        client_tx.prepare_message(1u8).unwrap();
        client_tx.send_slice(b"ping", true).await.unwrap();

        server_rx.read_packet().await.unwrap();
        assert_eq!(server_rx.payload(), b"ping");

        server_tx.prepare_message(2u8).unwrap();
        server_tx.send_slice(b"pong", true).await.unwrap();

        client_rx.read_packet().await.unwrap();
        assert_eq!(client_rx.payload(), b"pong");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_sequential_messages() {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server = NodeFixture::new(1, &cluster_kp);
        let client = NodeFixture::new(2, &cluster_kp);
        let ((_, mut server_rx, _), (mut client_tx, _)) =
            connect_pair(server, client, cluster_kp.public).await;

        for i in 0u8..5 {
            client_tx.prepare_message(i).unwrap();
            let payload = vec![i; 64];
            client_tx.send_slice(&payload, true).await.unwrap();

            let header = server_rx.read_packet().await.unwrap();
            assert_eq!(header.msg_type, i);
            assert_eq!(server_rx.payload(), payload.as_slice());
        }
    }
}
