use tokio::io::{AsyncRead, AsyncWrite};

use crate::packet_state::{PacketHeader, PacketKind};
use crate::packets::{PacketRx, PacketTx, ConnectionError};

// ── MessageRx ─────────────────────────────────────────────────────────────────

/// The receive half of a message transport.
///
/// Obtained from [`accept`][crate::accept] or [`connect`][crate::connect]
/// alongside a [`MessageTx`]. Reads framed messages from the underlying
/// encrypted packet stream.
///
/// Each call to [`read_message`][Self::read_message] reads the opening packet
/// and returns a [`Message`] handle. Remaining packets are consumed when the
/// message body is read. Only one message can be in progress at a time — the
/// borrow on [`Message`] prevents another call to `read_message` until it is
/// fully consumed.
pub struct MessageRx<R: AsyncRead + Unpin> {
    packets: PacketRx<R>,
    read_buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> MessageRx<R> {
    pub(crate) fn new(packets: PacketRx<R>) -> Self {
        Self { packets, read_buf: Vec::new() }
    }

    /// Wait for the next message and return a handle to it.
    ///
    /// The returned [`Message`] borrows this receiver until it is consumed via
    /// [`read_bytes`][Message::read_bytes] or [`into_packets`][Message::into_packets].
    pub async fn read_message(&mut self) -> Result<Message<'_, R>, ConnectionError> {
        let first_header = self.packets.read_packet().await?;
        Ok(Message { first_header, rx: self })
    }
}

// ── MessageTx ─────────────────────────────────────────────────────────────────

/// The transmit half of a message transport.
///
/// Obtained from [`accept`][crate::accept] or [`connect`][crate::connect]
/// alongside a [`MessageRx`]. Sends messages over the underlying encrypted
/// packet stream.
///
/// Large payloads are automatically split into packets of up to
/// [`MAX_PACKET_SIZE`][crate::packet_state::MAX_PACKET_SIZE] bytes.
pub struct MessageTx<W: AsyncWrite + Unpin> {
    packets: PacketTx<W>,
}

impl<W: AsyncWrite + Unpin> MessageTx<W> {
    pub(crate) fn new(packets: PacketTx<W>) -> Self {
        Self { packets }
    }

    /// Send a complete message from a byte slice.
    ///
    /// `msg_type` must be a 12-bit value (`0x0000`–`0x0FFF`); values above
    /// `0x0FFF` return [`ConnectionError::PacketBuilder`]. `payload` may be empty.
    pub async fn send_message<T>(&mut self, msg_type: T, payload: &[u8]) -> Result<(), ConnectionError>
    where
        T: Into<u16>,
    {
        self.packets.prepare_message(msg_type.into())?;
        self.packets.send_slice(payload, true).await
    }

    /// Stream a large message from an [`AsyncRead`] source.
    ///
    /// The reader is consumed packet-by-packet; no internal buffering beyond
    /// a single packet is required. Prefer this over `send_message` for
    /// payloads that are larger than a few hundred kilobytes.
    pub async fn send_reader<T, R>(&mut self, msg_type: T, reader: R) -> Result<(), ConnectionError>
    where
        T: Into<u16>,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.packets.prepare_message(msg_type.into())?;
        self.packets.send_reader(reader).await
    }

    /// Abandon the current in-progress message.
    ///
    /// Sends an [`Abort`][PacketKind::Abort] packet so the remote side can
    /// cleanly discard accumulated data and return
    /// [`ConnectionError::MessageAborted`]. The connection remains usable after
    /// this call.
    ///
    /// Safe to call speculatively — if no message is in progress (e.g. the
    /// sender had not yet called `send_reader`, or it already completed) this
    /// is a no-op.
    pub async fn abort_message(&mut self) -> Result<(), ConnectionError> {
        self.packets.abort_message().await
    }
}

// ── Message ───────────────────────────────────────────────────────────────────

/// A received message whose payload has not yet been consumed.
///
/// Obtained from [`MessageRx::read_message`]. The opening packet is already
/// buffered; continuation packets are read on demand when the message is
/// consumed via [`read_bytes`][Self::read_bytes] or
/// [`into_packets`][Self::into_packets]. Borrows the [`MessageRx`] that
/// produced it, preventing concurrent reads until the message is fully consumed.
///
/// If the sender calls [`MessageTx::abort_message`] mid-stream,
/// [`read_bytes`] and [`MessagePackets::next`] return
/// [`ConnectionError::MessageAborted`].
pub struct Message<'r, R: AsyncRead + Unpin> {
    first_header: PacketHeader,
    rx: &'r mut MessageRx<R>,
}

impl<'r, R: AsyncRead + Unpin> Message<'r, R> {
    /// The 12-bit message type discriminant set by the sender.
    pub fn msg_type(&self) -> u16 {
        self.first_header.msg_type
    }

    /// Consume the message, reading all packets into the receive buffer and
    /// returning a reference to the assembled payload.
    ///
    /// No allocation is performed — the returned slice borrows the buffer
    /// owned by the parent [`MessageRx`].
    ///
    /// Returns [`ConnectionError::MessageAborted`] if the sender abandons the
    /// message mid-stream.
    pub async fn read_bytes(self) -> Result<&'r [u8], ConnectionError> {
        self.rx.read_buf.clear();
        self.rx.read_buf.extend_from_slice(self.rx.packets.payload());
        if self.first_header.kind == PacketKind::Sole {
            return Ok(&self.rx.read_buf);
        }
        loop {
            let header = self.rx.packets.read_packet().await?;
            match header.kind {
                PacketKind::Abort => return Err(ConnectionError::MessageAborted),
                PacketKind::Last => {
                    self.rx.read_buf.extend_from_slice(self.rx.packets.payload());
                    return Ok(&self.rx.read_buf);
                }
                PacketKind::Mid => {
                    self.rx.read_buf.extend_from_slice(self.rx.packets.payload());
                }
                PacketKind::Sole | PacketKind::First => {
                    unreachable!("PacketReader enforces valid state transitions")
                }
            }
        }
    }

    /// Consume the message, returning an iterator over its raw packet payloads.
    ///
    /// Useful when the payload is large and should be processed or forwarded
    /// incrementally rather than assembled in memory.
    pub fn into_packets(self) -> MessagePackets<'r, R> {
        MessagePackets {
            done: false,
            first_kind: Some(self.first_header.kind),
            rx: self.rx,
        }
    }
}

// ── MessagePackets ────────────────────────────────────────────────────────────

/// A streaming iterator over the raw packet payloads of a received message.
///
/// Obtained from [`Message::into_packets`]. Each call to [`next`][Self::next]
/// returns the payload bytes of the next packet, or `None` after the last
/// packet. Concatenating all yielded slices produces the complete message
/// payload.
///
/// Returns [`Err(ConnectionError::MessageAborted)`][ConnectionError::MessageAborted]
/// if the sender abandons the message.
pub struct MessagePackets<'r, R: AsyncRead + Unpin> {
    done: bool,
    /// `Some` on the first call: the opening packet's kind (already buffered).
    /// `None` on subsequent calls: next packet must be read from the stream.
    first_kind: Option<PacketKind>,
    rx: &'r mut MessageRx<R>,
}

impl<'r, R: AsyncRead + Unpin> MessagePackets<'r, R> {
    /// Yield the next packet payload, or `None` if the message is complete.
    ///
    /// Each returned slice borrows from the [`MessageRx`] buffer and is valid
    /// until the next call to `next`.
    pub async fn next(&mut self) -> Result<Option<&[u8]>, ConnectionError> {
        if self.done {
            return Ok(None);
        }
        // First call: deliver the already-buffered opening packet payload.
        if let Some(kind) = self.first_kind.take() {
            if kind == PacketKind::Sole {
                self.done = true;
            }
            return Ok(Some(self.rx.packets.payload()));
        }
        // Subsequent calls: read the next continuation packet.
        let header = self.rx.packets.read_packet().await?;
        match header.kind {
            PacketKind::Abort => {
                self.done = true;
                Err(ConnectionError::MessageAborted)
            }
            PacketKind::Last => {
                self.done = true;
                Ok(Some(self.rx.packets.payload()))
            }
            PacketKind::Mid => {
                Ok(Some(self.rx.packets.payload()))
            }
            PacketKind::Sole | PacketKind::First => {
                unreachable!("PacketReader enforces valid state transitions")
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex};

    use crate::{
        NodeId,
        auth::AuthHeader,
        noise::TransportKeypair,
        messages::{MessageRx, MessageTx},
        packet_state::MAX_PACKET_SIZE,
        packets::{accept, connect},
        sign::SignatureKeypair,
    };

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        id: u32,
        text: String,
    }

    fn encode(msg: &Msg) -> Vec<u8> { serde_json::to_vec(msg).unwrap() }
    fn decode(bytes: &[u8]) -> Msg { serde_json::from_slice(bytes).unwrap() }

    type Tx = MessageTx<WriteHalf<DuplexStream>>;
    type Rx = MessageRx<ReadHalf<DuplexStream>>;

    async fn make_pair() -> ((Tx, Rx), (Tx, Rx)) {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server_tp = TransportKeypair::generate().unwrap();
        let client_tp = TransportKeypair::generate().unwrap();

        let server_id = NodeId::from(1u64);

        let server_auth = AuthHeader::new(server_id.clone(), None, &server_tp.public)
            .sign(&cluster_kp.private);
        let client_auth = AuthHeader::new(NodeId::from(2u64), None, &client_tp.public)
            .sign(&cluster_kp.private);

        let (client_stream, server_stream) = duplex(65537);
        let vk_s = cluster_kp.public.clone();
        let vk_c = cluster_kp.public;

        let server_task = tokio::spawn(async move {
            let ((tx, rx), _) = accept(server_stream, &server_tp.private, &server_auth, &vk_s).await.unwrap();
            (MessageTx::new(tx), MessageRx::new(rx))
        });
        let client_task = tokio::spawn(async move {
            let ((tx, rx), _) = connect(client_stream, &client_tp.private, &client_auth, &vk_c).await.unwrap();
            (MessageTx::new(tx), MessageRx::new(rx))
        });

        let (s, c) = tokio::join!(server_task, client_task);
        (s.unwrap(), c.unwrap())
    }

    // ── send_message / read_message / read_bytes ──────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn send_and_read_bytes_round_trip() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let sent = Msg { id: 1, text: "hello".into() };

        client_tx.send_message(7u16, &encode(&sent)).await.unwrap();

        let msg = server_rx.read_message().await.unwrap();
        assert_eq!(msg.msg_type(), 7);
        assert_eq!(decode(msg.read_bytes().await.unwrap()), sent);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn msg_type_is_twelve_bits() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        client_tx.send_message(0x0FFFu16, &[]).await.unwrap();
        let msg = server_rx.read_message().await.unwrap();
        assert_eq!(msg.msg_type(), 0x0FFF);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_sequential_messages() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;

        for i in 0u16..5 {
            let sent = Msg { id: i as u32, text: format!("msg-{i}") };
            client_tx.send_message(i, &encode(&sent)).await.unwrap();
            let msg = server_rx.read_message().await.unwrap();
            assert_eq!(msg.msg_type(), i);
            assert_eq!(decode(msg.read_bytes().await.unwrap()), sent);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bidirectional() {
        let ((mut server_tx, mut server_rx), (mut client_tx, mut client_rx)) = make_pair().await;

        client_tx.send_message(1u16, &encode(&Msg { id: 10, text: "ping".into() })).await.unwrap();
        let ping = decode(server_rx.read_message().await.unwrap().read_bytes().await.unwrap());
        assert_eq!(ping.id, 10);

        server_tx.send_message(2u16, &encode(&Msg { id: 20, text: "pong".into() })).await.unwrap();
        let pong = decode(client_rx.read_message().await.unwrap().read_bytes().await.unwrap());
        assert_eq!(pong.id, 20);
    }

    // ── Large message (multi-packet) ──────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn large_message_round_trip() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let sent = Msg { id: 99, text: "x".repeat(MAX_PACKET_SIZE * 3) };
        let payload = encode(&sent);

        let send_task = tokio::spawn(async move {
            client_tx.send_message(3u16, &payload).await.unwrap();
            sent
        });
        let recv_task = tokio::spawn(async move {
            let bytes = server_rx.read_message().await.unwrap().read_bytes().await.unwrap();
            decode(bytes)
        });

        let (send_res, recv_res) = tokio::join!(send_task, recv_task);
        assert_eq!(send_res.unwrap(), recv_res.unwrap());
    }

    // ── into_packets ──────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn into_packets_concatenates_to_original_payload() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let payload = encode(&Msg { id: 5, text: "chunks".into() });

        client_tx.send_message(4u16, &payload).await.unwrap();

        let mut packets = server_rx.read_message().await.unwrap().into_packets();
        let mut full = Vec::new();
        while let Some(chunk) = packets.next().await.unwrap() {
            full.extend_from_slice(chunk);
        }
        assert_eq!(full, payload);
    }

    // ── send_reader ───────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn send_reader_and_read_bytes() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let msg = Msg { id: 42, text: "via reader".into() };
        let payload = encode(&msg);

        client_tx.send_reader(6u16, std::io::Cursor::new(payload.clone())).await.unwrap();

        let received = decode(server_rx.read_message().await.unwrap().read_bytes().await.unwrap());
        assert_eq!(received, msg);
    }

    // ── abort ─────────────────────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn abort_mid_stream_returns_message_aborted() {
        use crate::packets::ConnectionError;

        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;

        // Sender starts a large multi-packet message then aborts it.
        let send_task = tokio::spawn(async move {
            let large = vec![0u8; MAX_PACKET_SIZE * 2];
            // send_reader drives the full stream; instead use send_message with
            // a multi-packet payload then abort on a separate message.
            // To test abort on a streaming send we use the lower-level API via
            // a second channel approach: send first packet then abort.
            client_tx.packets.prepare_message(9u16).unwrap();
            client_tx.packets.send_slice(&large[..MAX_PACKET_SIZE], false).await.unwrap();
            client_tx.abort_message().await.unwrap();
            // Send a clean message afterwards so the receiver can proceed.
            client_tx.send_message(10u16, b"after abort").await.unwrap();
        });

        let recv_task = tokio::spawn(async move {
            // First message should yield MessageAborted.
            let msg = server_rx.read_message().await.unwrap();
            assert_eq!(msg.msg_type(), 9);
            let mut pkts = msg.into_packets();
            // First packet arrives normally.
            pkts.next().await.unwrap().unwrap();
            // Second "packet" is the abort — should surface as error.
            let err = pkts.next().await.unwrap_err();
            assert!(matches!(err, ConnectionError::MessageAborted), "got: {err:?}");

            // Connection is still alive — read the next clean message.
            let clean = server_rx.read_message().await.unwrap();
            assert_eq!(clean.msg_type(), 10);
            assert_eq!(clean.read_bytes().await.unwrap(), b"after abort");
        });

        let (s, r) = tokio::join!(send_task, recv_task);
        s.unwrap();
        r.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn abort_read_bytes_returns_message_aborted() {
        use crate::packets::ConnectionError;

        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;

        let send_task = tokio::spawn(async move {
            let large = vec![0u8; MAX_PACKET_SIZE * 2];
            client_tx.packets.prepare_message(11u16).unwrap();
            client_tx.packets.send_slice(&large[..MAX_PACKET_SIZE], false).await.unwrap();
            client_tx.abort_message().await.unwrap();
            client_tx.send_message(12u16, b"clean").await.unwrap();
        });

        let recv_task = tokio::spawn(async move {
            let msg = server_rx.read_message().await.unwrap();
            assert_eq!(msg.msg_type(), 11);
            let err = msg.read_bytes().await.unwrap_err();
            assert!(matches!(err, ConnectionError::MessageAborted));

            let clean = server_rx.read_message().await.unwrap();
            assert_eq!(clean.msg_type(), 12);
            assert_eq!(clean.read_bytes().await.unwrap(), b"clean");
        });

        let (s, r) = tokio::join!(send_task, recv_task);
        s.unwrap();
        r.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn abort_no_op_when_not_in_progress() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;

        let send_task = tokio::spawn(async move {
            // abort with no message in progress — should be a no-op
            client_tx.abort_message().await.unwrap();
            client_tx.send_message(1u16, b"hello").await.unwrap();
        });

        let recv_task = tokio::spawn(async move {
            let msg = server_rx.read_message().await.unwrap();
            assert_eq!(msg.msg_type(), 1);
            assert_eq!(msg.read_bytes().await.unwrap(), b"hello");
        });

        let (s, r) = tokio::join!(send_task, recv_task);
        s.unwrap();
        r.unwrap();
    }

    // ── tx and rx work independently in separate tasks ────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn halves_work_in_separate_tasks() {
        let ((mut server_tx, mut server_rx), (mut client_tx, mut client_rx)) = make_pair().await;

        let send = tokio::spawn(async move {
            client_tx.send_message(5u16, &encode(&Msg { id: 1, text: "a".into() })).await.unwrap();
        });
        let recv = tokio::spawn(async move {
            let msg = server_rx.read_message().await.unwrap();
            assert_eq!(msg.msg_type(), 5);
            decode(msg.read_bytes().await.unwrap())
        });
        let (_, recv_res) = tokio::join!(send, recv);
        assert_eq!(recv_res.unwrap().id, 1);

        server_tx.send_message(6u16, &encode(&Msg { id: 2, text: "b".into() })).await.unwrap();
        let pong = decode(client_rx.read_message().await.unwrap().read_bytes().await.unwrap());
        assert_eq!(pong.id, 2);
    }
}
