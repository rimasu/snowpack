use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::packet_state::PacketHeader;
use crate::packets::{PacketRx, PacketTx, ConnectionError};

// ---------------------------------------------------------------------------
// MessageRx
// ---------------------------------------------------------------------------

/// The receive half of a message transport.
///
/// Obtained from [`accept`][crate::accept] or [`connect`][crate::connect] alongside
/// a [`MessageTx`]. Reads framed messages from the underlying encrypted packet stream.
/// Each call to [`read_message`][MessageRx::read_message] reads the first packet and
/// returns a [`Message`] handle; remaining packets are consumed when the message is
/// decoded or iterated. Only one message can be in progress at a time — the borrow on
/// [`Message`] prevents another call to `read_message` until it is consumed.
pub struct MessageRx<R: AsyncRead + Unpin> {
    packets: PacketRx<R>,
    read_buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> MessageRx<R> {
    pub(crate) fn new(packets: PacketRx<R>) -> Self {
        Self { packets, read_buf: Vec::new() }
    }

    pub async fn read_message(&mut self) -> Result<Message<'_, R>, ConnectionError> {
        let first_header = self.packets.read_packet().await?;
        Ok(Message { first_header, rx: self })
    }
}

// ---------------------------------------------------------------------------
// MessageTx
// ---------------------------------------------------------------------------

/// The transmit half of a message transport.
///
/// Obtained from [`accept`][crate::accept] or [`connect`][crate::connect] alongside
/// a [`MessageRx`]. Serializes and sends messages over the underlying encrypted packet
/// stream. Structured messages are postcard-encoded via
/// [`send_message`][MessageTx::send_message]; raw byte streams (e.g. snapshot data)
/// are forwarded via [`send_reader`][MessageTx::send_reader]. Both paths split the
/// payload into packets of up to 65,519 bytes before encryption.
pub struct MessageTx<W: AsyncWrite + Unpin> {
    packets: PacketTx<W>,
    write_buf: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> MessageTx<W> {
    pub(crate) fn new(packets: PacketTx<W>) -> Self {
        Self { packets, write_buf: Vec::new() }
    }

    pub async fn send_message<T, M>(&mut self, msg_type: T, message: &M) -> Result<(), ConnectionError>
    where
        T: Into<u8>,
        M: Serialize,
    {
        self.write_buf.clear();
        postcard::to_io(message, &mut self.write_buf)
            .map_err(|e| ConnectionError::MessageSerialization(e.to_string()))?;
        self.packets.prepare_message(msg_type.into())?;
        self.packets.send_slice(&self.write_buf, true).await
    }

    pub async fn send_reader<T, R>(&mut self, msg_type: T, reader: R) -> Result<(), ConnectionError>
    where
        T: Into<u8>,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.packets.prepare_message(msg_type.into())?;
        self.packets.send_reader(reader).await
    }
}

// ---------------------------------------------------------------------------
// Message — borrows MessageRx so it can read continuation packets
// ---------------------------------------------------------------------------

/// A received message whose payload has not yet been consumed.
///
/// Obtained from [`MessageRx::read_message`]. The first packet is already buffered;
/// remaining packets are read on demand when the message is consumed via
/// [`decode`][Message::decode] or [`into_packets`][Message::into_packets].
/// Borrows the [`MessageRx`] that produced it, preventing concurrent reads until
/// the message is fully consumed.
pub struct Message<'r, R: AsyncRead + Unpin> {
    first_header: PacketHeader,
    rx: &'r mut MessageRx<R>,
}

impl<'r, R: AsyncRead + Unpin> Message<'r, R> {
    pub fn msg_type(&self) -> u8 {
        self.first_header.msg_type
    }

    /// Consume the message, reading all packets and deserializing the payload.
    pub async fn decode<T: for<'de> Deserialize<'de>>(self) -> Result<T, ConnectionError> {
        let data = self.read_slice().await?;
        postcard::from_bytes(data).map_err(|e| ConnectionError::MessageSerialization(e.to_string()))
    }

    /// Consume the message, returning an iterator over its raw packet payloads.
    pub fn into_packets(self) -> MessagePackets<'r, R> {
        MessagePackets {
            last_sent: false,
            first_last: Some(self.first_header.last),
            rx: self.rx,
        }
    }

    async fn read_slice(self) -> Result<&'r [u8], ConnectionError> {
        self.rx.read_buf.clear();
        self.rx.read_buf.extend_from_slice(self.rx.packets.payload());
        let mut last = self.first_header.last;
        while !last {
            let header = self.rx.packets.read_packet().await?;
            self.rx.read_buf.extend_from_slice(self.rx.packets.payload());
            last = header.last;
        }
        Ok(&self.rx.read_buf)
    }
}

// ---------------------------------------------------------------------------
// MessagePackets — streaming raw packet payloads from a Message
// ---------------------------------------------------------------------------

/// A streaming iterator over the raw packet payloads of a received message.
///
/// Obtained from [`Message::into_packets`]. Each call to [`next`][MessagePackets::next]
/// returns the payload bytes of the next packet, or `None` after the last packet.
/// Concatenating all payloads yields the full message payload — postcard-encoded
/// when the message was sent via [`MessageTx::send_message`], raw bytes when sent
/// via [`MessageTx::send_reader`].
pub struct MessagePackets<'r, R: AsyncRead + Unpin> {
    last_sent: bool,
    first_last: Option<bool>,
    rx: &'r mut MessageRx<R>,
}

impl<'r, R: AsyncRead + Unpin> MessagePackets<'r, R> {
    pub async fn next(&mut self) -> Result<Option<&[u8]>, ConnectionError> {
        if self.last_sent {
            return Ok(None);
        }
        let last = if let Some(first_last) = self.first_last.take() {
            first_last
        } else {
            let header = self.rx.packets.read_packet().await?;
            header.last
        };
        self.last_sent = last;
        Ok(Some(self.rx.packets.payload()))
    }
}

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

    type Tx = MessageTx<WriteHalf<DuplexStream>>;
    type Rx = MessageRx<ReadHalf<DuplexStream>>;

    async fn make_pair() -> ((Tx, Rx), (Tx, Rx)) {
        let cluster_kp = SignatureKeypair::generate().unwrap();
        let server_tp = TransportKeypair::generate().unwrap();
        let client_tp = TransportKeypair::generate().unwrap();

        let server_id = NodeId::from(1u64);

        let server_auth = AuthHeader::new(server_id.clone(), &server_tp.public)
            .sign(&cluster_kp.private).unwrap();
        let client_auth = AuthHeader::new(NodeId::from(2u64), &client_tp.public)
            .sign(&cluster_kp.private).unwrap();

        let (client_stream, server_stream) = duplex(65537);
        let vk_s = cluster_kp.public.clone();
        let vk_c = cluster_kp.public;

        let server_task = tokio::spawn(async move {
            let ((tx, rx), _) = accept(server_stream, &server_tp.private, &server_auth, &vk_s).await.unwrap();
            (MessageTx::new(tx), MessageRx::new(rx))
        });
        let client_task = tokio::spawn(async move {
            let (tx, rx) = connect(client_stream, server_id, &client_tp.private, &client_auth, &vk_c).await.unwrap();
            (MessageTx::new(tx), MessageRx::new(rx))
        });

        let (s, c) = tokio::join!(server_task, client_task);
        (s.unwrap(), c.unwrap())
    }

    // -----------------------------------------------------------------------
    // send_message / read_message / decode
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn send_and_decode_round_trip() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let sent = Msg { id: 1, text: "hello".into() };

        client_tx.send_message(7u8, &sent).await.unwrap();

        let msg = server_rx.read_message().await.unwrap();
        assert_eq!(msg.msg_type(), 7);
        assert_eq!(msg.decode::<Msg>().await.unwrap(), sent);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn multiple_sequential_messages() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;

        for i in 0u8..5 {
            let sent = Msg { id: i as u32, text: format!("msg-{i}") };
            client_tx.send_message(i, &sent).await.unwrap();
            let msg = server_rx.read_message().await.unwrap();
            assert_eq!(msg.msg_type(), i);
            assert_eq!(msg.decode::<Msg>().await.unwrap(), sent);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bidirectional() {
        let ((mut server_tx, mut server_rx), (mut client_tx, mut client_rx)) = make_pair().await;

        client_tx.send_message(1u8, &Msg { id: 10, text: "ping".into() }).await.unwrap();
        let ping: Msg = server_rx.read_message().await.unwrap().decode().await.unwrap();
        assert_eq!(ping.id, 10);

        server_tx.send_message(2u8, &Msg { id: 20, text: "pong".into() }).await.unwrap();
        let pong: Msg = client_rx.read_message().await.unwrap().decode().await.unwrap();
        assert_eq!(pong.id, 20);
    }

    // -----------------------------------------------------------------------
    // Large message (exercises multi-packet chunking)
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn large_message_round_trip() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let sent = Msg { id: 99, text: "x".repeat(MAX_PACKET_SIZE * 3) };

        let send_task = tokio::spawn(async move {
            client_tx.send_message(3u8, &sent).await.unwrap();
            sent
        });
        let recv_task = tokio::spawn(async move {
            server_rx.read_message().await.unwrap().decode::<Msg>().await.unwrap()
        });

        let (send_res, recv_res) = tokio::join!(send_task, recv_task);
        assert_eq!(send_res.unwrap(), recv_res.unwrap());
    }

    // -----------------------------------------------------------------------
    // into_packets — raw streaming
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn into_packets_concatenates_to_postcard_encoding() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let msg = Msg { id: 5, text: "chunks".into() };
        let expected = postcard::to_allocvec(&msg).unwrap();

        client_tx.send_message(4u8, &msg).await.unwrap();

        let mut packets = server_rx.read_message().await.unwrap().into_packets();
        let mut full = Vec::new();
        while let Some(chunk) = packets.next().await.unwrap() {
            full.extend_from_slice(chunk);
        }
        assert_eq!(full, expected);
    }

    // -----------------------------------------------------------------------
    // send_reader
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn send_reader_and_decode() {
        let ((_, mut server_rx), (mut client_tx, _)) = make_pair().await;
        let msg = Msg { id: 42, text: "via reader".into() };
        let encoded = postcard::to_allocvec(&msg).unwrap();

        client_tx.send_reader(6u8, std::io::Cursor::new(encoded)).await.unwrap();

        let received: Msg = server_rx.read_message().await.unwrap().decode().await.unwrap();
        assert_eq!(received, msg);
    }

    // -----------------------------------------------------------------------
    // tx and rx work independently in separate tasks
    // -----------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn halves_work_in_separate_tasks() {
        let ((mut server_tx, mut server_rx), (mut client_tx, mut client_rx)) = make_pair().await;

        let send = tokio::spawn(async move {
            client_tx.send_message(5u8, &Msg { id: 1, text: "a".into() }).await.unwrap();
        });
        let recv = tokio::spawn(async move {
            let msg = server_rx.read_message().await.unwrap();
            assert_eq!(msg.msg_type(), 5);
            msg.decode::<Msg>().await.unwrap()
        });
        let (_, recv_res) = tokio::join!(send, recv);
        assert_eq!(recv_res.unwrap().id, 1);

        server_tx.send_message(6u8, &Msg { id: 2, text: "b".into() }).await.unwrap();
        let pong: Msg = client_rx.read_message().await.unwrap().decode().await.unwrap();
        assert_eq!(pong.id, 2);
    }
}
