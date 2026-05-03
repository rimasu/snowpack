use serde::Deserialize;
use serde::Serialize;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

use crate::packet::Packet;
use crate::packet_transport::PacketTransport;
use crate::packet_transport::TransportError;

pub struct MessageTransport<S> {
    pub packets: PacketTransport<S>,

    /// Scratch buffer for inbound plain text to support read_message; grown as needed, never shrunk.
    read_buf: Vec<u8>,

    /// Scratch buffer for outbound plain text to support read_message; grown as needed, never shrunk.
    write_buf: Vec<u8>,
}

pub struct Message {
    first_packet: Packet,
}

impl Message {
    pub fn msg_type(&self) -> u8 {
        self.first_packet.msg_type
    }
}

pub struct MessagePackets<'t, S> {
    last_sent: bool,
    first_packet: Option<Packet>,
    packets: &'t mut PacketTransport<S>,
}

impl<'t, S> MessagePackets<'t, S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn next(&mut self) -> Result<Option<&[u8]>, TransportError> {
        if self.last_sent {
            Ok(None)
        } else {
            let packet = if let Some(first_packet) = self.first_packet.take() {
                first_packet
            } else {
                self.packets.read_packet().await?
            };

            self.last_sent = packet.last;
            Ok(Some(self.packets.packet_data(&packet)))
        }
    }
}

impl<S> MessageTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(packet_transport: PacketTransport<S>) -> Self {
        Self {
            packets: packet_transport,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    pub async fn read_message(&mut self) -> Result<Message, TransportError> {
        let first_packet = self.packets.read_packet().await?;
        Ok(Message { first_packet })
    }

    pub async fn decode_unlimited<'s, T: Deserialize<'s>>(
        &'s mut self,
        msg: Message,
    ) -> Result<T, TransportError> {
        // to do avoid pushing this into a buffer
        let data = self.read_unlimited_slice(msg).await?;
        postcard::from_bytes(data).map_err(|e| TransportError::MessageSerialization(e.to_string()))
    }

    pub fn into_packets(&mut self, msg: Message) -> MessagePackets<'_, S> {
        MessagePackets {
            last_sent: false,
            first_packet: Some(msg.first_packet),
            packets: &mut self.packets,
        }
    }

    pub async fn read_unlimited_slice(&mut self, msg: Message) -> Result<&[u8], TransportError> {
        self.read_buf.clear();
        self.read_buf
            .extend_from_slice(self.packets.packet_data(&msg.first_packet));
        let mut last = msg.first_packet.last;
        while !last {
            let packet = self.packets.read_packet().await?;
            self.read_buf
                .extend_from_slice(self.packets.packet_data(&packet));
            last = packet.last;
        }

        Ok(&self.read_buf)
    }

    pub async fn send_message<T, M>(
        &mut self,
        msg_type: T,
        message: &M,
    ) -> Result<(), TransportError>
    where
        T: Into<u8>,
        M: Serialize,
    {
        self.write_buf.clear();
        postcard::to_io(message, &mut self.write_buf)
            .map_err(|e| TransportError::MessageSerialization(e.to_string()))?;
        self.packets.prepare_message(msg_type.into())?;
        self.packets.send_slice(&self.write_buf, true).await
    }

    pub async fn send_reader<T, R>(&mut self, msg_type: T, reader: R) -> Result<(), TransportError>
    where
        T: Into<u8>,
        R: tokio::io::AsyncRead + Unpin,
    {
        self.packets.prepare_message(msg_type.into())?;
        self.packets.send_reader(reader).await?;
        Ok(())
    }
}
