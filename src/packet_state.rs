const FIRST_PACKET_MASK: u8 = 0b1000_0000;
const LAST_PACKET_MASK: u8 = 0b0100_0000;
const MSG_TYPE_MASK: u8 = 0b0011_1111;

/// Errors returned by PacketBuilder.
#[derive(thiserror::Error, Debug)]
pub enum PacketBuildError {
    /// prepare was called while a message was already in progress.
    #[error("message already in progress")]
    MessageAlreadyInProgress,

    /// pack was called before prepare.
    #[error("no message in progress")]
    NoMessageInProgress,
}

/// Builds framed packets for transmission over a noise/snow encrypted transport.
///
/// A message is split into one or more packets. Each packet carries a one-byte
/// header followed by a payload. The header encodes whether this is the first
/// packet of a message, whether it is the last, and the message type.
///
/// Usage:
///   1. Call prepare to start a new message and set the message type.
///   2. Call pack one or more times, passing last = true on the final chunk.
///   3. The returned slice is valid until the next call to pack or prepare.
pub(crate) struct PacketBuilder {
    in_progress: bool,
    header: u8,
    buf: Vec<u8>,
}

impl PacketBuilder {
    /// Create a new PacketBuilder.
    pub(crate) fn new() -> PacketBuilder {
        PacketBuilder {
            in_progress: false,
            header: 0,
            buf: Vec::with_capacity(MAX_RAW_PACKET_SIZE),
        }
    }

    /// Begin a new message with the given message type.
    ///
    /// msg_type is masked to the lower six bits. Returns
    /// MessageAlreadyInProgress if pack has not yet been called with
    /// last = true for the previous message.
    pub(crate) fn prepare(&mut self, msg_type: u8) -> Result<(), PacketBuildError> {
        if self.in_progress {
            Err(PacketBuildError::MessageAlreadyInProgress)
        } else {
            self.in_progress = true;
            self.header = msg_type & MSG_TYPE_MASK | FIRST_PACKET_MASK;
            Ok(())
        }
    }

    /// Pack a payload slice into a raw packet and return it.
    ///
    /// The returned slice is borrowed from internal storage and remains valid
    /// until the next call to pack or prepare.
    ///
    /// Set last = true on the final chunk of a message. This sets the last-packet
    /// flag in the header and allows prepare to be called again afterwards.
    ///
    /// Returns NoMessageInProgress if prepare has not been called.
    pub(crate) fn pack(&mut self, payload: &[u8], last: bool) -> Result<&[u8], PacketBuildError> {
        if !self.in_progress {
            return Err(PacketBuildError::NoMessageInProgress);
        }

        if last {
            self.header |= LAST_PACKET_MASK;
        }

        self.buf.clear();
        self.buf.push(self.header);
        self.buf.extend_from_slice(payload);
        self.in_progress = !last;
        self.header &= !FIRST_PACKET_MASK;

        Ok(&self.buf)
    }
}

/// Errors returned by PacketReader.
#[derive(thiserror::Error, Debug)]
pub enum PacketReadError {
    /// The raw packet slice was empty, so there was no header byte.
    #[error("raw packet empty")]
    RawPacketEmpty,

    /// A first-packet arrived while a message was already in progress.
    /// from is the message type of the message in progress, to is the
    /// type of the unexpected packet.
    #[error("unexpected first ({from} -> {to})")]
    UnexpectedFirst { from: u8, to: u8 },

    /// A last-packet arrived with no message in progress.
    #[error("unexpected last ({msg_type})")]
    UnexpectedLast { msg_type: u8 },

    /// A continuation packet arrived whose message type differs from the
    /// message currently in progress.
    #[error("message type change ({from} -> {to})")]
    MessageTypeChange { from: u8, to: u8 },

    /// A continuation or last packet arrived with no message in progress,
    /// i.e. the first packet was never seen.
    #[error("missing first ({msg_type})")]
    MissingFirst { msg_type: u8 },
}

pub(crate) const MAX_CIPHERTEXT_SIZE: usize = 0xFFFF;
pub(crate) const CIPHER_OVERHEAD_SIZE: usize = 16;
pub(crate) const MAX_RAW_PACKET_SIZE: usize = MAX_CIPHERTEXT_SIZE - CIPHER_OVERHEAD_SIZE;
pub(crate) const MAX_PACKET_SIZE: usize = MAX_RAW_PACKET_SIZE - 1;

/// Reads and validates framed packets arriving from a noise/snow encrypted transport.
///
/// Maintains state across successive calls to read so that multi-packet messages
/// can be validated for consistency. A Packet returned by read borrows directly
/// from the raw_packet slice passed in, so no copying of the payload occurs.
pub(crate) struct PacketReader {
    in_progress: bool,
    msg_type: u8,
}

impl PacketReader {
    /// Create a new PacketReader.
    pub(crate) fn new() -> PacketReader {
        PacketReader {
            in_progress: false,
            msg_type: 0,
        }
    }

    /// Read and validate a raw packet.
    ///
    /// Checks the header flags and message type against the current reader
    /// state and returns an error if anything is inconsistent. On success
    /// returns a Packet whose payload slice borrows from raw_packet.
    ///
    /// Errors:
    ///   RawPacketEmpty        - raw_packet has no bytes at all
    ///   UnexpectedFirst       - first-packet flag set while a message is in progress
    ///   MissingFirst          - continuation or last packet with no message in progress
    ///   MessageTypeChange     - message type differs from the one started by the first packet
    ///   UnexpectedLast        - last-packet flag set with no message in progress
    pub(crate) fn read(&mut self, raw_packet: &[u8]) -> Result<PacketHeader, PacketReadError> {
        if raw_packet.is_empty() {
            return Err(PacketReadError::RawPacketEmpty);
        }

        let header = raw_packet[0];
        let first = header & FIRST_PACKET_MASK != 0;
        let last = header & LAST_PACKET_MASK != 0;
        let msg_type = header & MSG_TYPE_MASK;

        if first {
            if self.in_progress {
                return Err(PacketReadError::UnexpectedFirst {
                    from: self.msg_type,
                    to: msg_type,
                });
            } else {
                self.in_progress = true;
                self.msg_type = msg_type;
            }
        } else if self.in_progress && self.msg_type != msg_type {
            return Err(PacketReadError::MessageTypeChange {
                from: self.msg_type,
                to: msg_type,
            });
        } else if !self.in_progress {
            return Err(PacketReadError::MissingFirst { msg_type });
        }

        if last {
            if self.in_progress {
                self.in_progress = false;
                self.msg_type = 0;
            } else {
                return Err(PacketReadError::UnexpectedLast { msg_type });
            }
        }

        Ok(PacketHeader { first, last, msg_type })
    }
}

/// The decoded header of a successfully parsed packet.
///
/// The reader has already verified that this packet is consistent with the
/// current message in progress. The payload is not included here — callers
/// retrieve it from the buffer they passed to `PacketReader::read`.
pub(crate) struct PacketHeader {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) first: bool,
    pub(crate) last: bool,
    pub(crate) msg_type: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // PacketBuilder
    // -------------------------------------------------------------------------

    #[test]
    fn builder_single_packet_message() {
        let mut b = PacketBuilder::new();
        b.prepare(1).unwrap();
        let raw = b.pack(b"hello", true).unwrap();
        // first and last bits set, msg_type 1
        assert_eq!(raw[0], FIRST_PACKET_MASK | LAST_PACKET_MASK | 1);
        assert_eq!(&raw[1..], b"hello");
    }

    #[test]
    fn builder_multi_packet_message() {
        let mut b = PacketBuilder::new();
        b.prepare(2).unwrap();

        let first = b.pack(b"part1", false).unwrap();
        assert_eq!(first[0] & FIRST_PACKET_MASK, FIRST_PACKET_MASK);
        assert_eq!(first[0] & LAST_PACKET_MASK, 0);
        assert_eq!(&first[1..], b"part1");

        let last = b.pack(b"part2", true).unwrap();
        assert_eq!(last[0] & FIRST_PACKET_MASK, 0);
        assert_eq!(last[0] & LAST_PACKET_MASK, LAST_PACKET_MASK);
        assert_eq!(&last[1..], b"part2");
    }

    #[test]
    fn builder_msg_type_masked_to_six_bits() {
        let mut b = PacketBuilder::new();
        b.prepare(0xFF).unwrap();
        let raw = b.pack(b"x", true).unwrap();
        assert_eq!(raw[0] & MSG_TYPE_MASK, 0x3F);
    }

    #[test]
    fn builder_reuse_after_message_complete() {
        let mut b = PacketBuilder::new();
        b.prepare(1).unwrap();
        b.pack(b"a", true).unwrap();
        // should be able to start a new message
        b.prepare(2).unwrap();
        let raw = b.pack(b"b", true).unwrap();
        assert_eq!(raw[0] & MSG_TYPE_MASK, 2);
    }

    #[test]
    fn builder_prepare_while_in_progress_is_error() {
        let mut b = PacketBuilder::new();
        b.prepare(1).unwrap();
        let err = b.prepare(2).unwrap_err();
        assert!(matches!(err, PacketBuildError::MessageAlreadyInProgress));
    }

    #[test]
    fn builder_pack_without_prepare_is_error() {
        let mut b = PacketBuilder::new();
        let err = b.pack(b"data", true).unwrap_err();
        assert!(matches!(err, PacketBuildError::NoMessageInProgress));
    }

    #[test]
    fn builder_empty_payload_is_allowed() {
        let mut b = PacketBuilder::new();
        b.prepare(0).unwrap();
        let raw = b.pack(b"", true).unwrap();
        assert_eq!(raw.len(), 1);
    }

    // -------------------------------------------------------------------------
    // PacketReader
    // -------------------------------------------------------------------------

    #[test]
    fn reader_single_packet_message() {
        let mut r = PacketReader::new();
        let header = FIRST_PACKET_MASK | LAST_PACKET_MASK | 3;
        let raw = [header, 0xAA, 0xBB];
        let pkt = r.read(&raw).unwrap();
        assert!(pkt.first);
        assert!(pkt.last);
        assert_eq!(pkt.msg_type, 3);
    }

    #[test]
    fn reader_multi_packet_message() {
        let mut r = PacketReader::new();

        let first_header = FIRST_PACKET_MASK | 5;
        let buf = [first_header, 1, 2];
        let p1 = r.read(&buf).unwrap();
        assert!(p1.first);
        assert!(!p1.last);
        assert_eq!(p1.msg_type, 5);

        let cont_header = 5;
        let buf = [cont_header, 3, 4];
        let p2 = r.read(&buf).unwrap();
        assert!(!p2.first);
        assert!(!p2.last);

        let last_header = LAST_PACKET_MASK | 5;
        let buf = [last_header, 5, 6];
        let p3 = r.read(&buf).unwrap();
        assert!(!p3.first);
        assert!(p3.last);
    }

    #[test]
    fn reader_reuse_after_message_complete() {
        let mut r = PacketReader::new();
        let h = FIRST_PACKET_MASK | LAST_PACKET_MASK | 1;
        r.read(&[h]).unwrap();
        // second message should succeed
        let h2 = FIRST_PACKET_MASK | LAST_PACKET_MASK | 2;
        let buf = [h2];
        let pkt = r.read(&buf).unwrap();
        assert_eq!(pkt.msg_type, 2);
    }

    #[test]
    fn reader_empty_packet_is_error() {
        let mut r = PacketReader::new();
        let err = r.read(&[]).err().unwrap();
        assert!(matches!(err, PacketReadError::RawPacketEmpty));
    }

    #[test]
    fn reader_unexpected_first_is_error() {
        let mut r = PacketReader::new();
        // start message type 1
        r.read(&[FIRST_PACKET_MASK | 1]).unwrap();
        // another first packet arrives before the message ends
        let err = r.read(&[FIRST_PACKET_MASK | 2]).err().unwrap();
        assert!(matches!(
            err,
            PacketReadError::UnexpectedFirst { from: 1, to: 2 }
        ));
    }

    #[test]
    fn reader_missing_first_is_error() {
        let mut r = PacketReader::new();
        // continuation with no prior first packet
        let err = r.read(&[7]).err().unwrap();
        assert!(matches!(err, PacketReadError::MissingFirst { msg_type: 7 }));
    }

    #[test]
    fn reader_message_type_change_is_error() {
        let mut r = PacketReader::new();
        r.read(&[FIRST_PACKET_MASK | 4]).unwrap();
        // continuation with different msg_type
        let err = r.read(&[5]).err().unwrap();
        assert!(matches!(
            err,
            PacketReadError::MessageTypeChange { from: 4, to: 5 }
        ));
    }

    #[test]
    fn reader_payload_empty_is_allowed() {
        let mut r = PacketReader::new();
        let h = FIRST_PACKET_MASK | LAST_PACKET_MASK;
        let buf = [h];
        let pkt = r.read(&buf).unwrap();
        assert!(pkt.first && pkt.last);
    }

    // -------------------------------------------------------------------------
    // Round-trip: builder then reader
    // -------------------------------------------------------------------------

    #[test]
    fn roundtrip_single_packet() {
        let mut b = PacketBuilder::new();
        let mut r = PacketReader::new();

        b.prepare(10).unwrap();
        let raw = b.pack(b"roundtrip", true).unwrap().to_owned();
        let pkt = r.read(&raw).unwrap();

        assert!(pkt.first);
        assert!(pkt.last);
        assert_eq!(pkt.msg_type, 10);
        assert_eq!(&raw[1..], b"roundtrip");
    }

    #[test]
    fn roundtrip_multi_packet() {
        let mut b = PacketBuilder::new();
        let mut r = PacketReader::new();

        b.prepare(7).unwrap();
        let p1 = b.pack(b"foo", false).unwrap().to_owned();
        let p2 = b.pack(b"bar", true).unwrap().to_owned();

        let pkt1 = r.read(&p1).unwrap();
        assert!(pkt1.first && !pkt1.last);
        assert_eq!(&p1[1..], b"foo");

        let pkt2 = r.read(&p2).unwrap();
        assert!(!pkt2.first && pkt2.last);
        assert_eq!(&p2[1..], b"bar");
    }
}
