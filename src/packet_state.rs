/// The four high bits of the 2-byte header encode the packet kind.
const KIND_SHIFT: u16 = 12;
const KIND_MASK: u16 = 0xF000;
/// The twelve low bits encode the message type.
const TYPE_MASK: u16 = 0x0FFF;

// ── PacketKind ────────────────────────────────────────────────────────────────

/// The structural role of a packet within a message stream.
///
/// Every packet carries a 4-bit kind in the high nibble of its 2-byte header.
/// The kind determines how the packet relates to the message it belongs to and
/// drives the receiver's state machine.
///
/// | Kind    | Sender has called…                    | Receiver should…                |
/// |---------|---------------------------------------|---------------------------------|
/// | `Sole`  | `send_message` (fits in one packet)   | deliver complete message        |
/// | `First` | started a multi-packet message        | open a new in-progress message  |
/// | `Mid`   | sent more data for the current message| accumulate payload              |
/// | `Last`  | finished the current message          | close and deliver the message   |
/// | `Abort` | abandoned the current message         | discard accumulated payload     |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    /// A complete message that fits in a single packet.
    Sole  = 0,
    /// The first packet of a multi-packet message.
    First = 1,
    /// A continuation packet — more packets follow.
    Mid   = 2,
    /// The final packet of a multi-packet message, delivered successfully.
    Last  = 3,
    /// The sender is abandoning the in-progress message. The receiver should
    /// discard any accumulated payload and return
    /// [`ConnectionError::MessageAborted`][crate::ConnectionError::MessageAborted].
    Abort = 4,
}

impl PacketKind {
    fn from_u8(v: u8) -> Result<Self, PacketReadError> {
        match v {
            0 => Ok(PacketKind::Sole),
            1 => Ok(PacketKind::First),
            2 => Ok(PacketKind::Mid),
            3 => Ok(PacketKind::Last),
            4 => Ok(PacketKind::Abort),
            _ => Err(PacketReadError::UnknownKind(v)),
        }
    }
}

// ── PacketBuildError ──────────────────────────────────────────────────────────

/// Errors returned by [`PacketBuilder`].
#[derive(thiserror::Error, Debug)]
pub enum PacketBuildError {
    /// [`PacketBuilder::prepare`] was called while a message was already in progress.
    #[error("message already in progress")]
    MessageAlreadyInProgress,

    /// [`PacketBuilder::pack`] or [`PacketBuilder::abort`] was called before
    /// [`PacketBuilder::prepare`].
    #[error("no message in progress")]
    NoMessageInProgress,

    /// The message type value exceeds the 12-bit maximum (`0x0FFF`).
    #[error("message type {0:#06x} exceeds maximum (0x0FFF)")]
    MessageTypeTooLarge(u16),
}

// ── PacketBuilder ─────────────────────────────────────────────────────────────

/// Builds framed packets for transmission over a Noise-encrypted transport.
///
/// A message is split into one or more packets. Each packet carries a 2-byte
/// header followed by a payload. The header encodes a [`PacketKind`] (4 bits)
/// and a message type (12 bits).
///
/// ## Usage
///
/// 1. Call [`prepare`][Self::prepare] to start a new message and record its type.
/// 2. Call [`pack`][Self::pack] one or more times with payload chunks; pass
///    `last = true` on the final chunk.
/// 3. To abandon a message before it is complete, call [`abort`][Self::abort].
pub(crate) struct PacketBuilder {
    in_progress: bool,
    is_first: bool,
    msg_type: u16,
    buf: Vec<u8>,
}

impl PacketBuilder {
    pub(crate) fn new() -> Self {
        PacketBuilder {
            in_progress: false,
            is_first: false,
            msg_type: 0,
            buf: Vec::with_capacity(MAX_RAW_PACKET_SIZE),
        }
    }

    /// Begin a new message with the given type.
    ///
    /// `msg_type` must fit in 12 bits (`0x0000`–`0x0FFF`). Returns
    /// [`PacketBuildError::MessageTypeTooLarge`] for values above `0x0FFF`, and
    /// [`PacketBuildError::MessageAlreadyInProgress`] if the previous message
    /// has not yet been terminated with `last = true` or [`abort`][Self::abort].
    pub(crate) fn prepare(&mut self, msg_type: u16) -> Result<(), PacketBuildError> {
        if msg_type > TYPE_MASK {
            return Err(PacketBuildError::MessageTypeTooLarge(msg_type));
        }
        if self.in_progress {
            return Err(PacketBuildError::MessageAlreadyInProgress);
        }
        self.in_progress = true;
        self.is_first = true;
        self.msg_type = msg_type;
        Ok(())
    }

    /// Pack a payload slice into a raw packet and return it.
    ///
    /// The returned slice is borrowed from internal storage and remains valid
    /// until the next call to [`pack`][Self::pack], [`abort`][Self::abort], or
    /// [`prepare`][Self::prepare].
    ///
    /// Set `last = true` on the final chunk of a message. This emits a [`Last`]
    /// (or [`Sole`] if this is also the first chunk) packet and allows
    /// [`prepare`][Self::prepare] to be called again afterwards.
    ///
    /// [`Last`]: PacketKind::Last
    /// [`Sole`]: PacketKind::Sole
    pub(crate) fn pack(&mut self, payload: &[u8], last: bool) -> Result<&[u8], PacketBuildError> {
        if !self.in_progress {
            return Err(PacketBuildError::NoMessageInProgress);
        }
        let kind = match (self.is_first, last) {
            (true,  true)  => PacketKind::Sole,
            (true,  false) => PacketKind::First,
            (false, false) => PacketKind::Mid,
            (false, true)  => PacketKind::Last,
        };
        let header = ((kind as u16) << KIND_SHIFT) | self.msg_type;
        self.buf.clear();
        self.buf.extend_from_slice(&header.to_be_bytes());
        self.buf.extend_from_slice(payload);
        self.is_first = false;
        self.in_progress = !last;
        Ok(&self.buf)
    }

    /// Emit an [`Abort`] packet for the current in-progress message, then reset
    /// state so a new message can be started with [`prepare`][Self::prepare].
    ///
    /// Returns `None` if no message is in progress (safe to call speculatively).
    /// Returns `Some(&[u8])` with the abort packet bytes when a message was
    /// abandoned.
    ///
    /// [`Abort`]: PacketKind::Abort
    pub(crate) fn abort(&mut self) -> Option<&[u8]> {
        if !self.in_progress {
            return None;
        }
        let header = ((PacketKind::Abort as u16) << KIND_SHIFT) | self.msg_type;
        self.buf.clear();
        self.buf.extend_from_slice(&header.to_be_bytes());
        self.in_progress = false;
        self.is_first = true;
        Some(&self.buf)
    }
}

// ── PacketReadError ───────────────────────────────────────────────────────────

/// Errors returned by [`PacketReader`].
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum PacketReadError {
    /// The raw packet had fewer than two bytes; the header cannot be decoded.
    #[error("packet too short")]
    PacketTooShort,

    /// The kind field (top 4 bits) is not one of the five defined kinds (0–4).
    #[error("unknown packet kind: {0}")]
    UnknownKind(u8),

    /// A message-start packet ([`Sole`] or [`First`]) arrived while a message
    /// was already in progress.
    ///
    /// `from` is the type of the in-progress message; `to` is the type carried
    /// by the unexpected packet.
    ///
    /// [`Sole`]: PacketKind::Sole
    /// [`First`]: PacketKind::First
    #[error("unexpected message start (in-progress type {from}, new type {to})")]
    UnexpectedMessageStart { from: u16, to: u16 },

    /// A continuation, final, or abort packet arrived with no message in progress.
    #[error("missing message start (msg_type {msg_type})")]
    MissingMessageStart { msg_type: u16 },

    /// A continuation or final packet's message type differs from the type
    /// established by the opening packet.
    #[error("message type changed ({from} -> {to})")]
    MessageTypeChange { from: u16, to: u16 },
}

// ── PacketReader ──────────────────────────────────────────────────────────────

/// Reads and validates framed packets from a Noise-encrypted transport.
///
/// Maintains state across successive calls so that multi-packet messages can
/// be validated for consistency. The payload slice returned via
/// [`PacketRx::payload`][crate::packets::PacketRx::payload] borrows from the
/// buffer passed into the containing [`PacketRx`], so no payload copying occurs.
pub(crate) struct PacketReader {
    in_progress: bool,
    msg_type: u16,
}

impl PacketReader {
    pub(crate) fn new() -> Self {
        PacketReader { in_progress: false, msg_type: 0 }
    }

    /// Decode and validate a raw (decrypted) packet.
    ///
    /// `raw_packet` must contain the full plaintext produced by the Noise
    /// transport layer — 2 header bytes followed by the payload.
    ///
    /// Returns the [`PacketHeader`] on success. Errors:
    ///
    /// - [`PacketTooShort`] — fewer than 2 bytes
    /// - [`UnknownKind`] — kind nibble is 5–15
    /// - [`UnexpectedMessageStart`] — `Sole`/`First` arrived mid-message
    /// - [`MissingMessageStart`] — `Mid`/`Last`/`Abort` arrived with no open message
    /// - [`MessageTypeChange`] — continuation msg_type differs from opening packet
    ///
    /// [`PacketTooShort`]: PacketReadError::PacketTooShort
    /// [`UnknownKind`]: PacketReadError::UnknownKind
    /// [`UnexpectedMessageStart`]: PacketReadError::UnexpectedMessageStart
    /// [`MissingMessageStart`]: PacketReadError::MissingMessageStart
    /// [`MessageTypeChange`]: PacketReadError::MessageTypeChange
    pub(crate) fn read(&mut self, raw_packet: &[u8]) -> Result<PacketHeader, PacketReadError> {
        if raw_packet.len() < 2 {
            return Err(PacketReadError::PacketTooShort);
        }
        let header = u16::from_be_bytes([raw_packet[0], raw_packet[1]]);
        let kind_raw = ((header & KIND_MASK) >> KIND_SHIFT) as u8;
        let msg_type = header & TYPE_MASK;
        let kind = PacketKind::from_u8(kind_raw)?;

        match kind {
            PacketKind::Sole | PacketKind::First => {
                if self.in_progress {
                    return Err(PacketReadError::UnexpectedMessageStart {
                        from: self.msg_type,
                        to: msg_type,
                    });
                }
                if matches!(kind, PacketKind::First) {
                    self.in_progress = true;
                    self.msg_type = msg_type;
                }
                // Sole: in_progress stays false
            }
            PacketKind::Mid | PacketKind::Last | PacketKind::Abort => {
                if !self.in_progress {
                    return Err(PacketReadError::MissingMessageStart { msg_type });
                }
                if self.msg_type != msg_type {
                    return Err(PacketReadError::MessageTypeChange {
                        from: self.msg_type,
                        to: msg_type,
                    });
                }
                if matches!(kind, PacketKind::Last | PacketKind::Abort) {
                    self.in_progress = false;
                    self.msg_type = 0;
                }
            }
        }

        Ok(PacketHeader { kind, msg_type })
    }
}

// ── PacketHeader ──────────────────────────────────────────────────────────────

/// The decoded header of a successfully parsed packet.
///
/// The reader has already verified that this packet is consistent with the
/// current message in progress. The payload is not included here — callers
/// retrieve it from the buffer they passed to the containing [`PacketRx`].
#[derive(Debug, PartialEq)]
pub(crate) struct PacketHeader {
    pub(crate) kind: PacketKind,
    pub(crate) msg_type: u16,
}

// ── Size constants ────────────────────────────────────────────────────────────

/// Byte length of the length-prefix frame header prepended to every Noise frame.
pub(crate) const FRAME_HEADER_SIZE: usize = 2;
/// Maximum ciphertext size that fits in a 16-bit length prefix.
pub(crate) const MAX_CIPHERTEXT_SIZE: usize = 0xFFFF;
/// AES-GCM authentication tag overhead per Noise message.
pub(crate) const CIPHER_OVERHEAD_SIZE: usize = 16;
/// Maximum plaintext size (header + payload) per packet.
pub(crate) const MAX_RAW_PACKET_SIZE: usize = MAX_CIPHERTEXT_SIZE - CIPHER_OVERHEAD_SIZE;
/// Maximum **payload** bytes per packet — plaintext minus the 2-byte packet header.
pub const MAX_PACKET_SIZE: usize = MAX_RAW_PACKET_SIZE - 2;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PacketBuilder ─────────────────────────────────────────────────────────

    #[test]
    fn builder_single_packet_message() {
        let mut b = PacketBuilder::new();
        b.prepare(1).unwrap();
        let raw = b.pack(b"hello", true).unwrap();
        let header = u16::from_be_bytes([raw[0], raw[1]]);
        assert_eq!((header >> KIND_SHIFT) as u8, PacketKind::Sole as u8);
        assert_eq!(header & TYPE_MASK, 1);
        assert_eq!(&raw[2..], b"hello");
    }

    #[test]
    fn builder_multi_packet_message() {
        let mut b = PacketBuilder::new();
        b.prepare(2).unwrap();

        let first = b.pack(b"part1", false).unwrap();
        let h0 = u16::from_be_bytes([first[0], first[1]]);
        assert_eq!((h0 >> KIND_SHIFT) as u8, PacketKind::First as u8);
        assert_eq!(h0 & TYPE_MASK, 2);
        assert_eq!(&first[2..], b"part1");

        let mid = b.pack(b"part2", false).unwrap();
        let h1 = u16::from_be_bytes([mid[0], mid[1]]);
        assert_eq!((h1 >> KIND_SHIFT) as u8, PacketKind::Mid as u8);

        let last = b.pack(b"part3", true).unwrap();
        let h2 = u16::from_be_bytes([last[0], last[1]]);
        assert_eq!((h2 >> KIND_SHIFT) as u8, PacketKind::Last as u8);
        assert_eq!(&last[2..], b"part3");
    }

    #[test]
    fn builder_msg_type_too_large_is_error() {
        let mut b = PacketBuilder::new();
        assert!(matches!(b.prepare(0x1000), Err(PacketBuildError::MessageTypeTooLarge(0x1000))));
        assert!(matches!(b.prepare(0xFFFF), Err(PacketBuildError::MessageTypeTooLarge(0xFFFF))));
    }

    #[test]
    fn builder_max_msg_type_is_accepted() {
        let mut b = PacketBuilder::new();
        b.prepare(0x0FFF).unwrap();
        let raw = b.pack(b"x", true).unwrap();
        let header = u16::from_be_bytes([raw[0], raw[1]]);
        assert_eq!(header & TYPE_MASK, 0x0FFF);
    }

    #[test]
    fn builder_reuse_after_message_complete() {
        let mut b = PacketBuilder::new();
        b.prepare(1).unwrap();
        b.pack(b"a", true).unwrap();
        b.prepare(2).unwrap();
        let raw = b.pack(b"b", true).unwrap();
        let header = u16::from_be_bytes([raw[0], raw[1]]);
        assert_eq!(header & TYPE_MASK, 2);
    }

    #[test]
    fn builder_prepare_while_in_progress_is_error() {
        let mut b = PacketBuilder::new();
        b.prepare(1).unwrap();
        assert!(matches!(b.prepare(2), Err(PacketBuildError::MessageAlreadyInProgress)));
    }

    #[test]
    fn builder_pack_without_prepare_is_error() {
        let mut b = PacketBuilder::new();
        assert!(matches!(b.pack(b"data", true), Err(PacketBuildError::NoMessageInProgress)));
    }

    #[test]
    fn builder_empty_payload_is_allowed() {
        let mut b = PacketBuilder::new();
        b.prepare(0).unwrap();
        let raw = b.pack(b"", true).unwrap();
        assert_eq!(raw.len(), 2); // header only
    }

    #[test]
    fn builder_abort_mid_message() {
        let mut b = PacketBuilder::new();
        b.prepare(5).unwrap();
        b.pack(b"first", false).unwrap();
        let abort_pkt = b.abort().expect("should produce abort packet");
        let header = u16::from_be_bytes([abort_pkt[0], abort_pkt[1]]);
        assert_eq!((header >> KIND_SHIFT) as u8, PacketKind::Abort as u8);
        assert_eq!(header & TYPE_MASK, 5);
        assert_eq!(abort_pkt.len(), 2); // no payload

        // builder is reset — can start a new message
        b.prepare(6).unwrap();
        let raw = b.pack(b"new", true).unwrap();
        let h = u16::from_be_bytes([raw[0], raw[1]]);
        assert_eq!((h >> KIND_SHIFT) as u8, PacketKind::Sole as u8);
    }

    #[test]
    fn builder_abort_without_message_is_none() {
        let mut b = PacketBuilder::new();
        assert!(b.abort().is_none());
    }

    #[test]
    fn builder_abort_after_sole_is_none() {
        let mut b = PacketBuilder::new();
        b.prepare(1).unwrap();
        b.pack(b"done", true).unwrap();
        assert!(b.abort().is_none());
    }

    // ── PacketReader ──────────────────────────────────────────────────────────

    fn make_raw(kind: PacketKind, msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let header = ((kind as u16) << KIND_SHIFT) | (msg_type & TYPE_MASK);
        let mut v = header.to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn reader_sole_packet() {
        let mut r = PacketReader::new();
        let raw = make_raw(PacketKind::Sole, 3, b"data");
        let pkt = r.read(&raw).unwrap();
        assert_eq!(pkt.kind, PacketKind::Sole);
        assert_eq!(pkt.msg_type, 3);
    }

    #[test]
    fn reader_multi_packet_message() {
        let mut r = PacketReader::new();

        let p1 = r.read(&make_raw(PacketKind::First, 5, b"a")).unwrap();
        assert_eq!(p1.kind, PacketKind::First);
        assert!(r.in_progress);

        let p2 = r.read(&make_raw(PacketKind::Mid, 5, b"b")).unwrap();
        assert_eq!(p2.kind, PacketKind::Mid);

        let p3 = r.read(&make_raw(PacketKind::Last, 5, b"c")).unwrap();
        assert_eq!(p3.kind, PacketKind::Last);
        assert!(!r.in_progress);
    }

    #[test]
    fn reader_abort_mid_message() {
        let mut r = PacketReader::new();
        r.read(&make_raw(PacketKind::First, 7, b"start")).unwrap();
        let pkt = r.read(&make_raw(PacketKind::Abort, 7, b"")).unwrap();
        assert_eq!(pkt.kind, PacketKind::Abort);
        assert!(!r.in_progress);

        // can receive a new message after abort
        let pkt2 = r.read(&make_raw(PacketKind::Sole, 8, b"fresh")).unwrap();
        assert_eq!(pkt2.kind, PacketKind::Sole);
    }

    #[test]
    fn reader_reuse_after_message_complete() {
        let mut r = PacketReader::new();
        r.read(&make_raw(PacketKind::Sole, 1, b"")).unwrap();
        let pkt = r.read(&make_raw(PacketKind::Sole, 2, b"")).unwrap();
        assert_eq!(pkt.msg_type, 2);
    }

    #[test]
    fn reader_too_short_is_error() {
        let mut r = PacketReader::new();
        assert_eq!(r.read(&[0x00]), Err(PacketReadError::PacketTooShort));
        assert_eq!(r.read(&[]), Err(PacketReadError::PacketTooShort));
    }

    #[test]
    fn reader_unknown_kind_is_error() {
        let mut r = PacketReader::new();
        // kind=5 (reserved) in top nibble
        let raw = [0x50, 0x01];
        assert_eq!(r.read(&raw), Err(PacketReadError::UnknownKind(5)));
    }

    #[test]
    fn reader_unexpected_message_start_is_error() {
        let mut r = PacketReader::new();
        r.read(&make_raw(PacketKind::First, 1, b"")).unwrap();
        let err = r.read(&make_raw(PacketKind::First, 2, b"")).unwrap_err();
        assert_eq!(err, PacketReadError::UnexpectedMessageStart { from: 1, to: 2 });
    }

    #[test]
    fn reader_sole_mid_message_is_error() {
        let mut r = PacketReader::new();
        r.read(&make_raw(PacketKind::First, 1, b"")).unwrap();
        let err = r.read(&make_raw(PacketKind::Sole, 1, b"")).unwrap_err();
        assert_eq!(err, PacketReadError::UnexpectedMessageStart { from: 1, to: 1 });
    }

    #[test]
    fn reader_missing_message_start_is_error() {
        let mut r = PacketReader::new();
        let err = r.read(&make_raw(PacketKind::Mid, 3, b"")).unwrap_err();
        assert_eq!(err, PacketReadError::MissingMessageStart { msg_type: 3 });
    }

    #[test]
    fn reader_last_without_start_is_error() {
        let mut r = PacketReader::new();
        let err = r.read(&make_raw(PacketKind::Last, 3, b"")).unwrap_err();
        assert_eq!(err, PacketReadError::MissingMessageStart { msg_type: 3 });
    }

    #[test]
    fn reader_abort_without_start_is_error() {
        let mut r = PacketReader::new();
        let err = r.read(&make_raw(PacketKind::Abort, 3, b"")).unwrap_err();
        assert_eq!(err, PacketReadError::MissingMessageStart { msg_type: 3 });
    }

    #[test]
    fn reader_message_type_change_is_error() {
        let mut r = PacketReader::new();
        r.read(&make_raw(PacketKind::First, 4, b"")).unwrap();
        let err = r.read(&make_raw(PacketKind::Mid, 5, b"")).unwrap_err();
        assert_eq!(err, PacketReadError::MessageTypeChange { from: 4, to: 5 });
    }

    #[test]
    fn reader_empty_payload_is_allowed() {
        let mut r = PacketReader::new();
        let raw = make_raw(PacketKind::Sole, 0, b"");
        let pkt = r.read(&raw).unwrap();
        assert!(matches!(pkt.kind, PacketKind::Sole));
    }

    // ── Round-trips ───────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_single_packet() {
        let mut b = PacketBuilder::new();
        let mut r = PacketReader::new();
        b.prepare(10).unwrap();
        let raw = b.pack(b"roundtrip", true).unwrap().to_owned();
        let pkt = r.read(&raw).unwrap();
        assert_eq!(pkt.kind, PacketKind::Sole);
        assert_eq!(pkt.msg_type, 10);
        assert_eq!(&raw[2..], b"roundtrip");
    }

    #[test]
    fn roundtrip_multi_packet() {
        let mut b = PacketBuilder::new();
        let mut r = PacketReader::new();
        b.prepare(7).unwrap();
        let p1 = b.pack(b"foo", false).unwrap().to_owned();
        let p2 = b.pack(b"bar", true).unwrap().to_owned();
        let h1 = r.read(&p1).unwrap();
        assert_eq!(h1.kind, PacketKind::First);
        assert_eq!(&p1[2..], b"foo");
        let h2 = r.read(&p2).unwrap();
        assert_eq!(h2.kind, PacketKind::Last);
        assert_eq!(&p2[2..], b"bar");
    }

    #[test]
    fn roundtrip_abort() {
        let mut b = PacketBuilder::new();
        let mut r = PacketReader::new();
        b.prepare(3).unwrap();
        b.pack(b"start", false).unwrap();
        let abort_raw = b.abort().unwrap().to_owned();
        let pkt = r.read(&make_raw(PacketKind::First, 3, b"start")).unwrap();
        assert_eq!(pkt.kind, PacketKind::First);
        let abort_pkt = r.read(&abort_raw).unwrap();
        assert_eq!(abort_pkt.kind, PacketKind::Abort);
        assert_eq!(abort_pkt.msg_type, 3);
    }

    #[test]
    fn all_kind_values_round_trip() {
        for kind in [PacketKind::Sole, PacketKind::First, PacketKind::Mid, PacketKind::Last, PacketKind::Abort] {
            assert_eq!(PacketKind::from_u8(kind as u8).unwrap(), kind);
        }
    }

    #[test]
    fn max_type_value_preserved() {
        let mut b = PacketBuilder::new();
        let mut r = PacketReader::new();
        b.prepare(0x0FFF).unwrap();
        let raw = b.pack(b"", true).unwrap().to_owned();
        let pkt = r.read(&raw).unwrap();
        assert_eq!(pkt.msg_type, 0x0FFF);
    }
}
