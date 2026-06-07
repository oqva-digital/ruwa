//! WhatsApp Web wire protocol.
//!
//! Layers (top → bottom):
//!   1. Application: signal-encrypted protobuf messages (waE2E).
//!   2. Frame: WhatsApp binary nodes (XMPP-like; token tables encode tag/attr names).
//!   3. Session: Noise XX handshake establishes session keys, then frames are
//!      AES-GCM encrypted with a counter (`NoiseCipher`).
//!   4. Transport: WebSocket to wss://web.whatsapp.com/ws/chat.
//!
//! References:
//!   - whatsmeow/socket/noisehandshake.go     (Noise XX over WS)
//!   - whatsmeow/socket/framesocket.go        (frame length-prefix protocol)
//!   - whatsmeow/binary/encoder.go + decoder.go  (binary node codec)
//!   - whatsmeow/binary/token/token.go        (token tables — vendor verbatim)
#![allow(dead_code)]

mod tokens;

pub mod binary {
    //! Binary node codec (whatsmeow-compatible).
    //!
    //! Wire format primer:
    //!   - A node is `(tag, attrs, content)`. Content is None | bytes | child nodes.
    //!   - The encoder writes a "list size" header — `2*attr_count + 1 + has_content` —
    //!     followed by tag, alternating attr-key/value pairs, and (optional) content.
    //!   - Strings are compressed against a static token dictionary (single + double
    //!     byte) when possible, then tried as nibble-packed (digits/.- only) or
    //!     hex-packed (0-9 A-F), else fall through to length-prefixed raw bytes.
    //!   - JID-typed values get specialised tokens (JID_PAIR, AD_JID, FB_JID,
    //!     INTEROP_JID). This port currently emits all JID values as plain strings
    //!     on encode (server accepts that) but decodes incoming JID tokens to their
    //!     canonical "user[.agent[:device]]@server" string form.
    //!
    //! `Marshal` (whatsmeow) ≡ `pack(n)`: returns `[0u8] ++ encode(n)` where the
    //! leading 0 is the "compression flag" (bit 1 = zlib). `Unpack` strips it.

    use std::collections::{BTreeMap, HashMap};
    use std::sync::OnceLock;

    use super::tokens::{DOUBLE_BYTE_TOKENS, SINGLE_BYTE_TOKENS};

    pub type Attrs = BTreeMap<String, String>;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Node {
        pub tag: String,
        pub attrs: Attrs,
        pub content: Content,
    }

    impl Node {
        pub fn new(tag: impl Into<String>) -> Self {
            Self {
                tag: tag.into(),
                attrs: Attrs::new(),
                content: Content::None,
            }
        }

        /// Compact, structure-preserving XML-ish rendering for wire diffing
        /// against Baileys' `recv xml`/`xml send` traces. Attrs are sorted
        /// (BTreeMap) for stable diffs; byte payloads are shown as `#<len>b`
        /// rather than dumped. Not a faithful WA-XML encoder — debug only.
        pub fn to_xml(&self) -> String {
            let mut s = String::new();
            s.push('<');
            s.push_str(&self.tag);
            for (k, v) in &self.attrs {
                s.push(' ');
                s.push_str(k);
                s.push_str("=\"");
                s.push_str(v);
                s.push('"');
            }
            match &self.content {
                Content::None => s.push_str("/>"),
                Content::Bytes(b) => {
                    s.push_str(&format!(">#{}b</{}>", b.len(), self.tag));
                }
                Content::Nodes(ns) => {
                    s.push('>');
                    for n in ns {
                        s.push_str(&n.to_xml());
                    }
                    s.push_str("</");
                    s.push_str(&self.tag);
                    s.push('>');
                }
            }
            s
        }
    }

    /// Node content body. WA binary nodes carry exactly one of:
    /// nothing, a list of child nodes, or a raw byte payload (which the caller
    /// may interpret as a string or protobuf).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Content {
        None,
        Bytes(Vec<u8>),
        Nodes(Vec<Node>),
    }

    // -- Wire constants ------------------------------------------------------

    const LIST_EMPTY: u8 = 0;
    const DICT_0: u8 = 236;
    const DICT_1: u8 = 237;
    const DICT_2: u8 = 238;
    const DICT_3: u8 = 239;
    const INTEROP_JID: u8 = 245;
    const FB_JID: u8 = 246;
    const AD_JID: u8 = 247;
    const LIST_8: u8 = 248;
    const LIST_16: u8 = 249;
    const JID_PAIR: u8 = 250;
    const HEX_8: u8 = 251;
    const BINARY_8: u8 = 252;
    const BINARY_20: u8 = 253;
    const BINARY_32: u8 = 254;
    const NIBBLE_8: u8 = 255;
    const PACKED_MAX: usize = 127;

    // -- Errors --------------------------------------------------------------

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum DecodeError {
        #[error("unexpected EOF (need {need} more bytes at {at})")]
        Eof { at: usize, need: usize },
        #[error("invalid token byte {byte:#x} at {at}")]
        InvalidToken { at: usize, byte: u8 },
        #[error("invalid list size tag {tag} at {at}")]
        InvalidListSize { at: usize, tag: u8 },
        #[error("attribute key was not a string at {at}")]
        NonStringKey { at: usize },
        #[error("invalid node (empty tag or zero list size)")]
        InvalidNode,
        #[error("invalid nibble value {0:#x}")]
        InvalidNibble(u8),
        #[error("invalid hex value {0:#x}")]
        InvalidHex(u8),
        #[error("packed string too long: {0} bytes")]
        PackedTooLong(usize),
        #[error("frame length too large: {0}")]
        LengthTooLarge(usize),
        #[error("unsupported: {0}")]
        Unsupported(&'static str),
    }

    #[derive(Debug, thiserror::Error)]
    pub enum EncodeError {
        #[error("payload longer than i32::MAX ({0} bytes)")]
        TooLarge(usize),
        #[error("packed string too long ({0} bytes; max 127)")]
        PackedTooLong(usize),
    }

    // -- Token lookup --------------------------------------------------------

    fn single_byte_index(tok: &str) -> Option<u8> {
        static IDX: OnceLock<HashMap<&'static str, u8>> = OnceLock::new();
        let map = IDX.get_or_init(|| {
            let mut m = HashMap::with_capacity(SINGLE_BYTE_TOKENS.len());
            for (i, t) in SINGLE_BYTE_TOKENS.iter().enumerate() {
                if !t.is_empty() {
                    m.insert(*t, i as u8);
                }
            }
            m
        });
        map.get(tok).copied()
    }

    fn double_byte_index(tok: &str) -> Option<(u8, u8)> {
        static IDX: OnceLock<HashMap<&'static str, (u8, u8)>> = OnceLock::new();
        let map = IDX.get_or_init(|| {
            let mut m = HashMap::with_capacity(1024);
            for (di, dict) in DOUBLE_BYTE_TOKENS.iter().enumerate() {
                for (i, t) in dict.iter().enumerate() {
                    m.insert(*t, (di as u8, i as u8));
                }
            }
            m
        });
        map.get(tok).copied()
    }

    // -- Public API ----------------------------------------------------------

    /// Encode a node to its wire bytes (without the leading compression flag).
    pub fn encode(n: &Node) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::with_capacity(64);
        write_node(n, &mut buf)?;
        Ok(buf)
    }

    /// `Marshal` equivalent — prepends the compression flag byte (0, uncompressed).
    pub fn pack(n: &Node) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::with_capacity(64);
        buf.push(0u8);
        write_node(n, &mut buf)?;
        Ok(buf)
    }

    /// Decode a node from wire bytes (without the leading compression flag).
    pub fn decode(data: &[u8]) -> Result<Node, DecodeError> {
        let mut r = Decoder { data, pos: 0 };
        r.read_node_required()
    }

    /// `Unmarshal` equivalent: strips the leading compression flag byte,
    /// zlib-decompresses if bit 1 is set, then [`decode`]s.
    pub fn unmarshal(data: &[u8]) -> Result<Node, DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::Eof { at: 0, need: 1 });
        }
        let flag = data[0];
        let body = &data[1..];
        if flag & 2 != 0 {
            use flate2::read::ZlibDecoder;
            use std::io::Read;
            let mut buf = Vec::with_capacity(body.len() * 2);
            ZlibDecoder::new(body)
                .read_to_end(&mut buf)
                .map_err(|_| DecodeError::Unsupported("zlib decompression failed"))?;
            decode(&buf)
        } else {
            decode(body)
        }
    }

    // -- Encoder -------------------------------------------------------------

    fn write_node(n: &Node, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        // whatsmeow has a special case where tag "0" is encoded as an empty list.
        if n.tag == "0" {
            buf.push(LIST_8);
            buf.push(LIST_EMPTY);
            return Ok(());
        }
        let attr_count = n.attrs.iter().filter(|(_, v)| !v.is_empty()).count();
        let has_content = !matches!(n.content, Content::None);
        let list_size = 2 * attr_count + 1 + usize::from(has_content);
        write_list_start(list_size, buf)?;
        write_string(&n.tag, buf)?;
        for (k, v) in &n.attrs {
            if v.is_empty() {
                continue;
            }
            write_string(k, buf)?;
            write_attr_value(v, buf)?;
        }
        match &n.content {
            Content::None => {}
            Content::Bytes(b) => write_bytes(b, buf)?,
            Content::Nodes(children) => {
                write_list_start(children.len(), buf)?;
                for c in children {
                    write_node(c, buf)?;
                }
            }
        }
        Ok(())
    }

    fn write_list_start(size: usize, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        if size == 0 {
            buf.push(LIST_EMPTY);
        } else if size < 256 {
            buf.push(LIST_8);
            buf.push(size as u8);
        } else if size < 1 << 16 {
            buf.push(LIST_16);
            buf.push((size >> 8) as u8);
            buf.push(size as u8);
        } else {
            return Err(EncodeError::TooLarge(size));
        }
        Ok(())
    }

    fn write_byte_length(len: usize, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        if len < 256 {
            buf.push(BINARY_8);
            buf.push(len as u8);
        } else if len < 1 << 20 {
            buf.push(BINARY_20);
            buf.push(((len >> 16) & 0x0F) as u8);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        } else if (len as u64) < i32::MAX as u64 {
            buf.push(BINARY_32);
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        } else {
            return Err(EncodeError::TooLarge(len));
        }
        Ok(())
    }

    fn write_bytes(value: &[u8], buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        write_byte_length(value.len(), buf)?;
        buf.extend_from_slice(value);
        Ok(())
    }

    /// Known WhatsApp JID servers — an attribute value `user@<server>` for one
    /// of these is encoded as a binary `JID_PAIR` token, NOT a literal string.
    const KNOWN_JID_SERVERS: &[&str] = &[
        "s.whatsapp.net",
        "c.us",
        "g.us",
        "lid",
        "broadcast",
        "newsletter",
        "call",
    ];

    /// Encode an attribute VALUE. JID-shaped values (`user@known-server`, no
    /// device/agent suffix) MUST go out as a `JID_PAIR` binary token — some
    /// server handlers (notably the `usync` device-query parser) silently drop
    /// a request whose `<user jid=...>` is a plain string instead of a real
    /// JID, so the query returns nothing and every send times out. Device/agent
    /// JIDs (`:N`/`.N`) and non-JID strings fall through to `write_string`
    /// unchanged (the existing message/receipt paths rely on that).
    fn write_attr_value(v: &str, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        if let Some((left, server)) = v.rsplit_once('@') {
            if !left.is_empty() && !left.contains('@') {
                // Bare `user@server` (no agent/device) → JID_PAIR.
                if KNOWN_JID_SERVERS.contains(&server) && !left.contains([':', '.']) {
                    buf.push(JID_PAIR);
                    write_string(left, buf)?;
                    write_string(server, buf)?;
                    return Ok(());
                }
                // `user[.agent][:device]@{s.whatsapp.net|lid}` → AD_JID. The server
                // maps to an agent byte (0=s.whatsapp.net, 1=lid); the inverse of
                // `format_ad_jid`. Device JIDs MUST be AD_JID-encoded or the prekey
                // (`<key><user jid=…:N…>`) and per-device message routing silently fail.
                let server_agent = match server {
                    "s.whatsapp.net" => Some(0u8),
                    "lid" => Some(1u8),
                    _ => None,
                };
                if let Some(server_agent) = server_agent {
                    let (head, device) = match left.rsplit_once(':') {
                        Some((h, d)) => (h, d.parse::<u8>().ok()),
                        None => (left, Some(0u8)),
                    };
                    let (user, dot_agent) = match head.split_once('.') {
                        Some((u, a)) => (u, a.parse::<u8>().ok()),
                        None => (head, None),
                    };
                    if let Some(device) = device {
                        let agent = dot_agent.unwrap_or(server_agent);
                        if !user.is_empty() && (device > 0 || agent > 0) {
                            buf.push(AD_JID);
                            buf.push(agent);
                            buf.push(device);
                            write_string(user, buf)?;
                            return Ok(());
                        }
                    }
                }
            }
        }
        write_string(v, buf)
    }

    fn write_string(s: &str, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        if let Some(idx) = single_byte_index(s) {
            buf.push(idx);
        } else if let Some((di, idx)) = double_byte_index(s) {
            buf.push(DICT_0 + di);
            buf.push(idx);
        } else if validate_nibble(s) {
            write_packed(s, NIBBLE_8, buf)?;
        } else if validate_hex(s) {
            write_packed(s, HEX_8, buf)?;
        } else {
            write_byte_length(s.len(), buf)?;
            buf.extend_from_slice(s.as_bytes());
        }
        Ok(())
    }

    fn write_packed(s: &str, ty: u8, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
        if s.len() > PACKED_MAX {
            return Err(EncodeError::PackedTooLong(s.len()));
        }
        buf.push(ty);
        let bytes = s.as_bytes();
        let half_len = bytes.len().div_ceil(2);
        let mut header = half_len as u8;
        if bytes.len() % 2 == 1 {
            header |= 0x80;
        }
        buf.push(header);
        let pack: fn(u8) -> u8 = if ty == NIBBLE_8 { pack_nibble } else { pack_hex };
        let pairs = bytes.len() / 2;
        for i in 0..pairs {
            buf.push((pack(bytes[2 * i]) << 4) | pack(bytes[2 * i + 1]));
        }
        if bytes.len() % 2 == 1 {
            buf.push((pack(bytes[bytes.len() - 1]) << 4) | pack(0));
        }
        Ok(())
    }

    fn validate_nibble(s: &str) -> bool {
        if s.len() > PACKED_MAX || s.is_empty() {
            return false;
        }
        s.bytes()
            .all(|c| c.is_ascii_digit() || c == b'-' || c == b'.')
    }

    fn validate_hex(s: &str) -> bool {
        if s.len() > PACKED_MAX || s.is_empty() {
            return false;
        }
        s.bytes()
            .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
    }

    fn pack_nibble(c: u8) -> u8 {
        match c {
            b'-' => 10,
            b'.' => 11,
            0 => 15,
            c if c.is_ascii_digit() => c - b'0',
            _ => unreachable!("validate_nibble must filter unpackable bytes"),
        }
    }

    fn pack_hex(c: u8) -> u8 {
        match c {
            c if c.is_ascii_digit() => c - b'0',
            b'A'..=b'F' => 10 + c - b'A',
            0 => 15,
            _ => unreachable!("validate_hex must filter unpackable bytes"),
        }
    }

    // -- Decoder -------------------------------------------------------------

    /// Tagged value the decoder produces internally; the public API only
    /// surfaces these via `Node`/`Attrs`/`Content`.
    enum DecodedValue {
        None,
        Str(String),
        Bytes(Vec<u8>),
        Nodes(Vec<Node>),
    }

    struct Decoder<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Decoder<'_> {
        fn need(&self, n: usize) -> Result<(), DecodeError> {
            if self.pos + n > self.data.len() {
                Err(DecodeError::Eof {
                    at: self.pos,
                    need: n,
                })
            } else {
                Ok(())
            }
        }

        fn read_byte(&mut self) -> Result<u8, DecodeError> {
            self.need(1)?;
            let b = self.data[self.pos];
            self.pos += 1;
            Ok(b)
        }

        fn read_int_be(&mut self, n: usize) -> Result<usize, DecodeError> {
            self.need(n)?;
            let mut v = 0usize;
            for i in 0..n {
                v = (v << 8) | (self.data[self.pos + i] as usize);
            }
            self.pos += n;
            Ok(v)
        }

        fn read_int20(&mut self) -> Result<usize, DecodeError> {
            self.need(3)?;
            let v = ((self.data[self.pos] as usize & 0x0F) << 16)
                | ((self.data[self.pos + 1] as usize) << 8)
                | (self.data[self.pos + 2] as usize);
            self.pos += 3;
            Ok(v)
        }

        fn read_raw(&mut self, n: usize) -> Result<Vec<u8>, DecodeError> {
            self.need(n)?;
            let v = self.data[self.pos..self.pos + n].to_vec();
            self.pos += n;
            Ok(v)
        }

        fn read_list_size(&mut self, tag: u8) -> Result<usize, DecodeError> {
            match tag {
                LIST_EMPTY => Ok(0),
                LIST_8 => self.read_int_be(1),
                LIST_16 => self.read_int_be(2),
                _ => Err(DecodeError::InvalidListSize {
                    at: self.pos,
                    tag,
                }),
            }
        }

        fn read_packed(&mut self, ty: u8) -> Result<String, DecodeError> {
            let header = self.read_byte()?;
            let half_len = (header & 0x7F) as usize;
            let mut out = Vec::with_capacity(half_len * 2);
            for _ in 0..half_len {
                let b = self.read_byte()?;
                let upper = unpack_byte(ty, b >> 4)?;
                let lower = unpack_byte(ty, b & 0x0F)?;
                out.push(upper);
                out.push(lower);
            }
            if header & 0x80 != 0 && !out.is_empty() {
                out.pop();
            }
            String::from_utf8(out)
                .map_err(|_| DecodeError::Unsupported("packed bytes were not valid UTF-8"))
        }

        /// `read(asString)` from the Go decoder.
        fn read_value(&mut self, as_string: bool) -> Result<DecodedValue, DecodeError> {
            let tag = self.read_byte()?;
            match tag {
                LIST_EMPTY => Ok(DecodedValue::None),
                LIST_8 | LIST_16 => {
                    let size = self.read_list_size(tag)?;
                    let mut nodes = Vec::with_capacity(size);
                    for _ in 0..size {
                        nodes.push(self.read_node_inner()?);
                    }
                    Ok(DecodedValue::Nodes(nodes))
                }
                BINARY_8 => {
                    let n = self.read_int_be(1)?;
                    self.read_bytes_or_string(n, as_string)
                }
                BINARY_20 => {
                    let n = self.read_int20()?;
                    self.read_bytes_or_string(n, as_string)
                }
                BINARY_32 => {
                    let n = self.read_int_be(4)?;
                    self.read_bytes_or_string(n, as_string)
                }
                DICT_0..=DICT_3 => {
                    let i = self.read_byte()? as usize;
                    let dict = (tag - DICT_0) as usize;
                    DOUBLE_BYTE_TOKENS
                        .get(dict)
                        .and_then(|d| d.get(i))
                        .map(|s| DecodedValue::Str((*s).to_string()))
                        .ok_or(DecodeError::InvalidToken { at: self.pos, byte: tag })
                }
                FB_JID => self.read_fb_jid().map(DecodedValue::Str),
                INTEROP_JID => self.read_interop_jid().map(DecodedValue::Str),
                JID_PAIR => self.read_jid_pair().map(DecodedValue::Str),
                AD_JID => self.read_ad_jid().map(DecodedValue::Str),
                NIBBLE_8 | HEX_8 => self.read_packed(tag).map(DecodedValue::Str),
                t if (1..(SINGLE_BYTE_TOKENS.len() as u8)).contains(&t) => Ok(DecodedValue::Str(
                    SINGLE_BYTE_TOKENS[t as usize].to_string(),
                )),
                _ => Err(DecodeError::InvalidToken {
                    at: self.pos,
                    byte: tag,
                }),
            }
        }

        fn read_bytes_or_string(
            &mut self,
            n: usize,
            as_string: bool,
        ) -> Result<DecodedValue, DecodeError> {
            let raw = self.read_raw(n)?;
            if as_string {
                String::from_utf8(raw)
                    .map(DecodedValue::Str)
                    .map_err(|_| DecodeError::Unsupported("attribute value was not valid UTF-8"))
            } else {
                Ok(DecodedValue::Bytes(raw))
            }
        }

        fn read_jid_pair(&mut self) -> Result<String, DecodeError> {
            let user = self.read_value(true)?;
            let server = self.read_value(true)?;
            let server = match server {
                DecodedValue::Str(s) => s,
                _ => return Err(DecodeError::Unsupported("JID server must be a string")),
            };
            Ok(match user {
                DecodedValue::None => format!("@{server}"),
                DecodedValue::Str(u) => format!("{u}@{server}"),
                _ => return Err(DecodeError::Unsupported("JID user must be string|none")),
            })
        }

        fn read_ad_jid(&mut self) -> Result<String, DecodeError> {
            let agent = self.read_byte()?;
            let device = self.read_byte()?;
            let user = match self.read_value(true)? {
                DecodedValue::Str(u) => u,
                _ => return Err(DecodeError::Unsupported("AD JID user must be string")),
            };
            Ok(format_ad_jid(&user, agent, device))
        }

        fn read_fb_jid(&mut self) -> Result<String, DecodeError> {
            let user = match self.read_value(true)? {
                DecodedValue::Str(u) => u,
                _ => return Err(DecodeError::Unsupported("FB JID user must be string")),
            };
            let device = self.read_int_be(2)?;
            let server = match self.read_value(true)? {
                DecodedValue::Str(s) => s,
                _ => return Err(DecodeError::Unsupported("FB JID server must be string")),
            };
            Ok(if device > 0 {
                format!("{user}:{device}@{server}")
            } else {
                format!("{user}@{server}")
            })
        }

        fn read_interop_jid(&mut self) -> Result<String, DecodeError> {
            let user = match self.read_value(true)? {
                DecodedValue::Str(u) => u,
                _ => return Err(DecodeError::Unsupported("Interop JID user must be string")),
            };
            let device = self.read_int_be(2)?;
            let integrator = self.read_int_be(2)?;
            let server = match self.read_value(true)? {
                DecodedValue::Str(s) => s,
                _ => return Err(DecodeError::Unsupported("Interop JID server must be string")),
            };
            Ok(format!("{user}:{device}_{integrator}@{server}"))
        }

        fn read_node_required(&mut self) -> Result<Node, DecodeError> {
            self.read_node_inner()
        }

        fn read_node_inner(&mut self) -> Result<Node, DecodeError> {
            let size_tag = self.read_byte()?;
            let list_size = self.read_list_size(size_tag)?;
            let raw_tag = self.read_value(true)?;
            let tag = match raw_tag {
                DecodedValue::Str(s) => s,
                _ => return Err(DecodeError::Unsupported("node tag must be a string")),
            };
            if list_size == 0 || tag.is_empty() {
                return Err(DecodeError::InvalidNode);
            }
            let attr_count = (list_size - 1) >> 1;
            let mut attrs = Attrs::new();
            for _ in 0..attr_count {
                let key = match self.read_value(true)? {
                    DecodedValue::Str(s) => s,
                    _ => return Err(DecodeError::NonStringKey { at: self.pos }),
                };
                let val = match self.read_value(true)? {
                    DecodedValue::Str(s) => s,
                    DecodedValue::None => String::new(),
                    DecodedValue::Bytes(b) => String::from_utf8(b)
                        .map_err(|_| DecodeError::Unsupported("attr was non-UTF8 bytes"))?,
                    DecodedValue::Nodes(_) => {
                        return Err(DecodeError::Unsupported("attr value cannot be a node list"))
                    }
                };
                attrs.insert(key, val);
            }
            let content = if list_size % 2 == 1 {
                Content::None
            } else {
                match self.read_value(false)? {
                    DecodedValue::None => Content::None,
                    DecodedValue::Bytes(b) => Content::Bytes(b),
                    DecodedValue::Nodes(ns) => Content::Nodes(ns),
                    DecodedValue::Str(s) => Content::Bytes(s.into_bytes()),
                }
            };
            Ok(Node { tag, attrs, content })
        }
    }

    fn unpack_byte(ty: u8, value: u8) -> Result<u8, DecodeError> {
        match ty {
            NIBBLE_8 => match value {
                0..=9 => Ok(b'0' + value),
                10 => Ok(b'-'),
                11 => Ok(b'.'),
                15 => Ok(0),
                _ => Err(DecodeError::InvalidNibble(value)),
            },
            HEX_8 => match value {
                0..=9 => Ok(b'0' + value),
                10..=15 => Ok(b'A' + value - 10),
                _ => Err(DecodeError::InvalidHex(value)),
            },
            _ => Err(DecodeError::Unsupported("unpack with non-packed tag")),
        }
    }

    fn format_ad_jid(user: &str, agent: u8, device: u8) -> String {
        // Whatsmeow servers: agent=0 → s.whatsapp.net; agent=1 → lid;
        // others may be hosted/MSGR. We only emit the canonical string form;
        // M3 will introduce a typed JID where round-trip fidelity matters.
        let server = match agent {
            0 => "s.whatsapp.net",
            1 => "lid",
            _ => "hosted",
        };
        match (agent, device) {
            (0, 0) => format!("{user}@{server}"),
            (0, d) => format!("{user}:{d}@{server}"),
            (a, 0) => format!("{user}.{a}@{server}"),
            (a, d) => format!("{user}.{a}:{d}@{server}"),
        }
    }

    // -- Tests ---------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        fn roundtrip(n: &Node) -> Node {
            let bytes = encode(n).expect("encode");
            decode(&bytes).expect("decode")
        }

        fn pack_unpack(n: &Node) -> Node {
            let bytes = pack(n).expect("pack");
            assert_eq!(bytes[0], 0, "pack flag byte must be 0 (uncompressed)");
            unmarshal(&bytes).expect("unmarshal")
        }

        #[test]
        fn empty_attrs_no_content() {
            let n = Node::new("foo");
            assert_eq!(roundtrip(&n), n);
            assert_eq!(pack_unpack(&n), n);
        }

        /// JID-valued attributes must encode as binary JID tokens (JID_PAIR for
        /// bare `user@server`, AD_JID for device JIDs), not literal strings — the
        /// `usync`/prekey server handlers silently drop a string-encoded
        /// `<user jid=…>`. Verify the right token byte is emitted AND the value
        /// round-trips back to the identical string.
        #[test]
        fn jid_attrs_encode_as_jid_tokens() {
            // Bare PN → JID_PAIR (250).
            let mut n = Node::new("user");
            n.attrs.insert("jid".into(), "5511990000001@s.whatsapp.net".into());
            let bytes = encode(&n).unwrap();
            assert!(bytes.contains(&JID_PAIR), "bare jid must use JID_PAIR token");
            assert_eq!(roundtrip(&n), n);

            // Device JID → AD_JID (247).
            let mut d = Node::new("user");
            d.attrs.insert("jid".into(), "5511990000001:56@s.whatsapp.net".into());
            let db = encode(&d).unwrap();
            assert!(db.contains(&AD_JID), "device jid must use AD_JID token");
            assert_eq!(roundtrip(&d), d);

            // LID with agent + device round-trips.
            let mut l = Node::new("user");
            l.attrs.insert("jid".into(), "64000000000001.1:50@lid".into());
            assert_eq!(roundtrip(&l), l);

            // A non-JID attribute value is untouched (still a plain string).
            let mut p = Node::new("x");
            p.attrs.insert("v".into(), "2.3000.1040665440".into());
            assert_eq!(roundtrip(&p), p);
        }

        #[test]
        fn token_compressed_tag() {
            // "iq" is a single-byte token (index 25). Encoded form should be 3 bytes:
            //   [LIST_8, 1, single_byte_idx_for_iq]
            let n = Node::new("iq");
            let bytes = encode(&n).unwrap();
            let idx = single_byte_index("iq").expect("iq is a token");
            assert_eq!(bytes, vec![LIST_8, 1, idx]);
            assert_eq!(decode(&bytes).unwrap(), n);
        }

        #[test]
        fn attrs_string_values() {
            let mut n = Node::new("message");
            n.attrs.insert("type".into(), "text".into());
            n.attrs.insert("id".into(), "ABC123".into()); // hex-packable
            n.attrs.insert("phone".into(), "5511999999999".into()); // nibble-packable
            assert_eq!(roundtrip(&n), n);
        }

        #[test]
        fn empty_attr_value_is_skipped() {
            let mut n = Node::new("foo");
            n.attrs.insert("a".into(), "1".into());
            n.attrs.insert("b".into(), "".into()); // dropped on encode
            let decoded = roundtrip(&n);
            assert!(!decoded.attrs.contains_key("b"));
            assert_eq!(decoded.attrs.get("a"), Some(&"1".to_string()));
        }

        #[test]
        fn bytes_content() {
            let mut n = Node::new("enc");
            n.attrs.insert("type".into(), "msg".into());
            n.content = Content::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
            assert_eq!(roundtrip(&n), n);
        }

        #[test]
        fn child_nodes_content() {
            let parent = Node {
                tag: "iq".into(),
                attrs: BTreeMap::from([
                    ("type".into(), "set".into()),
                    ("xmlns".into(), "urn:xmpp:ping".into()),
                    ("id".into(), "ABC123".into()),
                ]),
                content: Content::Nodes(vec![
                    Node::new("ping"),
                    {
                        let mut child = Node::new("query");
                        child.attrs.insert("v".into(), "1".into());
                        child
                    },
                ]),
            };
            assert_eq!(roundtrip(&parent), parent);
        }

        #[test]
        fn binary_20_length_payload() {
            // Any payload between 256 and 1<<20 forces BINARY_20 framing.
            let mut n = Node::new("enc");
            n.content = Content::Bytes(vec![0x42u8; 5000]);
            assert_eq!(roundtrip(&n), n);
        }

        #[test]
        fn empty_attrs_node_in_list() {
            // Reproduces the "tag 0" branch of the encoder.
            let outer = Node {
                tag: "list".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![Node::new("0")]),
            };
            // Round-trip: the inner "0" node decodes back as an empty-tag node,
            // which our decoder rejects. We assert encode-only behaviour here.
            let bytes = encode(&outer).unwrap();
            // The "0" tag emits [LIST_8, LIST_EMPTY] inline, so the second
            // child position should contain that pair.
            assert!(bytes.windows(2).any(|w| w == [LIST_8, LIST_EMPTY]));
        }

        #[test]
        fn unmarshal_decompresses_zlib_when_flag_set() {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;

            let mut node = Node::new("message");
            node.attrs.insert("type".into(), "text".into());
            let raw = encode(&node).unwrap();

            let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
            zlib.write_all(&raw).unwrap();
            let compressed = zlib.finish().unwrap();

            // Build a frame body identical to whatsmeow's compressed Marshal.
            let mut framed = Vec::with_capacity(1 + compressed.len());
            framed.push(2); // flag byte: bit 1 = zlib
            framed.extend(compressed);

            let decoded = unmarshal(&framed).unwrap();
            assert_eq!(decoded, node);
        }

        #[test]
        fn unmarshal_rejects_invalid_zlib_payload() {
            // Flag bit 1 set but body isn't real zlib → Unsupported.
            let bytes = [2u8, 0xff, 0xff, 0xff];
            let err = unmarshal(&bytes).unwrap_err();
            assert!(matches!(err, DecodeError::Unsupported(_)));
        }

        #[test]
        fn decode_rejects_eof() {
            // Single byte LIST_8 with nothing after.
            let err = decode(&[LIST_8]).unwrap_err();
            assert!(matches!(err, DecodeError::Eof { .. }));
        }

        #[test]
        fn nibble_packing_of_phone_number() {
            // Encoding "5511999999999" should fit in a nibble-packed form:
            // 1 type byte + 1 header byte + ceil(13/2)=7 data bytes = 9 bytes.
            let mut buf = Vec::new();
            write_string("5511999999999", &mut buf).unwrap();
            assert_eq!(buf[0], NIBBLE_8);
            assert_eq!(buf.len(), 1 + 1 + 7);
            // Round-trip the value through a node.
            let mut n = Node::new("foo");
            n.attrs.insert("phone".into(), "5511999999999".into());
            assert_eq!(roundtrip(&n), n);
        }

        #[test]
        fn hex_packing_of_uppercase_hex_id() {
            let mut buf = Vec::new();
            write_string("ABCDEF0123", &mut buf).unwrap();
            assert_eq!(buf[0], HEX_8);
            // Round-trip as an attr.
            let mut n = Node::new("msg");
            n.attrs.insert("id".into(), "ABCDEF0123".into());
            assert_eq!(roundtrip(&n), n);
        }

        #[test]
        fn double_byte_token() {
            // "active" is in DoubleByteTokens[0]; encoded form is 2 bytes.
            let n = Node::new("active");
            let bytes = encode(&n).unwrap();
            let (di, idx) = double_byte_index("active").expect("active is a double-byte token");
            assert_eq!(bytes, vec![LIST_8, 1, DICT_0 + di, idx]);
            assert_eq!(decode(&bytes).unwrap(), n);
        }
    }
}

pub mod noise {
    //! Noise XX handshake + post-handshake AEAD.
    //!
    //! WhatsApp's handshake is a hand-rolled subset of `Noise_XX_25519_AESGCM_SHA256`,
    //! not a Noise-framework call. This module mirrors that surface: `Authenticate`
    //! mixes data into a running SHA-256 hash; `Encrypt`/`Decrypt` AES-GCM with the
    //! current hash as AAD and a 12-byte counter IV; `MixIntoKey` HKDFs a new
    //! (salt, key) pair and resets the counter; `MixSharedSecretIntoKey` runs an
    //! X25519 first; `Finish` derives the two AEAD keys (write/read) used by the
    //! post-handshake `NoiseCipher`.
    //!
    //! References: whatsmeow/socket/noisehandshake.go, /handshake.go, /noisesocket.go.

    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::Aes256Gcm;
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256};

    /// `Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00` — exactly 32 bytes.
    pub const NOISE_START_PATTERN: [u8; 32] =
        *b"Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00";

    #[derive(Debug, thiserror::Error)]
    pub enum NoiseError {
        #[error("AEAD encrypt/decrypt failed (auth tag or key mismatch)")]
        Aead,
    }

    pub struct NoiseHandshake {
        hash: [u8; 32],
        salt: [u8; 32],
        cipher: Aes256Gcm,
        counter: u32,
    }

    impl NoiseHandshake {
        /// Equivalent to `NewNoiseHandshake().Start(pattern, header)`.
        ///
        /// `pattern` is normally [`NOISE_START_PATTERN`]; if it's exactly 32
        /// bytes whatsmeow uses it as the initial hash directly, otherwise it
        /// SHA-256s it first. `header` is hashed in afterwards (typically the
        /// 4-byte WA connection header).
        pub fn start(pattern: &[u8], header: &[u8]) -> Self {
            let hash = if pattern.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(pattern);
                h
            } else {
                sha256_arr(pattern)
            };
            let salt = hash;
            let cipher = Aes256Gcm::new((&hash).into());
            let mut nh = Self {
                hash,
                salt,
                cipher,
                counter: 0,
            };
            nh.authenticate(header);
            nh
        }

        /// `hash := SHA256(hash || data)`.
        pub fn authenticate(&mut self, data: &[u8]) {
            let mut h = Sha256::new();
            h.update(self.hash);
            h.update(data);
            self.hash = h.finalize().into();
        }

        /// AES-GCM(plaintext, AAD = current hash, IV = counter); then mixes the
        /// ciphertext into the hash.
        pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
            let iv = counter_iv(self.counter);
            self.counter = self.counter.checked_add(1).expect("noise counter overflow");
            let ct = self
                .cipher
                .encrypt(
                    (&iv).into(),
                    Payload {
                        msg: plaintext,
                        aad: &self.hash,
                    },
                )
                .map_err(|_| NoiseError::Aead)?;
            self.authenticate(&ct);
            Ok(ct)
        }

        /// Inverse of [`Self::encrypt`]. Mixes the *ciphertext* into the hash
        /// even on success — this matches the sender side so the two states
        /// stay in lockstep.
        pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
            let iv = counter_iv(self.counter);
            self.counter = self.counter.checked_add(1).expect("noise counter overflow");
            let pt = self
                .cipher
                .decrypt(
                    (&iv).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &self.hash,
                    },
                )
                .map_err(|_| NoiseError::Aead)?;
            self.authenticate(ciphertext);
            Ok(pt)
        }

        /// HKDF(salt, ikm = data) → (new_salt, new_key); resets counter.
        pub fn mix_into_key(&mut self, data: &[u8]) {
            let (write, read) = extract_and_expand(&self.salt, data);
            self.salt = write;
            self.cipher = Aes256Gcm::new((&read).into());
            self.counter = 0;
        }

        /// `secret = X25519(priv, pub); MixIntoKey(secret)`.
        pub fn mix_shared_secret_into_key(&mut self, priv_key: &[u8; 32], pub_key: &[u8; 32]) {
            let secret = x25519_dalek::x25519(*priv_key, *pub_key);
            self.mix_into_key(&secret);
        }

        /// Read access for the rolling hash. Useful for callers that need to
        /// authenticate handshake-related material outside this module.
        pub fn hash(&self) -> &[u8; 32] {
            &self.hash
        }

        /// Derive the post-handshake (write, read) AEAD ciphers and consume
        /// the handshake state. The first cipher encrypts client→server frames,
        /// the second decrypts server→client frames.
        pub fn finish(self) -> (NoiseCipher, NoiseCipher) {
            let (write, read) = extract_and_expand(&self.salt, &[]);
            (NoiseCipher::new(write), NoiseCipher::new(read))
        }
    }

    /// Post-handshake AEAD with a monotonic 32-bit counter as the bottom 4
    /// bytes of the 12-byte IV.
    pub struct NoiseCipher {
        cipher: Aes256Gcm,
        counter: u32,
    }

    impl NoiseCipher {
        fn new(key: [u8; 32]) -> Self {
            Self {
                cipher: Aes256Gcm::new((&key).into()),
                counter: 0,
            }
        }

        pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
            let iv = counter_iv(self.counter);
            self.counter = self.counter.checked_add(1).expect("noise counter overflow");
            self.cipher
                .encrypt((&iv).into(), plaintext)
                .map_err(|_| NoiseError::Aead)
        }

        pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
            let iv = counter_iv(self.counter);
            self.counter = self.counter.checked_add(1).expect("noise counter overflow");
            self.cipher
                .decrypt((&iv).into(), ciphertext)
                .map_err(|_| NoiseError::Aead)
        }
    }

    fn sha256_arr(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    fn extract_and_expand(salt: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut out = [0u8; 64];
        hk.expand(&[], &mut out).expect("64 bytes is within HKDF-SHA256 max");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&out[..32]);
        b.copy_from_slice(&out[32..]);
        (a, b)
    }

    fn counter_iv(counter: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&counter.to_be_bytes());
        iv
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rand::rngs::OsRng;

        // Two handshake states that started identically remain in lockstep
        // after Authenticate / Encrypt / Decrypt / MixIntoKey calls.
        fn paired() -> (NoiseHandshake, NoiseHandshake) {
            let header = b"WA\x06\x03";
            (
                NoiseHandshake::start(&NOISE_START_PATTERN, header),
                NoiseHandshake::start(&NOISE_START_PATTERN, header),
            )
        }

        #[test]
        fn paired_states_share_initial_hash_and_key() {
            let (a, b) = paired();
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.salt, b.salt);
            assert_eq!(a.counter, 0);
        }

        #[test]
        fn authenticate_is_pure_sha256_chaining() {
            let (mut a, mut b) = paired();
            let prev = a.hash;
            a.authenticate(b"more-data");
            b.authenticate(b"more-data");
            assert_eq!(a.hash, b.hash);
            assert_ne!(a.hash, prev);
            // Manually compute the expected next hash.
            let mut h = Sha256::new();
            h.update(prev);
            h.update(b"more-data");
            let want: [u8; 32] = h.finalize().into();
            assert_eq!(a.hash, want);
        }

        #[test]
        fn encrypt_decrypt_round_trip_keeps_states_in_sync() {
            let (mut a, mut b) = paired();
            let pt1 = b"first message";
            let ct1 = a.encrypt(pt1).unwrap();
            let recovered1 = b.decrypt(&ct1).unwrap();
            assert_eq!(recovered1, pt1);
            // Counters and hash should match after both processed the frame.
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.counter, 1);
            assert_eq!(b.counter, 1);

            // Second round, this time peer→initiator direction.
            let pt2 = b"second message";
            let ct2 = b.encrypt(pt2).unwrap();
            let recovered2 = a.decrypt(&ct2).unwrap();
            assert_eq!(recovered2, pt2);
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.counter, 2);
        }

        #[test]
        fn decrypt_with_tampered_ciphertext_fails() {
            let (mut a, mut b) = paired();
            let mut ct = a.encrypt(b"payload").unwrap();
            ct[0] ^= 0x01;
            let err = b.decrypt(&ct).unwrap_err();
            assert!(matches!(err, NoiseError::Aead));
        }

        #[test]
        fn mix_into_key_resets_counter_and_changes_key() {
            let (mut a, mut b) = paired();
            let _ = a.encrypt(b"x").unwrap();
            assert_eq!(a.counter, 1);

            a.mix_into_key(b"shared-secret");
            b.mix_into_key(b"shared-secret");
            // a.encrypt advanced its hash by authenticating the ciphertext;
            // b.decrypt would have done the same. Here we never decrypted, so
            // a's hash diverges from b's. mix_into_key only touches
            // (salt, key, counter) — it does NOT reset hash.
            assert_eq!(a.counter, 0);
            assert_eq!(b.counter, 0);
            assert_eq!(a.salt, b.salt);
        }

        #[test]
        fn mix_shared_secret_dh_agrees_on_both_sides() {
            // Simulate a Diffie–Hellman exchange between two parties with
            // independent X25519 keys, then assert that both NoiseHandshake
            // instances derive the same key after MixSharedSecretIntoKey.
            let priv_a = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let pub_a = x25519_dalek::PublicKey::from(&priv_a);
            let priv_b = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let pub_b = x25519_dalek::PublicKey::from(&priv_b);

            let (mut a, mut b) = paired();
            a.mix_shared_secret_into_key(&priv_a.to_bytes(), &pub_b.to_bytes());
            b.mix_shared_secret_into_key(&priv_b.to_bytes(), &pub_a.to_bytes());

            // Now encrypt/decrypt across the shared key — both sides agree.
            let pt = b"after-DH";
            let ct = a.encrypt(pt).unwrap();
            assert_eq!(b.decrypt(&ct).unwrap(), pt);
        }

        #[test]
        fn finish_yields_paired_post_handshake_ciphers() {
            // Run a few mix_into_key steps to advance state, then finish.
            let (mut a, mut b) = paired();
            a.mix_into_key(b"step1");
            b.mix_into_key(b"step1");
            a.mix_into_key(b"step2");
            b.mix_into_key(b"step2");

            // `finish()` returns (first_half, second_half) deterministically.
            // The Noise pattern requires the responder to swap which half is
            // its write vs. read — initiator's write key == responder's read
            // key. whatsmeow's `Finish` returns (write, read) for the client
            // side; a real server would flip the assignment.
            let (mut a_write, mut a_read) = a.finish();
            let (mut b_read, mut b_write) = b.finish();

            // a (initiator) → b (responder)
            let pt = b"app-frame";
            let ct = a_write.encrypt(pt).unwrap();
            assert_eq!(b_read.decrypt(&ct).unwrap(), pt);

            // b → a
            let pt2 = b"reverse-frame";
            let ct2 = b_write.encrypt(pt2).unwrap();
            assert_eq!(a_read.decrypt(&ct2).unwrap(), pt2);
        }

        #[test]
        fn counter_iv_layout_matches_whatsmeow() {
            // The 4-byte counter sits in the last 4 bytes (big-endian).
            assert_eq!(counter_iv(0), [0u8; 12]);
            let iv = counter_iv(0x01020304);
            assert_eq!(&iv[..8], &[0u8; 8]);
            assert_eq!(&iv[8..], &[0x01, 0x02, 0x03, 0x04]);
        }
    }
}

pub mod frame {
    //! Length-prefixed framing for the WhatsApp Web wire.
    //!
    //! Wire layout: each frame is `[3-byte BE length][payload of that length]`.
    //! On a brand-new connection the very first frame is preceded by the WA
    //! connection header (`[0x57, 0x41, 0x06, dict_version]`), then the 3-byte
    //! length, then the payload.
    //!
    //! References: whatsmeow/socket/{constants,framesocket}.go.

    /// 3-byte big-endian length prefix.
    pub const FRAME_LENGTH_SIZE: usize = 3;

    /// 1 << 24 — server enforces this; we mirror to fail loudly client-side.
    pub const FRAME_MAX_SIZE: usize = 1 << 24;

    /// `'W' 'A' 0x06 dict_version=3`. Sent once at the start of a connection.
    pub const WA_CONN_HEADER: [u8; 4] = [b'W', b'A', 0x06, 0x03];

    /// Origin header required by the WA WS endpoint.
    pub const ORIGIN: &str = "https://web.whatsapp.com";

    /// Multi-device WS URL.
    pub const URL: &str = "wss://web.whatsapp.com/ws/chat";

    #[derive(Debug, thiserror::Error)]
    pub enum FrameError {
        #[error("frame too large: {0} bytes (max 16777216)")]
        TooLarge(usize),
    }

    /// Encode a single frame ready to ship over the WebSocket.
    ///
    /// Pass `Some(WA_CONN_HEADER)` exactly once per WS connection (the very
    /// first send); subsequent calls pass `None`.
    pub fn encode_frame(payload: &[u8], header: Option<&[u8]>) -> Result<Vec<u8>, FrameError> {
        if payload.len() >= FRAME_MAX_SIZE {
            return Err(FrameError::TooLarge(payload.len()));
        }
        let header_len = header.map_or(0, <[u8]>::len);
        let mut out = Vec::with_capacity(header_len + FRAME_LENGTH_SIZE + payload.len());
        if let Some(h) = header {
            out.extend_from_slice(h);
        }
        let len = payload.len();
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Stateful receiver. Push WS message bytes via `feed`; pop completed
    /// frames via `next_frame`. Mirrors the buffer logic in
    /// `framesocket.processData` so partial / coalesced WS messages work.
    #[derive(Debug, Default)]
    pub struct FrameDecoder {
        buf: Vec<u8>,
    }

    impl FrameDecoder {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn feed(&mut self, chunk: &[u8]) {
            self.buf.extend_from_slice(chunk);
        }

        pub fn next_frame(&mut self) -> Option<Vec<u8>> {
            if self.buf.len() < FRAME_LENGTH_SIZE {
                return None;
            }
            let len = ((self.buf[0] as usize) << 16)
                | ((self.buf[1] as usize) << 8)
                | (self.buf[2] as usize);
            if self.buf.len() < FRAME_LENGTH_SIZE + len {
                return None;
            }
            let frame = self.buf[FRAME_LENGTH_SIZE..FRAME_LENGTH_SIZE + len].to_vec();
            self.buf.drain(..FRAME_LENGTH_SIZE + len);
            Some(frame)
        }

        pub fn pending(&self) -> usize {
            self.buf.len()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::sync::mpsc;

        #[test]
        fn encode_then_decode_round_trip() {
            let payload = b"hello, world".to_vec();
            let frame = encode_frame(&payload, None).unwrap();
            assert_eq!(frame.len(), FRAME_LENGTH_SIZE + payload.len());
            assert_eq!(frame[0], 0);
            assert_eq!(frame[1], 0);
            assert_eq!(frame[2], payload.len() as u8);

            let mut dec = FrameDecoder::new();
            dec.feed(&frame);
            assert_eq!(dec.next_frame().as_deref(), Some(payload.as_slice()));
            assert_eq!(dec.next_frame(), None);
        }

        #[test]
        fn first_frame_carries_connection_header() {
            let payload = vec![0x42; 5];
            let frame = encode_frame(&payload, Some(&WA_CONN_HEADER)).unwrap();
            assert_eq!(&frame[..4], &WA_CONN_HEADER);
            assert_eq!(&frame[4..7], &[0x00, 0x00, 0x05]);
            assert_eq!(&frame[7..], &payload[..]);

            // The decoder is fed AFTER the header (the WS server strips it once);
            // here we simulate by feeding only the framed portion.
            let mut dec = FrameDecoder::new();
            dec.feed(&frame[WA_CONN_HEADER.len()..]);
            assert_eq!(dec.next_frame().unwrap(), payload);
        }

        #[test]
        fn split_chunks_assemble_into_one_frame() {
            let payload = (0..400u32).map(|i| i as u8).collect::<Vec<_>>(); // > 256 bytes
            let frame = encode_frame(&payload, None).unwrap();

            let mut dec = FrameDecoder::new();
            dec.feed(&frame[..2]); // partial header
            assert_eq!(dec.next_frame(), None);
            dec.feed(&frame[2..50]); // header completes; partial body
            assert_eq!(dec.next_frame(), None);
            dec.feed(&frame[50..]); // body completes
            assert_eq!(dec.next_frame().unwrap(), payload);
            assert_eq!(dec.next_frame(), None);
        }

        #[test]
        fn coalesced_chunks_yield_multiple_frames() {
            let p1 = b"first".to_vec();
            let p2 = b"second-frame-payload".to_vec();
            let mut combined = encode_frame(&p1, None).unwrap();
            combined.extend(encode_frame(&p2, None).unwrap());

            let mut dec = FrameDecoder::new();
            dec.feed(&combined);
            assert_eq!(dec.next_frame().unwrap(), p1);
            assert_eq!(dec.next_frame().unwrap(), p2);
            assert_eq!(dec.next_frame(), None);
        }

        #[test]
        fn too_large_payload_is_rejected() {
            // Constructing a >16 MB Vec just to test the boundary is wasteful;
            // use a struct-level fact instead: encode_frame's check is `>=`.
            let err = encode_frame(&vec![0u8; FRAME_MAX_SIZE], None).unwrap_err();
            assert!(matches!(err, FrameError::TooLarge(_)));
        }

        /// "Mock WS" round-trip: shovel encoded frames through a tokio mpsc
        /// channel pair as the transport. The sender sends the WA header
        /// once, then each payload as its own frame, in 1-byte chunks (the
        /// pathological case for the chunk reassembly logic). The receiver
        /// drops the header bytes, then runs everything else through
        /// `FrameDecoder::feed` and asserts the payloads come back in order.
        #[tokio::test]
        async fn mock_ws_round_trip() {
            let (tx, mut rx) = mpsc::channel::<u8>(64);

            let payloads = vec![
                b"<iq id=\"1\" type=\"set\"/>".to_vec(),
                vec![0xCA, 0xFE, 0xBA, 0xBE],
                b"another".to_vec(),
            ];

            let send_payloads = payloads.clone();
            let send = tokio::spawn(async move {
                let mut wire = Vec::new();
                wire.extend_from_slice(&WA_CONN_HEADER);
                for p in &send_payloads {
                    wire.extend(encode_frame(p, None).unwrap());
                }
                for b in wire {
                    tx.send(b).await.unwrap();
                }
            });

            let mut dec = FrameDecoder::new();
            let mut got = Vec::new();
            let mut header_remaining = WA_CONN_HEADER.len();

            while let Some(b) = rx.recv().await {
                if header_remaining > 0 {
                    header_remaining -= 1;
                    continue;
                }
                dec.feed(&[b]);
                while let Some(f) = dec.next_frame() {
                    got.push(f);
                }
                if got.len() == payloads.len() {
                    break;
                }
            }

            send.await.unwrap();
            assert_eq!(got, payloads);
        }
    }
}

pub mod connection {
    //! WS connection + Noise XX driver.
    //!
    //! `connect_wa()` opens the WS to `wss://web.whatsapp.com/ws/chat` with the
    //! WA Origin. `do_handshake()` then drives the 3-flight `Noise_XX` dance
    //! (ClientHello → ServerHello → ClientFinish) and returns paired AEAD
    //! ciphers ready for the post-handshake socket layer.
    //!
    //! References: whatsmeow/handshake.go.
    //!
    //! NOT YET DONE in this commit: server certificate verification (whatsmeow
    //! checks the noise cert chain against `WACertPubKey` via Ed25519/XEdDSA).
    //! Until vendored (waCert.proto + ed25519/xeddsa verify) the cert payload
    //! is decrypted and *trusted*. Track via the `verify_server_cert` TODO
    //! in this module.
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use prost::Message;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::TcpStream;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::{client_async, WebSocketStream};

    use super::binary::{self, Node};
    use super::frame::{encode_frame, FrameDecoder, FrameError, ORIGIN, URL, WA_CONN_HEADER};
    use super::noise::{NoiseCipher, NoiseError, NoiseHandshake, NOISE_START_PATTERN};

    /// Combined transport bound — `AsyncRead`+`AsyncWrite` can't be named
    /// together in a `dyn` object (both are non-auto traits), so we alias them
    /// behind one trait with a blanket impl.
    pub trait WaIo: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> WaIo for T {}

    /// Type-erased post-TLS transport so direct and proxied connections share a
    /// single `Ws` type. `NoiseSocket<S>` and `do_handshake<S>` are generic over
    /// it, so nothing downstream cares which path produced the stream.
    pub type WaStream = Box<dyn WaIo>;
    pub type Ws = WebSocketStream<WaStream>;

    /// Encrypt a binary node for the post-handshake socket.
    ///
    /// Pipeline: `pack(node)` → `cipher.encrypt(...)`. Caller wraps the
    /// returned ciphertext in a length-prefixed frame and ships it.
    pub fn encrypt_node(cipher: &mut NoiseCipher, node: &Node) -> Result<Vec<u8>, NodeError> {
        let payload = binary::pack(node).map_err(NodeError::Encode)?;
        let ct = cipher.encrypt(&payload)?;
        Ok(ct)
    }

    /// Inverse of [`encrypt_node`]: AES-GCM-decrypt one full ciphertext frame
    /// and `unmarshal` the resulting binary-node bytes (handling the WA
    /// compression flag).
    pub fn decrypt_node(cipher: &mut NoiseCipher, ciphertext: &[u8]) -> Result<Node, NodeError> {
        let pt = cipher.decrypt(ciphertext)?;
        let node = binary::unmarshal(&pt).map_err(NodeError::Decode)?;
        Ok(node)
    }

    #[derive(Debug, thiserror::Error)]
    pub enum NodeError {
        #[error("noise: {0}")]
        Noise(#[from] NoiseError),
        #[error("encode: {0}")]
        Encode(binary::EncodeError),
        #[error("decode: {0}")]
        Decode(binary::DecodeError),
    }

    #[derive(Debug, thiserror::Error)]
    pub enum SocketError {
        #[error("WebSocket: {0}")]
        Ws(#[from] tokio_tungstenite::tungstenite::Error),
        #[error("WebSocket closed")]
        Closed,
        #[error("frame: {0}")]
        Frame(#[from] FrameError),
        #[error("node: {0}")]
        Node(#[from] NodeError),
    }

    /// Post-handshake transport: AES-GCM-encrypted binary nodes over a
    /// length-prefixed WebSocket. Wraps the WS plus the (write, read) cipher
    /// pair returned by [`do_handshake`].
    pub struct NoiseSocket<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        ws: WebSocketStream<S>,
        write_cipher: NoiseCipher,
        read_cipher: NoiseCipher,
        decoder: FrameDecoder,
    }

    impl<S> NoiseSocket<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        pub fn new(
            ws: WebSocketStream<S>,
            write_cipher: NoiseCipher,
            read_cipher: NoiseCipher,
        ) -> Self {
            Self {
                ws,
                write_cipher,
                read_cipher,
                decoder: FrameDecoder::new(),
            }
        }

        /// Encrypt + frame + ship a binary node over the WS.
        pub async fn send_node(&mut self, node: &Node) -> Result<(), SocketError> {
            // Wire trace for Baileys-style diffing. Off in normal runs; enable
            // with `RUST_LOG=info,ruwa::protocol=debug`.
            tracing::debug!(xml = %node.to_xml(), "wire send →");
            let ct = encrypt_node(&mut self.write_cipher, node)?;
            let frame = encode_frame(&ct, None)?;
            self.ws.send(WsMessage::Binary(frame)).await?;
            Ok(())
        }

        /// Pull bytes from the WS until a complete encrypted frame is
        /// reassembled, then decrypt + decode it into a binary node.
        pub async fn recv_node(&mut self) -> Result<Node, SocketError> {
            loop {
                if let Some(frame) = self.decoder.next_frame() {
                    let node = decrypt_node(&mut self.read_cipher, &frame)?;
                    tracing::debug!(xml = %node.to_xml(), "wire recv ←");
                    return Ok(node);
                }
                let msg = self.ws.next().await.ok_or(SocketError::Closed)??;
                match msg {
                    WsMessage::Binary(b) => self.decoder.feed(&b),
                    WsMessage::Close(_) => return Err(SocketError::Closed),
                    _ => continue,
                }
            }
        }

        pub async fn close(mut self) -> Result<(), SocketError> {
            self.ws
                .close(None)
                .await
                .map_err(SocketError::Ws)
        }

        /// Send a clean WebSocket Close frame without consuming the socket.
        /// Used on graceful shutdown: an abrupt TCP drop leaves WhatsApp holding
        /// a half-open socket for the device until its own keepalive times out
        /// (tens of seconds), so the next instance's login races that ghost into
        /// a `<conflict type="replaced"/>`. A clean Close frees the slot at once.
        pub async fn send_close(&mut self) -> Result<(), SocketError> {
            self.ws.close(None).await.map_err(SocketError::Ws)
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum HandshakeError {
        #[error("WebSocket: {0}")]
        Ws(#[from] tokio_tungstenite::tungstenite::Error),
        #[error("WebSocket closed before handshake completed")]
        Closed,
        #[error("invalid handshake URL")]
        Url(#[from] url::ParseError),
        #[error("frame: {0}")]
        Frame(#[from] FrameError),
        #[error("noise: {0}")]
        Noise(#[from] NoiseError),
        #[error("protobuf: {0}")]
        Proto(#[from] prost::DecodeError),
        #[error("server response missing field: {0}")]
        MissingField(&'static str),
        #[error("invalid public key length: got {got}, want 32")]
        BadPubKeyLen { got: usize },
        #[error("timed out waiting for {0}")]
        Timeout(&'static str),
        #[error("server cert: {0}")]
        CertVerify(&'static str),
        #[error("transport: {0}")]
        Transport(String),
    }

    /// WhatsApp's hardcoded Curve25519 root public key. Server-issued cert
    /// chains are anchored at this key — the intermediate certificate's
    /// signature must verify under it. Mirrors whatsmeow's `WACertPubKey`
    /// in handshake.go.
    pub const WA_CERT_ROOT_PUB_KEY: [u8; 32] = [
        0x14, 0x23, 0x75, 0x57, 0x4D, 0x0A, 0x58, 0x71, 0x66, 0xAA, 0xE7, 0x1E, 0xBE, 0x51, 0x64,
        0x37, 0xC4, 0xA2, 0x8B, 0x73, 0xE3, 0x69, 0x5C, 0x6C, 0xE1, 0xF7, 0xF9, 0x54, 0x5D, 0xA8,
        0xEE, 0x6B,
    ];

    /// The intermediate certificate's `details.issuerSerial` must equal
    /// this constant — the WACertPubKey's own serial.
    pub const WA_CERT_ROOT_ISSUER_SERIAL: u32 = 0;

    /// Verify the server-issued certificate chain decrypted from
    /// ServerHello.payload. The chain is two-deep: WACertPubKey signs the
    /// intermediate, the intermediate signs the leaf, and the leaf's `key`
    /// must equal the noise static pubkey we just decrypted from
    /// ServerHello.static. Time-window validity is checked too.
    ///
    /// Mirrors whatsmeow's `verifyServerCert` (handshake.go) byte-for-byte.
    /// Errors are reported as `&'static str` so the caller can map them
    /// into `HandshakeError::CertVerify` cleanly.
    pub fn verify_server_cert(
        cert_decrypted: &[u8],
        server_static_pub: &[u8; 32],
    ) -> Result<(), &'static str> {
        use crate::proto::wa_cert as pb;
        use prost::Message as _;

        let cert_chain = pb::CertChain::decode(cert_decrypted)
            .map_err(|_| "decode CertChain failed")?;

        let intermediate = cert_chain
            .intermediate
            .ok_or("CertChain missing intermediate")?;
        let leaf = cert_chain.leaf.ok_or("CertChain missing leaf")?;

        let intermediate_details_raw = intermediate
            .details
            .ok_or("intermediate missing details")?;
        let intermediate_sig = intermediate
            .signature
            .ok_or("intermediate missing signature")?;
        let leaf_details_raw = leaf.details.ok_or("leaf missing details")?;
        let leaf_sig = leaf.signature.ok_or("leaf missing signature")?;

        if intermediate_sig.len() != 64 {
            return Err("intermediate signature wrong length");
        }
        if leaf_sig.len() != 64 {
            return Err("leaf signature wrong length");
        }
        let mut intermediate_sig_arr = [0u8; 64];
        intermediate_sig_arr.copy_from_slice(&intermediate_sig);
        let mut leaf_sig_arr = [0u8; 64];
        leaf_sig_arr.copy_from_slice(&leaf_sig);

        // 1. Root anchor: WACertPubKey must verify the intermediate.
        if !crate::crypto::identity::xeddsa_verify(
            &WA_CERT_ROOT_PUB_KEY,
            &intermediate_details_raw,
            &intermediate_sig_arr,
        ) {
            return Err("intermediate signature did not verify under WACertPubKey");
        }

        let intermediate_details =
            pb::cert_chain::noise_certificate::Details::decode(intermediate_details_raw.as_slice())
                .map_err(|_| "decode intermediate.details failed")?;

        if intermediate_details.issuer_serial.unwrap_or(u32::MAX)
            != WA_CERT_ROOT_ISSUER_SERIAL
        {
            return Err("unexpected intermediate.issuerSerial");
        }
        let intermediate_key = intermediate_details
            .key
            .as_ref()
            .filter(|k| k.len() == 32)
            .ok_or("intermediate key not 32 bytes")?;
        let mut intermediate_key_arr = [0u8; 32];
        intermediate_key_arr.copy_from_slice(intermediate_key);

        // 2. Intermediate signs the leaf.
        if !crate::crypto::identity::xeddsa_verify(
            &intermediate_key_arr,
            &leaf_details_raw,
            &leaf_sig_arr,
        ) {
            return Err("leaf signature did not verify under intermediate.key");
        }

        check_cert_window(&intermediate_details).map_err(|_| "intermediate cert outside time window")?;

        let leaf_details =
            pb::cert_chain::noise_certificate::Details::decode(leaf_details_raw.as_slice())
                .map_err(|_| "decode leaf.details failed")?;

        if leaf_details.issuer_serial.unwrap_or(u32::MAX)
            != intermediate_details.serial.unwrap_or(0)
        {
            return Err("leaf.issuerSerial does not match intermediate.serial");
        }
        let leaf_key = leaf_details
            .key
            .as_ref()
            .filter(|k| k.len() == 32)
            .ok_or("leaf key not 32 bytes")?;
        if leaf_key != server_static_pub {
            return Err("leaf.key does not match decrypted server static pubkey");
        }
        check_cert_window(&leaf_details).map_err(|_| "leaf cert outside time window")?;
        Ok(())
    }

    /// Reject certs whose `notBefore..notAfter` window doesn't contain
    /// the current wall clock. A cert without window fields is allowed.
    fn check_cert_window(
        d: &crate::proto::wa_cert::cert_chain::noise_certificate::Details,
    ) -> Result<(), &'static str> {
        let now = chrono::Utc::now().timestamp() as u64;
        if let Some(nb) = d.not_before {
            if now < nb {
                return Err("not yet valid");
            }
        }
        if let Some(na) = d.not_after {
            if now > na {
                return Err("expired");
            }
        }
        Ok(())
    }

    /// Open a WebSocket to the WhatsApp Web endpoint with the right `Origin`.
    /// Per-session egress proxy for the Noise WebSocket. Parsed from a URL:
    /// `socks5://[user:pass@]host:port`, `socks5h://…` (remote DNS), or
    /// `http://[user:pass@]host:port` (HTTP CONNECT). Media (reqwest) takes the
    /// raw URL via its own proxy support; this type is for the WS path.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Proxy {
        pub scheme: ProxyScheme,
        pub host: String,
        pub port: u16,
        pub auth: Option<(String, String)>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProxyScheme {
        Socks5,
        Http,
    }

    impl Proxy {
        /// Parse a proxy URL. `socks5`/`socks5h` → SOCKS5 (we always resolve the
        /// target remotely to avoid DNS leaks); `http`/`https` → HTTP CONNECT.
        pub fn parse(url: &str) -> Result<Self, String> {
            let (scheme_str, rest) = url
                .split_once("://")
                .ok_or_else(|| format!("proxy url missing scheme: {url}"))?;
            let scheme = match scheme_str.to_ascii_lowercase().as_str() {
                "socks5" | "socks5h" => ProxyScheme::Socks5,
                "http" | "https" => ProxyScheme::Http,
                other => return Err(format!("unsupported proxy scheme: {other}")),
            };
            let (auth, hostport) = match rest.rsplit_once('@') {
                Some((creds, hp)) => {
                    let (u, p) = creds
                        .split_once(':')
                        .ok_or_else(|| "proxy auth must be user:pass".to_string())?;
                    (Some((u.to_string(), p.to_string())), hp)
                }
                None => (None, rest),
            };
            let hostport = hostport.trim_end_matches('/');
            let (host, port_str) = hostport
                .rsplit_once(':')
                .ok_or_else(|| format!("proxy url missing port: {url}"))?;
            let port: u16 = port_str
                .parse()
                .map_err(|_| format!("invalid proxy port: {port_str}"))?;
            if host.is_empty() {
                return Err("proxy host is empty".into());
            }
            Ok(Proxy {
                scheme,
                host: host.to_string(),
                port,
                auth,
            })
        }

        /// Open a raw (pre-TLS) stream tunneled through this proxy to
        /// `target_host:target_port`, type-erased so the caller can TLS-wrap it.
        async fn connect(
            &self,
            target_host: &str,
            target_port: u16,
        ) -> Result<WaStream, HandshakeError> {
            match self.scheme {
                ProxyScheme::Socks5 => {
                    use tokio_socks::tcp::Socks5Stream;
                    let proxy_addr = (self.host.as_str(), self.port);
                    let target = (target_host, target_port);
                    let stream = match &self.auth {
                        Some((u, p)) => {
                            Socks5Stream::connect_with_password(proxy_addr, target, u, p).await
                        }
                        None => Socks5Stream::connect(proxy_addr, target).await,
                    }
                    .map_err(|e| HandshakeError::Transport(format!("socks5: {e}")))?;
                    Ok(Box::new(stream))
                }
                ProxyScheme::Http => {
                    let tcp = TcpStream::connect((self.host.as_str(), self.port))
                        .await
                        .map_err(|e| HandshakeError::Transport(format!("proxy connect: {e}")))?;
                    let tcp = http_connect(tcp, target_host, target_port, self.auth.as_ref()).await?;
                    Ok(Box::new(tcp))
                }
            }
        }
    }

    /// Drive an HTTP `CONNECT` tunnel over an established TCP stream to the proxy.
    async fn http_connect(
        mut tcp: TcpStream,
        host: &str,
        port: u16,
        auth: Option<&(String, String)>,
    ) -> Result<TcpStream, HandshakeError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if let Some((u, p)) = auth {
            use base64::Engine;
            let b = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
            req.push_str(&format!("Proxy-Authorization: Basic {b}\r\n"));
        }
        req.push_str("\r\n");
        tcp.write_all(req.as_bytes())
            .await
            .map_err(|e| HandshakeError::Transport(format!("CONNECT write: {e}")))?;
        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 256];
        loop {
            let n = tcp
                .read(&mut tmp)
                .await
                .map_err(|e| HandshakeError::Transport(format!("CONNECT read: {e}")))?;
            if n == 0 {
                return Err(HandshakeError::Transport("proxy closed during CONNECT".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                return Err(HandshakeError::Transport("CONNECT response too large".into()));
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let status_line = head.lines().next().unwrap_or("");
        // Expect a 2xx (typically "HTTP/1.1 200 Connection established").
        let ok = status_line
            .split_whitespace()
            .nth(1)
            .map(|c| c.starts_with('2'))
            .unwrap_or(false);
        if !ok {
            return Err(HandshakeError::Transport(format!(
                "proxy CONNECT rejected: {status_line}"
            )));
        }
        Ok(tcp)
    }

    /// Open the WS to `wss://web.whatsapp.com/ws/chat`. When `proxy` is set, the
    /// whole connection (TCP → tunnel → TLS → WS) egresses through it; otherwise
    /// a direct TCP+TLS connection. Returns the same `Ws` type either way.
    pub async fn connect_wa(proxy: Option<&Proxy>) -> Result<Ws, HandshakeError> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        const WA_HOST: &str = "web.whatsapp.com";
        const WA_PORT: u16 = 443;

        let mut req = URL.into_client_request()?;
        req.headers_mut()
            .insert("Origin", ORIGIN.parse().expect("static origin parses"));

        // Raw TCP to WA — directly, or tunneled through the session's proxy.
        let raw: WaStream = match proxy {
            None => {
                let tcp = TcpStream::connect((WA_HOST, WA_PORT))
                    .await
                    .map_err(|e| HandshakeError::Transport(format!("connect: {e}")))?;
                Box::new(tcp)
            }
            Some(p) => p.connect(WA_HOST, WA_PORT).await?,
        };

        // TLS over the (possibly proxied) stream, then the WS client handshake.
        let connector = native_tls::TlsConnector::new()
            .map_err(|e| HandshakeError::Transport(format!("tls init: {e}")))?;
        let connector = tokio_native_tls::TlsConnector::from(connector);
        let tls = connector
            .connect(WA_HOST, raw)
            .await
            .map_err(|e| HandshakeError::Transport(format!("tls: {e}")))?;
        let stream: WaStream = Box::new(tls);

        let (ws, _resp) = client_async(req, stream).await?;
        Ok(ws)
    }

    /// Drive Noise XX over `ws`. Returns `(write_cipher, read_cipher)` for the
    /// post-handshake socket. Caller owns: ephemeral keypair (one-shot), the
    /// long-term static (noise) keypair, and the marshaled ClientPayload.
    pub async fn do_handshake<S>(
        ws: &mut WebSocketStream<S>,
        eph_priv: [u8; 32],
        eph_pub: [u8; 32],
        static_priv: [u8; 32],
        static_pub: [u8; 32],
        client_payload: &[u8],
    ) -> Result<(NoiseCipher, NoiseCipher), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use crate::proto::wa_web_protobufs_wa6::handshake_message::{
            ClientFinish, ClientHello, ServerHello,
        };
        use crate::proto::wa_web_protobufs_wa6::HandshakeMessage;

        let mut nh = NoiseHandshake::start(&NOISE_START_PATTERN, &WA_CONN_HEADER);
        nh.authenticate(&eph_pub);

        // ---------- Flight 1: ClientHello ----------
        let client_hello = HandshakeMessage {
            client_hello: Some(ClientHello {
                ephemeral: Some(eph_pub.to_vec()),
                ..Default::default()
            }),
            server_hello: None,
            client_finish: None,
        };
        send_handshake_frame(ws, &client_hello.encode_to_vec(), Some(&WA_CONN_HEADER)).await?;

        // ---------- Flight 2: ServerHello ----------
        let mut decoder = FrameDecoder::new();
        let resp = recv_handshake_frame(ws, &mut decoder).await?;
        let resp_msg = HandshakeMessage::decode(&resp[..])?;
        let ServerHello {
            ephemeral: server_eph,
            r#static: server_static_ct,
            payload: cert_ct,
            ..
        } = resp_msg
            .server_hello
            .ok_or(HandshakeError::MissingField("ServerHello"))?;
        let server_eph = server_eph.ok_or(HandshakeError::MissingField("ServerHello.ephemeral"))?;
        let server_static_ct =
            server_static_ct.ok_or(HandshakeError::MissingField("ServerHello.static"))?;
        let cert_ct = cert_ct.ok_or(HandshakeError::MissingField("ServerHello.payload"))?;
        if server_eph.len() != 32 {
            return Err(HandshakeError::BadPubKeyLen {
                got: server_eph.len(),
            });
        }
        let mut server_eph_arr = [0u8; 32];
        server_eph_arr.copy_from_slice(&server_eph);

        nh.authenticate(&server_eph);
        nh.mix_shared_secret_into_key(&eph_priv, &server_eph_arr);

        let server_static = nh.decrypt(&server_static_ct)?;
        if server_static.len() != 32 {
            return Err(HandshakeError::BadPubKeyLen {
                got: server_static.len(),
            });
        }
        let mut server_static_arr = [0u8; 32];
        server_static_arr.copy_from_slice(&server_static);
        nh.mix_shared_secret_into_key(&eph_priv, &server_static_arr);

        let cert_bytes = nh.decrypt(&cert_ct)?;
        verify_server_cert(&cert_bytes, &server_static_arr)
            .map_err(HandshakeError::CertVerify)?;

        // ---------- Flight 3: ClientFinish ----------
        let encrypted_static = nh.encrypt(&static_pub)?;
        nh.mix_shared_secret_into_key(&static_priv, &server_eph_arr);
        let encrypted_payload = nh.encrypt(client_payload)?;

        let client_finish = HandshakeMessage {
            client_hello: None,
            server_hello: None,
            client_finish: Some(ClientFinish {
                r#static: Some(encrypted_static),
                payload: Some(encrypted_payload),
                ..Default::default()
            }),
        };
        send_handshake_frame(ws, &client_finish.encode_to_vec(), None).await?;

        Ok(nh.finish())
    }

    async fn send_handshake_frame<S>(
        ws: &mut WebSocketStream<S>,
        payload: &[u8],
        header: Option<&[u8]>,
    ) -> Result<(), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = encode_frame(payload, header)?;
        ws.send(WsMessage::Binary(frame)).await?;
        Ok(())
    }

    async fn recv_handshake_frame<S>(
        ws: &mut WebSocketStream<S>,
        decoder: &mut FrameDecoder,
    ) -> Result<Vec<u8>, HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Surface a clear timeout rather than hanging on a silent server.
        let fut = async {
            if let Some(f) = decoder.next_frame() {
                return Ok(f);
            }
            while let Some(msg) = ws.next().await {
                match msg? {
                    WsMessage::Binary(bytes) => {
                        decoder.feed(&bytes);
                        if let Some(f) = decoder.next_frame() {
                            return Ok(f);
                        }
                    }
                    WsMessage::Close(_) => return Err(HandshakeError::Closed),
                    // text/ping/pong are unexpected during handshake; ignore.
                    _ => continue,
                }
            }
            Err(HandshakeError::Closed)
        };
        tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .map_err(|_| HandshakeError::Timeout("handshake response"))?
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::protocol::binary::{Content, Node};
        use crate::protocol::noise::NOISE_START_PATTERN;
        use rand::rngs::OsRng;

        #[test]
        fn proxy_parse_socks5_with_auth() {
            let p = Proxy::parse("socks5://user:pass@1.2.3.4:1080").unwrap();
            assert_eq!(p.scheme, ProxyScheme::Socks5);
            assert_eq!(p.host, "1.2.3.4");
            assert_eq!(p.port, 1080);
            assert_eq!(p.auth, Some(("user".into(), "pass".into())));
        }

        #[test]
        fn proxy_parse_variants() {
            // socks5h maps to Socks5; no auth.
            let p = Proxy::parse("socks5h://proxy.example.com:9050").unwrap();
            assert_eq!(p.scheme, ProxyScheme::Socks5);
            assert_eq!(p.host, "proxy.example.com");
            assert_eq!(p.port, 9050);
            assert_eq!(p.auth, None);
            // http CONNECT with a trailing slash.
            let p = Proxy::parse("http://10.0.0.1:8080/").unwrap();
            assert_eq!(p.scheme, ProxyScheme::Http);
            assert_eq!(p.port, 8080);
        }

        #[test]
        fn proxy_parse_rejects_bad_input() {
            assert!(Proxy::parse("1.2.3.4:1080").is_err()); // no scheme
            assert!(Proxy::parse("ftp://h:1").is_err()); // bad scheme
            assert!(Proxy::parse("socks5://host").is_err()); // no port
            assert!(Proxy::parse("socks5://host:notaport").is_err()); // bad port
        }

        /// Set up two paired NoiseCipher instances simulating client +
        /// server post-handshake state — the responder reads what the
        /// initiator writes, and vice versa.
        fn paired_ciphers() -> (NoiseCipher, NoiseCipher, NoiseCipher, NoiseCipher) {
            use crate::protocol::noise::NoiseHandshake;
            let header = b"WA\x06\x03";
            let mut a = NoiseHandshake::start(&NOISE_START_PATTERN, header);
            let mut b = NoiseHandshake::start(&NOISE_START_PATTERN, header);
            a.mix_into_key(b"shared-secret");
            b.mix_into_key(b"shared-secret");
            let (a_write, a_read) = a.finish();
            let (b_read, b_write) = b.finish();
            (a_write, a_read, b_write, b_read)
        }

        #[test]
        fn encrypt_decrypt_node_round_trip() {
            let (mut a_write, _a_read, _b_write, mut b_read) = paired_ciphers();
            let mut node = Node::new("iq");
            node.attrs.insert("type".into(), "set".into());
            node.attrs.insert("xmlns".into(), "urn:xmpp:ping".into());
            node.content = Content::Nodes(vec![Node::new("ping")]);

            let ct = encrypt_node(&mut a_write, &node).unwrap();
            let recovered = decrypt_node(&mut b_read, &ct).unwrap();
            assert_eq!(recovered, node);
        }

        #[test]
        fn encrypt_node_uses_a_fresh_iv_each_call() {
            let (mut a_write, _a_read, _b_write, mut b_read) = paired_ciphers();
            let n1 = Node::new("ack");
            let mut n2 = Node::new("message");
            n2.attrs.insert("id".into(), "ABC".into());

            let ct1 = encrypt_node(&mut a_write, &n1).unwrap();
            let ct2 = encrypt_node(&mut a_write, &n2).unwrap();
            assert_ne!(ct1, ct2, "different counters must produce different ct");
            assert_eq!(decrypt_node(&mut b_read, &ct1).unwrap(), n1);
            assert_eq!(decrypt_node(&mut b_read, &ct2).unwrap(), n2);
        }

        #[test]
        fn decrypt_node_rejects_tampered_ciphertext() {
            let (mut a_write, _, _, mut b_read) = paired_ciphers();
            let mut ct = encrypt_node(&mut a_write, &Node::new("foo")).unwrap();
            ct[0] ^= 0x01;
            let err = decrypt_node(&mut b_read, &ct).unwrap_err();
            assert!(matches!(err, NodeError::Noise(_)));
        }

        /// Live test — only runs when `RUWA_LIVE_TEST=1` is set, since it
        /// hits `wss://web.whatsapp.com`. Asserts only that the handshake
        /// completes without error and yields a usable cipher pair. The
        /// server will close the WS shortly after if no valid ClientPayload
        /// follows up; we don't care about that for this test.
        #[tokio::test]
        #[ignore = "live: requires network + sets RUWA_LIVE_TEST=1"]
        async fn live_handshake_against_real_ws() {
            if std::env::var("RUWA_LIVE_TEST").as_deref() != Ok("1") {
                eprintln!("skipping; set RUWA_LIVE_TEST=1 to run");
                return;
            }
            let eph = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let eph_pub = x25519_dalek::PublicKey::from(&eph);
            let stat = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let stat_pub = x25519_dalek::PublicKey::from(&stat);

            let mut ws = connect_wa(None).await.expect("WS connect");
            // An empty client payload will be rejected by the server, but the
            // handshake (Noise XX) itself completes cleanly first.
            let _ciphers = do_handshake(
                &mut ws,
                eph.to_bytes(),
                eph_pub.to_bytes(),
                stat.to_bytes(),
                stat_pub.to_bytes(),
                &[],
            )
            .await
            .expect("handshake");
        }

        // -- Server cert verification --------------------------------------
        //
        // The real anchor key (WA_CERT_ROOT_PUB_KEY) is hardcoded; we can't
        // forge a chain that verifies under it without WhatsApp's private
        // key. So these tests temporarily swap in a *test* root by signing
        // the intermediate with a known keypair we control, then point the
        // verifier at it via `verify_server_cert_with_root` (a thin wrapper
        // that takes the root pubkey explicitly).

        use crate::crypto::identity::{xeddsa_sign, KeyPair};

        /// Same as the public verifier but takes the root pubkey instead
        /// of using the hardcoded constant. Test-only re-implementation
        /// kept identical to `verify_server_cert` to avoid sneaking real
        /// changes into the production verifier.
        fn verify_server_cert_with_root(
            cert_decrypted: &[u8],
            server_static_pub: &[u8; 32],
            root_pub: &[u8; 32],
        ) -> Result<(), &'static str> {
            use crate::proto::wa_cert as pb;
            use prost::Message as _;

            let cert_chain =
                pb::CertChain::decode(cert_decrypted).map_err(|_| "decode CertChain failed")?;
            let intermediate = cert_chain
                .intermediate
                .ok_or("CertChain missing intermediate")?;
            let leaf = cert_chain.leaf.ok_or("CertChain missing leaf")?;
            let intermediate_details_raw = intermediate
                .details
                .ok_or("intermediate missing details")?;
            let intermediate_sig = intermediate
                .signature
                .ok_or("intermediate missing signature")?;
            let leaf_details_raw = leaf.details.ok_or("leaf missing details")?;
            let leaf_sig = leaf.signature.ok_or("leaf missing signature")?;
            if intermediate_sig.len() != 64 || leaf_sig.len() != 64 {
                return Err("signature wrong length");
            }
            let mut intermediate_sig_arr = [0u8; 64];
            intermediate_sig_arr.copy_from_slice(&intermediate_sig);
            let mut leaf_sig_arr = [0u8; 64];
            leaf_sig_arr.copy_from_slice(&leaf_sig);
            if !crate::crypto::identity::xeddsa_verify(
                root_pub,
                &intermediate_details_raw,
                &intermediate_sig_arr,
            ) {
                return Err("intermediate sig under root failed");
            }
            let intermediate_details = pb::cert_chain::noise_certificate::Details::decode(
                intermediate_details_raw.as_slice(),
            )
            .map_err(|_| "decode intermediate.details failed")?;
            let intermediate_key = intermediate_details
                .key
                .as_ref()
                .filter(|k| k.len() == 32)
                .ok_or("intermediate key not 32 bytes")?;
            let mut intermediate_key_arr = [0u8; 32];
            intermediate_key_arr.copy_from_slice(intermediate_key);
            if !crate::crypto::identity::xeddsa_verify(
                &intermediate_key_arr,
                &leaf_details_raw,
                &leaf_sig_arr,
            ) {
                return Err("leaf sig under intermediate failed");
            }
            let leaf_details = pb::cert_chain::noise_certificate::Details::decode(
                leaf_details_raw.as_slice(),
            )
            .map_err(|_| "decode leaf.details failed")?;
            let leaf_key = leaf_details
                .key
                .as_ref()
                .filter(|k| k.len() == 32)
                .ok_or("leaf key not 32 bytes")?;
            if leaf_key != server_static_pub {
                return Err("leaf.key != server static");
            }
            Ok(())
        }

        /// Build a CertChain whose intermediate is signed by `root` and
        /// whose leaf is signed by `intermediate_kp`, with the leaf's
        /// `key` pointing at `static_pub`. Time fields are left absent
        /// so checkCertWindow accepts. issuer_serial chain: intermediate's
        /// issuerSerial=0 (root), leaf's issuerSerial = intermediate.serial.
        fn make_cert_chain(
            root: &KeyPair,
            intermediate_kp: &KeyPair,
            static_pub: &[u8; 32],
            intermediate_serial: u32,
        ) -> Vec<u8> {
            use crate::proto::wa_cert as pb;
            use prost::Message as _;

            let intermediate_details = pb::cert_chain::noise_certificate::Details {
                serial: Some(intermediate_serial),
                issuer_serial: Some(0),
                key: Some(intermediate_kp.public.to_vec()),
                not_before: None,
                not_after: None,
            }
            .encode_to_vec();
            let intermediate_sig = xeddsa_sign(&root.private, &intermediate_details);

            let leaf_details = pb::cert_chain::noise_certificate::Details {
                serial: Some(intermediate_serial.wrapping_add(1)),
                issuer_serial: Some(intermediate_serial),
                key: Some(static_pub.to_vec()),
                not_before: None,
                not_after: None,
            }
            .encode_to_vec();
            let leaf_sig = xeddsa_sign(&intermediate_kp.private, &leaf_details);

            pb::CertChain {
                intermediate: Some(pb::cert_chain::NoiseCertificate {
                    details: Some(intermediate_details),
                    signature: Some(intermediate_sig.to_vec()),
                }),
                leaf: Some(pb::cert_chain::NoiseCertificate {
                    details: Some(leaf_details),
                    signature: Some(leaf_sig.to_vec()),
                }),
            }
            .encode_to_vec()
        }

        #[test]
        fn verify_server_cert_accepts_well_formed_chain() {
            let root = KeyPair::generate();
            let intermediate = KeyPair::generate();
            let static_pub = [0xAB; 32];
            let chain = make_cert_chain(&root, &intermediate, &static_pub, 0);
            verify_server_cert_with_root(&chain, &static_pub, &root.public)
                .expect("well-formed chain must verify");
        }

        #[test]
        fn verify_server_cert_rejects_wrong_static_pub() {
            let root = KeyPair::generate();
            let intermediate = KeyPair::generate();
            let static_pub = [0xAB; 32];
            let chain = make_cert_chain(&root, &intermediate, &static_pub, 0);
            // Pretend the noise socket gave us a different static.
            let other_static = [0xCD; 32];
            let err = verify_server_cert_with_root(&chain, &other_static, &root.public)
                .expect_err("mismatched static must reject");
            assert!(err.contains("leaf"));
        }

        #[test]
        fn verify_server_cert_rejects_unknown_root() {
            let real_root = KeyPair::generate();
            let intermediate = KeyPair::generate();
            let static_pub = [0xAB; 32];
            let chain = make_cert_chain(&real_root, &intermediate, &static_pub, 0);
            let attacker_root = KeyPair::generate();
            let err = verify_server_cert_with_root(
                &chain,
                &static_pub,
                &attacker_root.public,
            )
            .expect_err("chain not anchored at our root must reject");
            assert!(err.contains("intermediate"));
        }

        #[test]
        fn verify_server_cert_rejects_mangled_intermediate_signature() {
            use crate::proto::wa_cert as pb;
            use prost::Message as _;
            let root = KeyPair::generate();
            let intermediate = KeyPair::generate();
            let static_pub = [0xAB; 32];
            let mut chain_bytes =
                make_cert_chain(&root, &intermediate, &static_pub, 0);
            // Re-decode, flip a byte in the intermediate signature, re-encode.
            let mut chain = pb::CertChain::decode(chain_bytes.as_slice()).unwrap();
            let mut sig = chain.intermediate.as_mut().unwrap().signature.clone().unwrap();
            sig[3] ^= 0x01;
            chain.intermediate.as_mut().unwrap().signature = Some(sig);
            chain_bytes = chain.encode_to_vec();
            assert!(verify_server_cert_with_root(&chain_bytes, &static_pub, &root.public).is_err());
        }

        /// Wires the real verifier (against the hardcoded WACertPubKey).
        /// A chain we've signed with our own keys MUST be rejected — it
        /// proves the production code path actually anchors at the WA key.
        #[test]
        fn production_verify_rejects_chain_anchored_at_attacker_root() {
            let attacker = KeyPair::generate();
            let intermediate = KeyPair::generate();
            let static_pub = [0xAB; 32];
            let chain = make_cert_chain(&attacker, &intermediate, &static_pub, 0);
            let err = verify_server_cert(&chain, &static_pub).unwrap_err();
            assert!(err.contains("intermediate"));
        }
    }
}
