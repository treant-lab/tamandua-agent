//! Message Codec for Protocol Encoding/Decoding
//!
//! This module handles serialization and deserialization of protocol messages.
//! It supports multiple formats and optional compression.
//!
//! # Wire Format
//!
//! Messages are encoded as length-prefixed frames:
//!
//! ```text
//! +--------+--------+------------------+
//! | Length | Format |     Payload      |
//! | 4 bytes| 1 byte |   N bytes        |
//! +--------+--------+------------------+
//! ```
//!
//! - **Length**: u32 (big-endian) - total frame size excluding length field
//! - **Format**: u8 - encoding format (0=JSON, 1=MessagePack, 2=Protobuf)
//! - **Payload**: encoded message data
//!
//! # Compression
//!
//! When compression is enabled, the format byte has the high bit set:
//!
//! - Bit 7: Compression flag (1=compressed, 0=uncompressed)
//! - Bits 0-6: Format ID
//!
//! Supported compression: zstd (level 3)

use crate::collectors::TelemetryEvent;
use crate::config::AgentConfig;
use crate::transport::sans_io::{MlScanResult, ProtocolStats, RulesUpdate};
use crate::transport::Command;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{trace, warn};

/// Maximum frame size (10 MB)
const MAX_FRAME_SIZE: u32 = 10 * 1024 * 1024;

/// Frame header size (length + format)
const FRAME_HEADER_SIZE: usize = 5;

/// Compression flag in format byte
const COMPRESSION_FLAG: u8 = 0x80;

/// Format mask
const FORMAT_MASK: u8 = 0x7F;

/// Message encoding format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingFormat {
    /// JSON encoding
    Json = 0,

    /// MessagePack encoding
    MessagePack = 1,

    /// Protocol Buffers
    Protobuf = 2,
}

impl TryFrom<u8> for EncodingFormat {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value & FORMAT_MASK {
            0 => Ok(EncodingFormat::Json),
            1 => Ok(EncodingFormat::MessagePack),
            2 => Ok(EncodingFormat::Protobuf),
            _ => Err(CodecError::UnsupportedFormat(value)),
        }
    }
}

/// Protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProtocolMessage {
    /// Telemetry batch
    TelemetryBatch {
        sequence: u64,
        events: Vec<TelemetryEvent>,
        timestamp: u64,
    },

    /// Telemetry acknowledgment
    TelemetryAck { sequence: u64, count: usize },

    /// Command from server
    Command(Command),

    /// Command response
    CommandResponse {
        command_id: String,
        success: bool,
        error_message: Option<String>,
        result_data: Option<serde_json::Value>,
        executed_at: u64,
    },

    /// Configuration update
    ConfigUpdate(AgentConfig),

    /// Rules update
    RulesUpdate(RulesUpdate),

    /// Heartbeat
    Heartbeat {
        timestamp: u64,
        stats: ProtocolStats,
    },

    /// Heartbeat acknowledgment
    HeartbeatAck,

    /// ML scan result
    MlScanResult(MlScanResult),

    /// Error message
    Error { message: String },

    /// Phoenix channel join
    PhoenixJoin {
        topic: String,
        payload: serde_json::Value,
    },

    /// Phoenix channel reply
    PhoenixReply {
        status: String,
        response: serde_json::Value,
    },
}

/// Message codec error
#[derive(Debug, Clone, thiserror::Error)]
pub enum CodecError {
    #[error("Unsupported encoding format: {0}")]
    UnsupportedFormat(u8),

    #[error("Frame too large: {size} bytes (max {MAX_FRAME_SIZE})")]
    FrameTooLarge { size: u32 },

    #[error("Incomplete frame: need {needed} bytes, have {available}")]
    IncompleteFrame { needed: usize, available: usize },

    #[error("JSON encoding error: {0}")]
    JsonError(String),

    #[error("MessagePack encoding error: {0}")]
    MessagePackError(String),

    #[error("Protobuf encoding error: {0}")]
    ProtobufError(String),

    #[error("Compression error: {0}")]
    CompressionError(String),

    #[error("Decompression error: {0}")]
    DecompressionError(String),

    #[error("Invalid message type: {0}")]
    InvalidMessageType(String),
}

/// Message codec
#[derive(Clone)]
pub struct MessageCodec {
    /// Encoding format
    format: EncodingFormat,

    /// Enable compression
    compression: bool,

    /// Compression level (1-21 for zstd)
    compression_level: i32,
}

impl MessageCodec {
    /// Create a new codec with default settings
    pub fn new() -> Self {
        Self {
            format: EncodingFormat::Json,
            compression: false,
            compression_level: 3,
        }
    }

    /// Create a codec with specific format
    pub fn with_format(format: EncodingFormat) -> Self {
        Self {
            format,
            compression: false,
            compression_level: 3,
        }
    }

    /// Enable compression
    pub fn with_compression(mut self, level: i32) -> Self {
        self.compression = true;
        self.compression_level = level;
        self
    }

    /// Encode a message
    pub fn encode(&self, message: &ProtocolMessage) -> Result<Vec<u8>, CodecError> {
        // Serialize message
        let payload = self.encode_payload(message)?;

        // Compress if enabled
        let (payload, compressed) = if self.compression {
            match self.compress(&payload) {
                Ok(compressed) => (compressed, true),
                Err(e) => {
                    warn!("Compression failed: {}, sending uncompressed", e);
                    (payload, false)
                }
            }
        } else {
            (payload, false)
        };

        // Build frame
        let frame_size = payload.len() + 1; // +1 for format byte

        if frame_size > MAX_FRAME_SIZE as usize {
            return Err(CodecError::FrameTooLarge {
                size: frame_size as u32,
            });
        }

        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());

        // Write length (big-endian u32)
        frame.extend_from_slice(&(frame_size as u32).to_be_bytes());

        // Write format byte
        let format_byte = if compressed {
            (self.format as u8) | COMPRESSION_FLAG
        } else {
            self.format as u8
        };
        frame.push(format_byte);

        // Write payload
        frame.extend_from_slice(&payload);

        trace!(
            size = frame.len(),
            compressed = compressed,
            format = ?self.format,
            "Encoded message"
        );

        Ok(frame)
    }

    /// Decode a message from a buffer
    ///
    /// Returns (message, consumed_bytes) on success, or None if more data needed
    pub fn decode(&self, buffer: &[u8]) -> Result<Option<(ProtocolMessage, usize)>, CodecError> {
        // Need at least frame header
        if buffer.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        // Read length
        let length_bytes: [u8; 4] = buffer[0..4].try_into().unwrap();
        let frame_size = u32::from_be_bytes(length_bytes);

        // Check frame size
        if frame_size > MAX_FRAME_SIZE {
            return Err(CodecError::FrameTooLarge { size: frame_size });
        }

        // A valid frame includes at least the format byte (counted in frame_size).
        // A zero frame_size would underflow total_size below the header and cause
        // the payload slice `&buffer[5..total_size]` to panic with start > end.
        if frame_size == 0 {
            return Err(CodecError::InvalidMessageType(
                "frame size cannot be zero".to_string(),
            ));
        }

        let total_size = FRAME_HEADER_SIZE + frame_size as usize - 1; // -1 because format byte is in frame_size

        // Check if we have the complete frame
        if buffer.len() < total_size {
            return Ok(None);
        }

        // Read format byte
        let format_byte = buffer[4];
        let compressed = (format_byte & COMPRESSION_FLAG) != 0;
        let format = EncodingFormat::try_from(format_byte)?;

        // Extract payload
        let payload = &buffer[5..total_size];

        // Decompress if needed
        let payload = if compressed {
            self.decompress(payload)?
        } else {
            payload.to_vec()
        };

        // Decode message
        let message = self.decode_payload(&payload, format)?;

        trace!(
            consumed = total_size,
            compressed = compressed,
            format = ?format,
            "Decoded message"
        );

        Ok(Some((message, total_size)))
    }

    // Private methods

    fn encode_payload(&self, message: &ProtocolMessage) -> Result<Vec<u8>, CodecError> {
        match self.format {
            EncodingFormat::Json => {
                serde_json::to_vec(message).map_err(|e| CodecError::JsonError(e.to_string()))
            }

            EncodingFormat::MessagePack => {
                rmp_serde::to_vec(message).map_err(|e| CodecError::MessagePackError(e.to_string()))
            }

            EncodingFormat::Protobuf => {
                // Not implemented yet
                Err(CodecError::ProtobufError("Not implemented".to_string()))
            }
        }
    }

    fn decode_payload(
        &self,
        payload: &[u8],
        format: EncodingFormat,
    ) -> Result<ProtocolMessage, CodecError> {
        match format {
            EncodingFormat::Json => {
                serde_json::from_slice(payload).map_err(|e| CodecError::JsonError(e.to_string()))
            }

            EncodingFormat::MessagePack => rmp_serde::from_slice(payload)
                .map_err(|e| CodecError::MessagePackError(e.to_string())),

            EncodingFormat::Protobuf => {
                Err(CodecError::ProtobufError("Not implemented".to_string()))
            }
        }
    }

    #[cfg(feature = "compression")]
    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, CodecError> {
        zstd::encode_all(data, self.compression_level)
            .map_err(|e| CodecError::CompressionError(e.to_string()))
    }

    #[cfg(not(feature = "compression"))]
    fn compress(&self, _data: &[u8]) -> Result<Vec<u8>, CodecError> {
        Err(CodecError::CompressionError(
            "Compression not enabled".to_string(),
        ))
    }

    #[cfg(feature = "compression")]
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, CodecError> {
        zstd::decode_all(data).map_err(|e| CodecError::DecompressionError(e.to_string()))
    }

    #[cfg(not(feature = "compression"))]
    fn decompress(&self, _data: &[u8]) -> Result<Vec<u8>, CodecError> {
        Err(CodecError::DecompressionError(
            "Compression not enabled".to_string(),
        ))
    }
}

pub fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl Default for MessageCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame builder for constructing messages incrementally
pub struct FrameBuilder {
    buffer: Vec<u8>,
    codec: MessageCodec,
}

impl FrameBuilder {
    /// Create a new frame builder
    pub fn new(codec: MessageCodec) -> Self {
        Self {
            buffer: Vec::new(),
            codec,
        }
    }

    /// Add data to the buffer
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to extract a complete frame
    pub fn try_extract(&mut self) -> Result<Option<ProtocolMessage>, CodecError> {
        match self.codec.decode(&self.buffer)? {
            Some((message, consumed)) => {
                // Remove consumed bytes
                self.buffer.drain(..consumed);
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    /// Get buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// MessagePack encoding support
mod messagepack {
    // Placeholder for MessagePack codec implementation
    // Would use rmp-serde crate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_json() {
        let codec = MessageCodec::new();

        let message = ProtocolMessage::Error {
            message: "test error".to_string(),
        };

        let encoded = codec.encode(&message).unwrap();
        let (decoded, consumed) = codec.decode(&encoded).unwrap().unwrap();

        assert_eq!(consumed, encoded.len());

        if let ProtocolMessage::Error { message } = decoded {
            assert_eq!(message, "test error");
        } else {
            panic!("Wrong message type");
        }
    }

    #[test]
    fn test_incomplete_frame() {
        let codec = MessageCodec::new();

        let message = ProtocolMessage::Error {
            message: "test".to_string(),
        };

        let mut encoded = codec.encode(&message).unwrap();

        // Truncate frame
        encoded.truncate(encoded.len() - 5);

        let result = codec.decode(&encoded).unwrap();
        assert!(result.is_none()); // Should need more data
    }

    #[test]
    fn test_frame_too_large() {
        let codec = MessageCodec::new();

        // Create a huge payload
        let huge_payload = vec![0u8; (MAX_FRAME_SIZE + 1) as usize];

        // Manually construct frame header with oversized length
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(MAX_FRAME_SIZE + 1).to_be_bytes());
        buffer.push(0); // Format byte

        let result = codec.decode(&buffer);
        assert!(matches!(result, Err(CodecError::FrameTooLarge { .. })));
    }

    #[test]
    fn test_frame_builder() {
        let codec = MessageCodec::new();
        let mut builder = FrameBuilder::new(codec.clone());

        let message = ProtocolMessage::HeartbeatAck;

        let encoded = codec.encode(&message).unwrap();

        // Feed in chunks
        for chunk in encoded.chunks(10) {
            builder.push(chunk);
        }

        let decoded = builder.try_extract().unwrap();
        assert!(decoded.is_some());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_compression() {
        let codec = MessageCodec::new().with_compression(3);

        let message = ProtocolMessage::Error {
            message: "test error ".repeat(100),
        };

        let encoded = codec.encode(&message).unwrap();

        // Compressed should have compression flag set
        let format_byte = encoded[4];
        assert!(format_byte & COMPRESSION_FLAG != 0);

        let (decoded, _) = codec.decode(&encoded).unwrap().unwrap();

        if let ProtocolMessage::Error { message } = decoded {
            assert!(message.starts_with("test error"));
        } else {
            panic!("Wrong message type");
        }
    }
}
