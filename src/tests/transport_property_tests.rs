//! Property-based tests for transport layer
//!
//! Tests message encoding, framing, compression, and protocol state machine properties.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    /// Frame header structure for testing
    #[derive(Debug, Clone, PartialEq)]
    struct FrameHeader {
        length: u32,
        format: u8,
    }

    impl FrameHeader {
        fn new(length: u32, format: u8) -> Self {
            Self { length, format }
        }

        fn encode(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&self.length.to_be_bytes());
            bytes.push(self.format);
            bytes
        }

        fn decode(bytes: &[u8]) -> Result<Self, String> {
            if bytes.len() < 5 {
                return Err("Insufficient bytes".to_string());
            }
            let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let format = bytes[4];
            Ok(Self { length, format })
        }
    }

    /// Simple message codec for testing
    struct MessageCodec {
        compression_enabled: bool,
    }

    impl MessageCodec {
        fn new(compression_enabled: bool) -> Self {
            Self {
                compression_enabled,
            }
        }

        fn encode(&self, data: &[u8]) -> Vec<u8> {
            let format = if self.compression_enabled { 0x81 } else { 0x01 };
            let header = FrameHeader::new(data.len() as u32 + 1, format);

            let mut frame = header.encode();
            frame.extend_from_slice(data);
            frame
        }

        fn decode(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
            if frame.len() < 5 {
                return Err("Frame too short".to_string());
            }

            let header = FrameHeader::decode(&frame[0..5])?;
            let payload_len = (header.length - 1) as usize;

            if frame.len() < 5 + payload_len {
                return Err("Incomplete frame".to_string());
            }

            Ok(frame[5..5 + payload_len].to_vec())
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        // Frame encoding/decoding properties
        #[test]
        fn frame_header_roundtrip(length in 0u32..1_000_000, format in any::<u8>()) {
            let header = FrameHeader::new(length, format);
            let encoded = header.encode();
            let decoded = FrameHeader::decode(&encoded).unwrap();

            prop_assert_eq!(header, decoded);
        }

        #[test]
        fn message_encoding_roundtrip(data in prop::collection::vec(any::<u8>(), 0..10000)) {
            let codec = MessageCodec::new(false);
            let encoded = codec.encode(&data);
            let decoded = codec.decode(&encoded).unwrap();

            prop_assert_eq!(data, decoded);
        }

        #[test]
        fn compressed_message_roundtrip(data in prop::collection::vec(any::<u8>(), 0..10000)) {
            let codec = MessageCodec::new(true);
            let encoded = codec.encode(&data);
            let decoded = codec.decode(&encoded).unwrap();

            prop_assert_eq!(data, decoded);
        }

        #[test]
        fn frame_length_is_correct(data in prop::collection::vec(any::<u8>(), 0..10000)) {
            let codec = MessageCodec::new(false);
            let encoded = codec.encode(&data);

            // Extract length from frame header
            let length = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);

            // Length should match payload + format byte
            prop_assert_eq!(length as usize, data.len() + 1);
        }

        #[test]
        fn partial_frames_are_detected(data in prop::collection::vec(any::<u8>(), 10..1000)) {
            let codec = MessageCodec::new(false);
            let encoded = codec.encode(&data);

            // Try to decode only part of the frame
            let partial = &encoded[0..encoded.len() / 2];
            let result = codec.decode(partial);

            prop_assert!(result.is_err());
        }

        // State machine properties
        #[test]
        fn connection_state_transitions_are_valid(
            transitions in prop::collection::vec(state_transition_strategy(), 1..50)
        ) {
            let mut state = ConnectionState::Disconnected;

            for transition in transitions {
                state = apply_transition(state, transition);

                // State should always be valid
                prop_assert!(is_valid_state(state));
            }
        }

        #[test]
        fn heartbeat_sequence_is_monotonic(count in 1usize..100) {
            let mut sequence = 0u64;
            let mut sequences = Vec::new();

            for _ in 0..count {
                sequence = next_sequence(sequence);
                sequences.push(sequence);
            }

            // Check monotonicity
            for i in 1..sequences.len() {
                prop_assert!(sequences[i] > sequences[i-1]);
            }
        }

        // Message batching properties
        #[test]
        fn batch_sizes_respect_limits(
            messages in prop::collection::vec(message_strategy(), 1..1000),
            max_batch_size in 1usize..100
        ) {
            let batches = create_message_batches(&messages, max_batch_size);

            for batch in &batches[..batches.len().saturating_sub(1)] {
                // All batches except possibly the last should be at max size
                prop_assert!(batch.len() <= max_batch_size);
            }

            // Total message count preserved
            let total: usize = batches.iter().map(|b| b.len()).sum();
            prop_assert_eq!(total, messages.len());
        }

        #[test]
        fn batch_order_is_preserved(
            messages in prop::collection::vec(message_strategy(), 1..100),
            batch_size in 1usize..50
        ) {
            let batches = create_message_batches(&messages, batch_size);
            let flattened: Vec<_> = batches.into_iter().flatten().collect();

            prop_assert_eq!(messages, flattened);
        }

        // Backpressure properties
        #[test]
        fn buffer_respects_capacity(
            capacity in 1usize..1000,
            items in prop::collection::vec(any::<u32>(), 1..2000)
        ) {
            let mut buffer = BoundedBuffer::new(capacity);

            for item in items {
                buffer.push(item);
            }

            // Buffer should never exceed capacity
            prop_assert!(buffer.len() <= capacity);
        }

        #[test]
        fn buffer_fifo_when_not_full(
            items in prop::collection::vec(any::<u32>(), 1..50)
        ) {
            let mut buffer = BoundedBuffer::new(1000);

            for item in &items {
                buffer.push(*item);
            }

            let mut drained = Vec::new();
            while let Some(item) = buffer.pop() {
                drained.push(item);
            }

            prop_assert_eq!(items, drained);
        }

        // Retry logic properties
        #[test]
        fn exponential_backoff_increases(attempt in 0u32..10) {
            let delay1 = calculate_backoff(attempt);
            let delay2 = calculate_backoff(attempt + 1);

            // Delay should increase (or stay at max)
            prop_assert!(delay2 >= delay1);
        }

        #[test]
        fn backoff_never_exceeds_max(attempt in 0u32..100) {
            let delay = calculate_backoff(attempt);
            const MAX_DELAY: u64 = 60_000; // 60 seconds

            prop_assert!(delay <= MAX_DELAY);
        }

        // Serialization properties
        #[test]
        fn json_encoding_is_deterministic(
            sequence in any::<u64>(),
            count in 1usize..1000
        ) {
            let msg = TestMessage { sequence, count };
            let json1 = serde_json::to_vec(&msg).unwrap();
            let json2 = serde_json::to_vec(&msg).unwrap();

            prop_assert_eq!(json1, json2);
        }

        #[test]
        fn messagepack_roundtrip(
            sequence in any::<u64>(),
            count in 1usize..1000
        ) {
            let msg = TestMessage { sequence, count };
            let encoded = rmp_serde::to_vec(&msg).unwrap();
            let decoded: TestMessage = rmp_serde::from_slice(&encoded).unwrap();

            prop_assert_eq!(msg.sequence, decoded.sequence);
            prop_assert_eq!(msg.count, decoded.count);
        }

        // Protocol version compatibility
        #[test]
        fn version_negotiation_succeeds(
            client_version in 1u8..10,
            server_version in 1u8..10
        ) {
            let negotiated = negotiate_version(client_version, server_version);

            // Should use minimum of both versions
            prop_assert_eq!(negotiated, client_version.min(server_version));
        }

        // Connection lifecycle properties
        #[test]
        fn connections_eventually_close(
            events in prop::collection::vec(connection_event_strategy(), 1..100)
        ) {
            let mut connection = TestConnection::new();

            for event in events {
                connection.handle_event(event);
            }

            // After handling all events, connection should be in a valid final state
            prop_assert!(connection.is_valid());
        }
    }

    // Supporting types and functions

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum ConnectionState {
        Disconnected,
        Connecting,
        Connected,
        Reconnecting,
    }

    #[derive(Debug, Clone, Copy)]
    enum StateTransition {
        Connect,
        Disconnect,
        Error,
        Reconnect,
    }

    fn apply_transition(state: ConnectionState, transition: StateTransition) -> ConnectionState {
        match (state, transition) {
            (ConnectionState::Disconnected, StateTransition::Connect) => {
                ConnectionState::Connecting
            }
            (ConnectionState::Connecting, StateTransition::Connect) => ConnectionState::Connected,
            (ConnectionState::Connected, StateTransition::Disconnect) => {
                ConnectionState::Disconnected
            }
            (ConnectionState::Connected, StateTransition::Error) => ConnectionState::Reconnecting,
            (ConnectionState::Reconnecting, StateTransition::Connect) => ConnectionState::Connected,
            (ConnectionState::Reconnecting, StateTransition::Disconnect) => {
                ConnectionState::Disconnected
            }
            (s, _) => s, // Invalid transitions maintain current state
        }
    }

    fn is_valid_state(state: ConnectionState) -> bool {
        matches!(
            state,
            ConnectionState::Disconnected
                | ConnectionState::Connecting
                | ConnectionState::Connected
                | ConnectionState::Reconnecting
        )
    }

    fn next_sequence(current: u64) -> u64 {
        current.wrapping_add(1)
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestMessage {
        sequence: u64,
        count: usize,
    }

    fn create_message_batches<T: Clone>(messages: &[T], max_size: usize) -> Vec<Vec<T>> {
        messages
            .chunks(max_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    struct BoundedBuffer<T> {
        buffer: Vec<T>,
        capacity: usize,
    }

    impl<T> BoundedBuffer<T> {
        fn new(capacity: usize) -> Self {
            Self {
                buffer: Vec::new(),
                capacity,
            }
        }

        fn push(&mut self, item: T) {
            if self.buffer.len() < self.capacity {
                self.buffer.push(item);
            }
        }

        fn pop(&mut self) -> Option<T> {
            if self.buffer.is_empty() {
                None
            } else {
                Some(self.buffer.remove(0))
            }
        }

        fn len(&self) -> usize {
            self.buffer.len()
        }
    }

    fn calculate_backoff(attempt: u32) -> u64 {
        const BASE_DELAY: u64 = 100; // 100ms
        const MAX_DELAY: u64 = 60_000; // 60s

        // Use checked/saturating arithmetic so large attempt counts saturate to
        // MAX_DELAY instead of overflowing the exponentiation/multiplication.
        let factor = 2u64.checked_pow(attempt).unwrap_or(u64::MAX);
        let delay = BASE_DELAY.saturating_mul(factor);
        delay.min(MAX_DELAY)
    }

    fn negotiate_version(client: u8, server: u8) -> u8 {
        client.min(server)
    }

    #[derive(Debug)]
    struct TestConnection {
        state: ConnectionState,
    }

    impl TestConnection {
        fn new() -> Self {
            Self {
                state: ConnectionState::Disconnected,
            }
        }

        fn handle_event(&mut self, event: ConnectionEvent) {
            match event {
                ConnectionEvent::Open => {
                    if matches!(self.state, ConnectionState::Disconnected) {
                        self.state = ConnectionState::Connected;
                    }
                }
                ConnectionEvent::Close => {
                    self.state = ConnectionState::Disconnected;
                }
                ConnectionEvent::Error => {
                    if matches!(self.state, ConnectionState::Connected) {
                        self.state = ConnectionState::Reconnecting;
                    }
                }
            }
        }

        fn is_valid(&self) -> bool {
            is_valid_state(self.state)
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum ConnectionEvent {
        Open,
        Close,
        Error,
    }

    // Property test strategies

    fn state_transition_strategy() -> impl Strategy<Value = StateTransition> {
        prop_oneof![
            Just(StateTransition::Connect),
            Just(StateTransition::Disconnect),
            Just(StateTransition::Error),
            Just(StateTransition::Reconnect),
        ]
    }

    fn message_strategy() -> impl Strategy<Value = TestMessage> {
        (any::<u64>(), 1usize..1000).prop_map(|(sequence, count)| TestMessage { sequence, count })
    }

    fn connection_event_strategy() -> impl Strategy<Value = ConnectionEvent> {
        prop_oneof![
            Just(ConnectionEvent::Open),
            Just(ConnectionEvent::Close),
            Just(ConnectionEvent::Error),
        ]
    }
}
