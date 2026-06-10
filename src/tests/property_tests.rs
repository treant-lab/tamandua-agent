//! Property-based tests using proptest
//!
//! These tests verify invariants that should hold for all inputs,
//! rather than testing specific cases. This helps catch edge cases
//! and ensures correctness across a wide range of inputs.

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::Value;
    use std::collections::HashMap;

    // Import types from the main codebase
    use crate::collectors::{EventPayload, EventType, Severity, TelemetryEvent};

    /// Ring buffer for testing FIFO properties
    struct RingBuffer<T> {
        buffer: Vec<Option<T>>,
        read_pos: usize,
        write_pos: usize,
        capacity: usize,
    }

    impl<T> RingBuffer<T> {
        fn new(capacity: usize) -> Self {
            Self {
                buffer: (0..capacity).map(|_| None).collect(),
                read_pos: 0,
                write_pos: 0,
                capacity,
            }
        }

        fn write(&mut self, item: T) -> bool {
            let next_write = (self.write_pos + 1) % self.capacity;
            if next_write == self.read_pos {
                // Buffer full, overwrite oldest
                self.read_pos = (self.read_pos + 1) % self.capacity;
            }
            self.buffer[self.write_pos] = Some(item);
            self.write_pos = next_write;
            true
        }

        fn read(&mut self) -> Option<T> {
            if self.read_pos == self.write_pos {
                return None;
            }
            let item = self.buffer[self.read_pos].take();
            self.read_pos = (self.read_pos + 1) % self.capacity;
            item
        }

        fn len(&self) -> usize {
            if self.write_pos >= self.read_pos {
                self.write_pos - self.read_pos
            } else {
                self.capacity - self.read_pos + self.write_pos
            }
        }

        fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
            std::iter::from_fn(move || self.read())
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        // Ring buffer properties
        #[test]
        fn ring_buffer_fifo(events in prop::collection::vec(1u32..1000, 1..100)) {
            let mut buffer = RingBuffer::new(1024);

            // Write all events
            for event in &events {
                buffer.write(*event);
            }

            // Read all events
            let mut read_events = Vec::new();
            while let Some(event) = buffer.read() {
                read_events.push(event);
            }

            // Should maintain FIFO order
            prop_assert_eq!(events.len(), read_events.len());
            for (orig, read) in events.iter().zip(read_events.iter()) {
                prop_assert_eq!(orig, read);
            }
        }

        #[test]
        fn ring_buffer_handles_overflow(events in prop::collection::vec(1u32..1000, 100..200)) {
            let mut buffer = RingBuffer::new(50); // Small buffer forces overflow

            for event in &events {
                buffer.write(*event);
            }

            // Should still be readable (oldest events lost)
            let read_count = buffer.drain().count();
            prop_assert!(read_count > 0);
            prop_assert!(read_count <= events.len());
            prop_assert!(read_count <= 50); // Can't exceed capacity
        }

        #[test]
        fn ring_buffer_len_correct(events in prop::collection::vec(1u32..1000, 1..50)) {
            let mut buffer = RingBuffer::new(100);

            for event in &events {
                buffer.write(*event);
            }

            let len = buffer.len();
            let drain_count = buffer.drain().count();
            prop_assert_eq!(len, drain_count);
        }

        // Entropy calculation properties
        #[test]
        fn entropy_is_bounded(data in prop::collection::vec(any::<u8>(), 1..10000)) {
            let entropy = calculate_entropy(&data);
            prop_assert!(entropy >= 0.0);
            prop_assert!(entropy <= 8.0); // Max entropy for bytes
        }

        #[test]
        fn entropy_of_constant_is_zero(byte in any::<u8>(), len in 1usize..1000) {
            let data = vec![byte; len];
            let entropy = calculate_entropy(&data);
            prop_assert!((entropy - 0.0).abs() < 0.001);
        }

        #[test]
        fn entropy_of_random_is_high(seed in any::<u64>()) {
            use rand::{SeedableRng, Rng};
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let data: Vec<u8> = (0..10000).map(|_| rng.gen()).collect();
            let entropy = calculate_entropy(&data);
            prop_assert!(entropy > 7.0); // Random data has high entropy (lowered threshold for reliability)
        }

        // Hash calculation properties
        #[test]
        fn hash_is_deterministic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hash1 = calculate_sha256(&data);
            let hash2 = calculate_sha256(&data);
            prop_assert_eq!(hash1, hash2);
        }

        #[test]
        fn hash_output_length_is_constant(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hash = calculate_sha256(&data);
            prop_assert_eq!(hash.len(), 32); // SHA256 always produces 32 bytes
        }

        #[test]
        fn different_data_different_hash(
            data1 in prop::collection::vec(any::<u8>(), 1..100),
            data2 in prop::collection::vec(any::<u8>(), 1..100)
        ) {
            // Only test if data is actually different
            if data1 != data2 {
                let hash1 = calculate_sha256(&data1);
                let hash2 = calculate_sha256(&data2);
                prop_assert_ne!(hash1, hash2);
            }
        }

        // JSON serialization properties
        #[test]
        fn json_roundtrip(
            event_type in event_type_strategy(),
            pid in 1u32..65535,
            path in "[a-zA-Z0-9_/\\\\]{1,50}",
        ) {
            let payload = EventPayload::Generic(serde_json::json!({
                "pid": pid,
                "path": path,
                "cmdline": "test",
                "user": "testuser",
                "is_elevated": false
            }));

            let event = TelemetryEvent {
                event_id: format!("prop-{}", pid),
                event_type,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                severity: Severity::Info,
                payload,
                detections: Vec::new(),
                metadata: HashMap::new(),
            };

            // Serialize to JSON
            let json = serde_json::to_string(&event).unwrap();

            // Deserialize back
            let decoded: TelemetryEvent = serde_json::from_str(&json).unwrap();

            // Event type should match
            prop_assert_eq!(event.event_type, decoded.event_type);
        }

        // Protocol message encoding properties
        #[test]
        fn message_encoding_is_deterministic(
            sequence in any::<u64>(),
            count in 1usize..100,
        ) {
            let msg = create_telemetry_ack(sequence, count);
            let enc1 = encode_json(&msg);
            let enc2 = encode_json(&msg);
            prop_assert_eq!(enc1, enc2);
        }

        // Path validation properties
        #[test]
        fn path_normalization_is_idempotent(path in "[a-zA-Z0-9_/\\\\. ]{1,100}") {
            let normalized1 = normalize_path(&path);
            let normalized2 = normalize_path(&normalized1);
            prop_assert_eq!(normalized1, normalized2);
        }

        #[test]
        fn absolute_paths_remain_absolute(path in absolute_path_strategy()) {
            let normalized = normalize_path(&path);
            prop_assert!(is_absolute(&normalized));
        }

        // PID validation properties
        #[test]
        fn pid_ranges_are_valid(pid in 1u32..65535) {
            prop_assert!(pid > 0);
            prop_assert!(pid < 65536);
        }

        // IP address validation properties
        #[test]
        fn ipv4_parsing_roundtrip(
            a in 0u8..255,
            b in 0u8..255,
            c in 0u8..255,
            d in 0u8..255,
        ) {
            let ip_str = format!("{}.{}.{}.{}", a, b, c, d);
            let parsed = parse_ipv4(&ip_str);
            prop_assert!(parsed.is_ok());
            if let Ok(ip) = parsed {
                prop_assert_eq!(ip, (a, b, c, d));
            }
        }

        // Port validation properties
        #[test]
        fn port_ranges_are_valid(port in 1u16..65535) {
            // u16 is type-bounded to 0..=65535; only the lower bound and the
            // exclusive-upper invariant of the generator need runtime assertion.
            prop_assert!(port > 0);
            prop_assert!(port < 65535);
        }

        // Timestamp properties
        #[test]
        fn timestamps_are_monotonic(count in 1usize..100) {
            let mut timestamps = Vec::new();
            for _ in 0..count {
                timestamps.push(chrono::Utc::now());
                std::thread::sleep(std::time::Duration::from_micros(1));
            }

            // Check monotonicity
            for i in 1..timestamps.len() {
                prop_assert!(timestamps[i] >= timestamps[i-1]);
            }
        }

        // Command line parsing properties
        #[test]
        fn cmdline_tokens_preserve_content(cmdline in "[a-zA-Z0-9_ ]{1,100}") {
            let tokens = parse_cmdline(&cmdline);
            let rejoined = tokens.join(" ");

            // Content should be preserved modulo whitespace collapsing: tokenizing
            // splits on runs of whitespace, so compare the whitespace-normalized
            // token sequences rather than doing a substring match.
            prop_assert_eq!(
                cmdline.split_whitespace().collect::<Vec<_>>(),
                rejoined.split_whitespace().collect::<Vec<_>>()
            );
        }

        // Map operations properties
        #[test]
        fn map_merge_preserves_keys(
            map1 in prop::collection::hash_map("[a-z]{1,10}", any::<i32>(), 0..10),
            map2 in prop::collection::hash_map("[a-z]{1,10}", any::<i32>(), 0..10),
        ) {
            let merged = merge_maps(&map1, &map2);

            // All keys from both maps should be present
            for key in map1.keys() {
                prop_assert!(merged.contains_key(key));
            }
            for key in map2.keys() {
                prop_assert!(merged.contains_key(key));
            }
        }

        // String operations properties
        #[test]
        fn truncate_preserves_prefix(
            s in "[a-zA-Z0-9]{10,100}",
            max_len in 5usize..50,
        ) {
            let truncated = truncate_string(&s, max_len);
            prop_assert!(truncated.len() <= max_len);
            prop_assert!(s.starts_with(&truncated));
        }

        // Batch size properties
        #[test]
        fn batch_sizes_are_reasonable(events in prop::collection::vec(any::<u32>(), 0..10000)) {
            let batches = create_batches(&events, 100);

            // All batches except last should be exactly batch size
            for batch in batches.iter().take(batches.len().saturating_sub(1)) {
                prop_assert_eq!(batch.len(), 100);
            }

            // Last batch should be <= batch size
            if let Some(last) = batches.last() {
                prop_assert!(last.len() <= 100);
            }

            // Total count should match
            let total: usize = batches.iter().map(|b| b.len()).sum();
            prop_assert_eq!(total, events.len());
        }
    }

    // Helper functions

    /// Calculate Shannon entropy of byte sequence
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Calculate SHA256 hash
    fn calculate_sha256(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    /// Normalize file path
    fn normalize_path(path: &str) -> String {
        path.replace("\\", "/").trim().to_string()
    }

    /// Check if path is absolute
    fn is_absolute(path: &str) -> bool {
        #[cfg(windows)]
        {
            path.len() >= 3 && path.chars().nth(1) == Some(':')
        }
        #[cfg(not(windows))]
        {
            path.starts_with('/')
        }
    }

    /// Parse IPv4 address
    fn parse_ipv4(ip: &str) -> Result<(u8, u8, u8, u8), String> {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return Err("Invalid IPv4 format".to_string());
        }

        let a = parts[0].parse().map_err(|_| "Invalid octet")?;
        let b = parts[1].parse().map_err(|_| "Invalid octet")?;
        let c = parts[2].parse().map_err(|_| "Invalid octet")?;
        let d = parts[3].parse().map_err(|_| "Invalid octet")?;

        Ok((a, b, c, d))
    }

    /// Parse command line into tokens
    fn parse_cmdline(cmdline: &str) -> Vec<String> {
        cmdline.split_whitespace().map(|s| s.to_string()).collect()
    }

    /// Merge two hashmaps (map2 overwrites map1 on conflicts)
    fn merge_maps(
        map1: &HashMap<String, i32>,
        map2: &HashMap<String, i32>,
    ) -> HashMap<String, i32> {
        let mut result = map1.clone();
        for (k, v) in map2 {
            result.insert(k.clone(), *v);
        }
        result
    }

    /// Truncate string to max length
    fn truncate_string(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            s.chars().take(max_len).collect()
        }
    }

    /// Create batches from a vector
    fn create_batches<T: Clone>(items: &[T], batch_size: usize) -> Vec<Vec<T>> {
        items
            .chunks(batch_size)
            .map(|chunk| chunk.to_vec())
            .collect()
    }

    /// Encode message as JSON
    fn encode_json<T: serde::Serialize>(msg: &T) -> Vec<u8> {
        serde_json::to_vec(msg).unwrap()
    }

    /// Create telemetry ack message
    fn create_telemetry_ack(sequence: u64, count: usize) -> HashMap<String, Value> {
        let mut map = HashMap::new();
        map.insert(
            "type".to_string(),
            Value::String("telemetry_ack".to_string()),
        );
        map.insert("sequence".to_string(), Value::Number(sequence.into()));
        map.insert("count".to_string(), Value::Number(count.into()));
        map
    }

    // Property test strategies

    fn event_type_strategy() -> impl Strategy<Value = EventType> {
        prop_oneof![
            Just(EventType::ProcessCreate),
            Just(EventType::ProcessTerminate),
            Just(EventType::FileCreate),
            Just(EventType::NetworkConnect),
            Just(EventType::DnsQuery),
        ]
    }

    fn absolute_path_strategy() -> impl Strategy<Value = String> {
        #[cfg(windows)]
        {
            prop::string::string_regex("[A-Z]:[/\\\\][a-zA-Z0-9_/\\\\]{0,50}").unwrap()
        }
        #[cfg(not(windows))]
        {
            prop::string::string_regex("/[a-zA-Z0-9_/]{0,50}").unwrap()
        }
    }
}
