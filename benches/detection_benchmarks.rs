//! Detection Performance Benchmarks
//!
//! Comprehensive benchmark suite for Tamandua EDR detection capabilities.
//! Measures performance of YARA, Sigma, ML, and behavioral detection.
//!
//! Run with:
//!   cargo bench --bench detection_benchmarks
//!   cargo bench --bench detection_benchmarks --features yara
//!   cargo bench --bench detection_benchmarks --features onnx
//!
//! For detailed HTML reports:
//!   cargo bench --bench detection_benchmarks -- --save-baseline main
//!
//! Compare against baseline:
//!   cargo bench --bench detection_benchmarks -- --baseline main

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// YARA Performance Benchmarks
// ============================================================================

mod yara_benchmarks {
    use super::*;

    /// Sample YARA rules of varying complexity
    const SIMPLE_RULE: &str = r#"
        rule SimpleString {
            strings:
                $s1 = "malware"
            condition:
                $s1
        }
    "#;

    const MEDIUM_RULE: &str = r#"
        rule MediumComplexity {
            meta:
                description = "Medium complexity rule"
                author = "Tamandua"
            strings:
                $s1 = "CreateRemoteThread" nocase
                $s2 = "VirtualAllocEx" nocase
                $s3 = "WriteProcessMemory" nocase
                $hex = { 48 8B 05 ?? ?? ?? ?? 48 89 45 }
            condition:
                2 of ($s*) or $hex
        }
    "#;

    const COMPLEX_RULE: &str = r#"
        rule ComplexRule {
            meta:
                description = "Complex detection rule"
                author = "Tamandua"
                severity = "high"
            strings:
                $api1 = "NtCreateThreadEx" nocase wide
                $api2 = "NtUnmapViewOfSection" nocase wide
                $api3 = "NtAllocateVirtualMemory" nocase wide
                $api4 = "LdrLoadDll" nocase wide
                $mz = { 4D 5A }
                $pe = { 50 45 00 00 }
                $suspicious1 = /[A-Za-z0-9+\/]{50,}={0,2}/ wide
                $suspicious2 = "powershell" nocase
                $suspicious3 = "-encodedcommand" nocase
            condition:
                $mz at 0 and $pe and
                (3 of ($api*) or (2 of ($suspicious*) and any of ($api*)))
        }
    "#;

    /// Generate a ruleset with N rules
    fn generate_ruleset(count: usize) -> String {
        let mut rules = String::new();
        for i in 0..count {
            rules.push_str(&format!(
                r#"
                rule GeneratedRule_{i} {{
                    strings:
                        $s1 = "pattern_{i}_alpha"
                        $s2 = "pattern_{i}_beta"
                        $hex = {{ {0:02X} {1:02X} {2:02X} ?? ?? }}
                    condition:
                        any of them
                }}
                "#,
                (i % 256) as u8,
                ((i * 7) % 256) as u8,
                ((i * 13) % 256) as u8,
            ));
        }
        rules
    }

    /// Generate test data of specified size
    fn generate_test_data(size: usize, with_match: bool) -> Vec<u8> {
        let mut data = vec![0u8; size];
        // Fill with semi-random but deterministic content
        for i in 0..size {
            data[i] = ((i * 7 + 13) % 256) as u8;
        }
        if with_match {
            // Insert a matching pattern
            let pattern = b"malware";
            let offset = size / 2;
            if offset + pattern.len() < size {
                data[offset..offset + pattern.len()].copy_from_slice(pattern);
            }
        }
        data
    }

    #[cfg(feature = "yara")]
    pub fn benchmark_yara_compilation(c: &mut Criterion) {
        let mut group = c.benchmark_group("yara_compilation");
        group.measurement_time(Duration::from_secs(15));
        group.sample_size(50);

        // Single rule compilation
        group.bench_function("simple_rule", |b| {
            b.iter(|| {
                let mut compiler = yara::Compiler::new().unwrap();
                compiler.add_rules_str(black_box(SIMPLE_RULE)).unwrap();
                let rules = compiler.compile_rules().unwrap();
                black_box(rules);
            });
        });

        group.bench_function("medium_rule", |b| {
            b.iter(|| {
                let mut compiler = yara::Compiler::new().unwrap();
                compiler.add_rules_str(black_box(MEDIUM_RULE)).unwrap();
                let rules = compiler.compile_rules().unwrap();
                black_box(rules);
            });
        });

        group.bench_function("complex_rule", |b| {
            b.iter(|| {
                let mut compiler = yara::Compiler::new().unwrap();
                compiler.add_rules_str(black_box(COMPLEX_RULE)).unwrap();
                let rules = compiler.compile_rules().unwrap();
                black_box(rules);
            });
        });

        // Ruleset compilation by size
        for rule_count in [10, 50, 100, 200, 500].iter() {
            let ruleset = generate_ruleset(*rule_count);
            group.bench_with_input(
                BenchmarkId::new("ruleset", rule_count),
                &ruleset,
                |b, ruleset| {
                    b.iter(|| {
                        let mut compiler = yara::Compiler::new().unwrap();
                        compiler.add_rules_str(black_box(ruleset)).unwrap();
                        let rules = compiler.compile_rules().unwrap();
                        black_box(rules);
                    });
                },
            );
        }

        group.finish();
    }

    #[cfg(feature = "yara")]
    pub fn benchmark_yara_scanning(c: &mut Criterion) {
        let mut group = c.benchmark_group("yara_scanning");
        group.measurement_time(Duration::from_secs(20));

        // Pre-compile rules
        let mut compiler = yara::Compiler::new().unwrap();
        compiler.add_rules_str(SIMPLE_RULE).unwrap();
        compiler.add_rules_str(MEDIUM_RULE).unwrap();
        compiler.add_rules_str(COMPLEX_RULE).unwrap();
        let rules = compiler.compile_rules().unwrap();

        // Scan throughput by data size
        for size in [
            1024,             // 1 KB
            10 * 1024,        // 10 KB
            100 * 1024,       // 100 KB
            1024 * 1024,      // 1 MB
            10 * 1024 * 1024, // 10 MB
        ]
        .iter()
        {
            let data_no_match = generate_test_data(*size, false);
            let data_with_match = generate_test_data(*size, true);

            group.throughput(Throughput::Bytes(*size as u64));

            group.bench_with_input(
                BenchmarkId::new("scan_no_match", size),
                &data_no_match,
                |b, data| {
                    b.iter(|| {
                        let result = rules.scan_mem(black_box(data), 60).unwrap();
                        black_box(result);
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("scan_with_match", size),
                &data_with_match,
                |b, data| {
                    b.iter(|| {
                        let result = rules.scan_mem(black_box(data), 60).unwrap();
                        black_box(result);
                    });
                },
            );
        }

        group.finish();
    }

    #[cfg(feature = "yara")]
    pub fn benchmark_yara_ruleset_scaling(c: &mut Criterion) {
        let mut group = c.benchmark_group("yara_ruleset_scaling");
        group.measurement_time(Duration::from_secs(30));
        group.sample_size(30);

        let test_data = generate_test_data(100 * 1024, false); // 100 KB

        for rule_count in [10, 25, 50, 100, 200, 500].iter() {
            let ruleset = generate_ruleset(*rule_count);

            // Compile once for scanning benchmark
            let mut compiler = yara::Compiler::new().unwrap();
            compiler.add_rules_str(&ruleset).unwrap();
            let rules = compiler.compile_rules().unwrap();

            group.bench_with_input(
                BenchmarkId::new("scan_100kb", rule_count),
                &rules,
                |b, rules| {
                    b.iter(|| {
                        let result = rules.scan_mem(black_box(&test_data), 60).unwrap();
                        black_box(result);
                    });
                },
            );
        }

        group.finish();
    }

    #[cfg(feature = "yara")]
    pub fn benchmark_yara_parallel_scanning(c: &mut Criterion) {
        use std::thread;

        let mut group = c.benchmark_group("yara_parallel_scanning");
        group.measurement_time(Duration::from_secs(20));
        group.sample_size(20);

        let ruleset = generate_ruleset(100);
        let mut compiler = yara::Compiler::new().unwrap();
        compiler.add_rules_str(&ruleset).unwrap();
        let rules = Arc::new(compiler.compile_rules().unwrap());

        let test_data = Arc::new(generate_test_data(100 * 1024, false));

        for num_threads in [1, 2, 4, 8].iter() {
            group.bench_with_input(
                BenchmarkId::new("parallel_scan", num_threads),
                num_threads,
                |b, &num_threads| {
                    b.iter(|| {
                        let handles: Vec<_> = (0..num_threads)
                            .map(|_| {
                                let rules = Arc::clone(&rules);
                                let data = Arc::clone(&test_data);
                                thread::spawn(move || {
                                    for _ in 0..10 {
                                        let result = rules.scan_mem(&data, 60).unwrap();
                                        black_box(result);
                                    }
                                })
                            })
                            .collect();

                        for handle in handles {
                            handle.join().unwrap();
                        }
                    });
                },
            );
        }

        group.finish();
    }

    #[cfg(not(feature = "yara"))]
    pub fn benchmark_yara_compilation(_c: &mut Criterion) {}

    #[cfg(not(feature = "yara"))]
    pub fn benchmark_yara_scanning(_c: &mut Criterion) {}

    #[cfg(not(feature = "yara"))]
    pub fn benchmark_yara_ruleset_scaling(_c: &mut Criterion) {}

    #[cfg(not(feature = "yara"))]
    pub fn benchmark_yara_parallel_scanning(_c: &mut Criterion) {}
}

// ============================================================================
// Sigma Performance Benchmarks
// ============================================================================

mod sigma_benchmarks {
    use super::*;

    /// Generate a test event
    fn generate_event(id: usize, event_type: &str) -> HashMap<String, String> {
        let mut event = HashMap::new();
        event.insert("event_type".to_string(), event_type.to_string());
        event.insert("pid".to_string(), format!("{}", 1000 + id));
        event.insert("ppid".to_string(), "1".to_string());
        event.insert("name".to_string(), format!("process_{}.exe", id % 100));
        event.insert(
            "path".to_string(),
            format!("C:\\Windows\\System32\\process_{}.exe", id % 100),
        );
        event.insert(
            "cmdline".to_string(),
            format!("process_{}.exe --arg{} --flag", id % 100, id),
        );
        event.insert("user".to_string(), "SYSTEM".to_string());
        event.insert(
            "remote_ip".to_string(),
            format!("192.168.{}.{}", id % 256, (id * 7) % 256),
        );
        event.insert("remote_port".to_string(), format!("{}", 1024 + id % 64000));
        event
    }

    /// Simple condition matching
    fn match_simple_condition(event: &HashMap<String, String>, pattern: &str) -> bool {
        event
            .get("cmdline")
            .map(|v| v.to_lowercase().contains(pattern))
            .unwrap_or(false)
    }

    /// Complex condition with multiple field checks
    fn match_complex_condition(event: &HashMap<String, String>) -> bool {
        let cmdline_match = event
            .get("cmdline")
            .map(|v| {
                let lower = v.to_lowercase();
                lower.contains("powershell")
                    || lower.contains("cmd.exe")
                    || lower.contains("-encodedcommand")
            })
            .unwrap_or(false);

        let path_match = event
            .get("path")
            .map(|v| {
                let lower = v.to_lowercase();
                lower.contains("\\temp\\") || lower.contains("\\appdata\\")
            })
            .unwrap_or(false);

        let user_match = event.get("user").map(|v| v == "SYSTEM").unwrap_or(false);

        cmdline_match && (path_match || user_match)
    }

    /// Regex-based matching
    fn match_regex_condition(event: &HashMap<String, String>, regex: &regex::Regex) -> bool {
        event
            .get("cmdline")
            .map(|v| regex.is_match(v))
            .unwrap_or(false)
    }

    pub fn benchmark_sigma_parsing(c: &mut Criterion) {
        let mut group = c.benchmark_group("sigma_parsing");
        group.measurement_time(Duration::from_secs(10));

        // Simulate parsing complexity
        let simple_condition = "selection";
        let medium_condition = "selection and not filter";
        let complex_condition =
            "(selection1 or selection2) and not (filter1 or filter2) | count() > 5";

        group.bench_function("parse_simple", |b| {
            b.iter(|| {
                let tokens: Vec<&str> = black_box(simple_condition).split_whitespace().collect();
                black_box(tokens);
            });
        });

        group.bench_function("parse_medium", |b| {
            b.iter(|| {
                let tokens: Vec<&str> = black_box(medium_condition).split_whitespace().collect();
                black_box(tokens);
            });
        });

        group.bench_function("parse_complex", |b| {
            b.iter(|| {
                let tokens: Vec<&str> = black_box(complex_condition)
                    .replace("(", " ( ")
                    .replace(")", " ) ")
                    .replace("|", " | ")
                    .split_whitespace()
                    .collect();
                black_box(tokens);
            });
        });

        group.finish();
    }

    pub fn benchmark_sigma_matching(c: &mut Criterion) {
        let mut group = c.benchmark_group("sigma_matching");
        group.measurement_time(Duration::from_secs(15));

        let events: Vec<_> = (0..1000)
            .map(|i| generate_event(i, "process_create"))
            .collect();

        // Single event, simple match
        group.bench_function("simple_match_single", |b| {
            let event = &events[0];
            b.iter(|| {
                let result = match_simple_condition(black_box(event), "process");
                black_box(result);
            });
        });

        // Single event, complex match
        group.bench_function("complex_match_single", |b| {
            let event = &events[0];
            b.iter(|| {
                let result = match_complex_condition(black_box(event));
                black_box(result);
            });
        });

        // Regex match
        let regex = regex::Regex::new(r"(?i)process_\d+\.exe.*--arg\d+").unwrap();
        group.bench_function("regex_match_single", |b| {
            let event = &events[0];
            b.iter(|| {
                let result = match_regex_condition(black_box(event), &regex);
                black_box(result);
            });
        });

        // Batch matching throughput
        for batch_size in [100, 500, 1000].iter() {
            group.throughput(Throughput::Elements(*batch_size as u64));

            group.bench_with_input(
                BenchmarkId::new("simple_batch", batch_size),
                batch_size,
                |b, &size| {
                    b.iter(|| {
                        let count = events
                            .iter()
                            .take(size)
                            .filter(|e| match_simple_condition(e, "process"))
                            .count();
                        black_box(count);
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("complex_batch", batch_size),
                batch_size,
                |b, &size| {
                    b.iter(|| {
                        let count = events
                            .iter()
                            .take(size)
                            .filter(|e| match_complex_condition(e))
                            .count();
                        black_box(count);
                    });
                },
            );
        }

        group.finish();
    }

    pub fn benchmark_sigma_rule_scaling(c: &mut Criterion) {
        let mut group = c.benchmark_group("sigma_rule_scaling");
        group.measurement_time(Duration::from_secs(20));

        let events: Vec<_> = (0..100)
            .map(|i| generate_event(i, "process_create"))
            .collect();

        // Simulate multiple rules
        let patterns: Vec<String> = (0..500).map(|i| format!("pattern_{}", i % 100)).collect();

        for rule_count in [10, 50, 100, 200, 500].iter() {
            group.bench_with_input(
                BenchmarkId::new("match_against_rules", rule_count),
                rule_count,
                |b, &count| {
                    b.iter(|| {
                        let event = &events[0];
                        let matches: usize = patterns
                            .iter()
                            .take(count)
                            .filter(|p| match_simple_condition(event, p))
                            .count();
                        black_box(matches);
                    });
                },
            );
        }

        group.finish();
    }

    pub fn benchmark_sigma_aggregation_window(c: &mut Criterion) {
        use std::collections::VecDeque;

        let mut group = c.benchmark_group("sigma_aggregation");
        group.measurement_time(Duration::from_secs(15));

        // Simulate aggregation window
        struct AggregationWindow {
            events: VecDeque<(u64, HashMap<String, String>)>,
            window_ms: u64,
        }

        impl AggregationWindow {
            fn new(window_ms: u64) -> Self {
                Self {
                    events: VecDeque::with_capacity(10000),
                    window_ms,
                }
            }

            fn add(&mut self, timestamp: u64, event: HashMap<String, String>) {
                // Expire old events
                let cutoff = timestamp.saturating_sub(self.window_ms);
                while let Some((ts, _)) = self.events.front() {
                    if *ts < cutoff {
                        self.events.pop_front();
                    } else {
                        break;
                    }
                }
                self.events.push_back((timestamp, event));
            }

            fn count_matches<F>(&self, predicate: F) -> usize
            where
                F: Fn(&HashMap<String, String>) -> bool,
            {
                self.events.iter().filter(|(_, e)| predicate(e)).count()
            }
        }

        let events: Vec<_> = (0..10000)
            .map(|i| generate_event(i, "process_create"))
            .collect();

        // Window operations
        for window_size in [100, 1000, 5000].iter() {
            group.bench_with_input(
                BenchmarkId::new("window_add", window_size),
                window_size,
                |b, &size| {
                    let mut window = AggregationWindow::new(60000); // 1 minute
                    b.iter(|| {
                        for i in 0..size {
                            window.add(i as u64 * 10, events[i % events.len()].clone());
                        }
                        black_box(window.events.len());
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("window_count", window_size),
                window_size,
                |b, &size| {
                    let mut window = AggregationWindow::new(u64::MAX);
                    for i in 0..size {
                        window.add(i as u64 * 10, events[i % events.len()].clone());
                    }
                    b.iter(|| {
                        let count = window.count_matches(|e| match_simple_condition(e, "process"));
                        black_box(count);
                    });
                },
            );
        }

        group.finish();
    }
}

// ============================================================================
// ML Performance Benchmarks
// ============================================================================

mod ml_benchmarks {
    use super::*;

    /// Generate binary data for ML testing
    fn generate_binary_data(size: usize, pattern: u8) -> Vec<u8> {
        let mut data = vec![0u8; size];
        for i in 0..size {
            data[i] = ((i * 7 + pattern as usize) % 256) as u8;
        }
        data
    }

    /// Simulate binary-to-image preprocessing
    fn preprocess_to_image(data: &[u8], image_size: usize) -> Vec<f32> {
        if data.is_empty() {
            return vec![0.0f32; image_size * image_size];
        }

        let side = (data.len() as f64).sqrt().ceil() as usize;
        let total = side * side;

        let mut buf = vec![0u8; total];
        let copy_len = data.len().min(total);
        buf[..copy_len].copy_from_slice(&data[..copy_len]);

        // Simple downsampling to target size (not bilinear, but fast for benchmarking)
        let mut result = vec![0.0f32; image_size * image_size];
        let scale = side as f32 / image_size as f32;

        for y in 0..image_size {
            for x in 0..image_size {
                let src_x = (x as f32 * scale) as usize;
                let src_y = (y as f32 * scale) as usize;
                let src_idx = (src_y * side + src_x).min(total - 1);
                result[y * image_size + x] = buf[src_idx] as f32 / 255.0;
            }
        }

        result
    }

    /// Simulate softmax
    fn softmax(logits: &[f32]) -> Vec<f32> {
        let max_val = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = logits.iter().map(|&x| (x - max_val).exp()).collect();
        let sum: f32 = exps.iter().sum();
        exps.iter().map(|&e| e / sum).collect()
    }

    pub fn benchmark_ml_preprocessing(c: &mut Criterion) {
        let mut group = c.benchmark_group("ml_preprocessing");
        group.measurement_time(Duration::from_secs(15));

        for size in [
            1024,        // 1 KB
            10 * 1024,   // 10 KB
            100 * 1024,  // 100 KB
            1024 * 1024, // 1 MB
        ]
        .iter()
        {
            let data = generate_binary_data(*size, 0x42);

            group.throughput(Throughput::Bytes(*size as u64));

            group.bench_with_input(BenchmarkId::new("to_image_64", size), &data, |b, data| {
                b.iter(|| {
                    let image = preprocess_to_image(black_box(data), 64);
                    black_box(image);
                });
            });

            group.bench_with_input(BenchmarkId::new("to_image_128", size), &data, |b, data| {
                b.iter(|| {
                    let image = preprocess_to_image(black_box(data), 128);
                    black_box(image);
                });
            });

            group.bench_with_input(BenchmarkId::new("to_image_256", size), &data, |b, data| {
                b.iter(|| {
                    let image = preprocess_to_image(black_box(data), 256);
                    black_box(image);
                });
            });
        }

        group.finish();
    }

    pub fn benchmark_ml_postprocessing(c: &mut Criterion) {
        let mut group = c.benchmark_group("ml_postprocessing");

        // Simulate model output with different class counts
        for num_classes in [2, 8, 16, 32].iter() {
            let logits: Vec<f32> = (0..*num_classes)
                .map(|i| (i as f32 - *num_classes as f32 / 2.0) * 0.5)
                .collect();

            group.bench_with_input(
                BenchmarkId::new("softmax", num_classes),
                &logits,
                |b, logits| {
                    b.iter(|| {
                        let probs = softmax(black_box(logits));
                        black_box(probs);
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("argmax", num_classes),
                &logits,
                |b, logits| {
                    b.iter(|| {
                        let probs = softmax(logits);
                        let (idx, val) = probs
                            .iter()
                            .enumerate()
                            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                            .unwrap();
                        black_box((idx, val));
                    });
                },
            );
        }

        group.finish();
    }

    #[cfg(feature = "onnx")]
    pub fn benchmark_ml_inference(c: &mut Criterion) {
        use tamandua_agent::analyzers::onnx_inference::{OnnxInferenceConfig, OnnxInferenceEngine};

        let mut group = c.benchmark_group("ml_inference");
        group.measurement_time(Duration::from_secs(30));
        group.sample_size(20);

        let config = OnnxInferenceConfig::default();
        let engine = OnnxInferenceEngine::new(config);

        if !engine.is_operational() {
            println!("ML model not available, skipping ONNX inference benchmarks");
            return;
        }

        // Inference latency by input size
        for size in [1024, 10 * 1024, 100 * 1024, 1024 * 1024].iter() {
            let data = generate_binary_data(*size, 0x42);

            group.throughput(Throughput::Bytes(*size as u64));

            group.bench_with_input(
                BenchmarkId::new("single_inference", size),
                &data,
                |b, data| {
                    b.iter(|| {
                        let result = engine.predict(black_box(data));
                        black_box(result);
                    });
                },
            );
        }

        // Batch inference comparison
        let test_samples: Vec<Vec<u8>> = (0..100)
            .map(|i| generate_binary_data(10 * 1024, i as u8))
            .collect();

        for batch_size in [1, 5, 10, 20].iter() {
            group.bench_with_input(
                BenchmarkId::new("batch_sequential", batch_size),
                batch_size,
                |b, &size| {
                    b.iter(|| {
                        for sample in test_samples.iter().take(size) {
                            let result = engine.predict(black_box(sample));
                            black_box(result);
                        }
                    });
                },
            );
        }

        group.finish();
    }

    #[cfg(not(feature = "onnx"))]
    pub fn benchmark_ml_inference(_c: &mut Criterion) {}

    pub fn benchmark_ml_model_loading(c: &mut Criterion) {
        let mut group = c.benchmark_group("ml_model_loading");
        group.measurement_time(Duration::from_secs(20));
        group.sample_size(10);

        // Simulate model loading overhead (weights allocation)
        for model_size_mb in [10, 50, 100, 200].iter() {
            let weight_count = model_size_mb * 1024 * 1024 / 4; // f32 = 4 bytes

            group.bench_with_input(
                BenchmarkId::new("allocate_weights", model_size_mb),
                &weight_count,
                |b, &count| {
                    b.iter(|| {
                        let weights: Vec<f32> = vec![0.0f32; count];
                        black_box(weights);
                    });
                },
            );
        }

        group.finish();
    }
}

// ============================================================================
// Behavioral Detection Benchmarks
// ============================================================================

mod behavioral_benchmarks {
    use super::*;
    use std::collections::{HashMap, HashSet, VecDeque};

    /// Simulate rolling statistics
    struct RollingStats {
        values: VecDeque<f64>,
        max_size: usize,
        sum: f64,
        sum_sq: f64,
    }

    impl RollingStats {
        fn new(max_size: usize) -> Self {
            Self {
                values: VecDeque::with_capacity(max_size),
                max_size,
                sum: 0.0,
                sum_sq: 0.0,
            }
        }

        fn add(&mut self, value: f64) {
            if self.values.len() >= self.max_size {
                if let Some(old) = self.values.pop_front() {
                    self.sum -= old;
                    self.sum_sq -= old * old;
                }
            }
            self.values.push_back(value);
            self.sum += value;
            self.sum_sq += value * value;
        }

        fn mean(&self) -> f64 {
            if self.values.is_empty() {
                return 0.0;
            }
            self.sum / self.values.len() as f64
        }

        fn std_dev(&self) -> f64 {
            if self.values.len() < 2 {
                return 0.0;
            }
            let n = self.values.len() as f64;
            let mean = self.mean();
            let variance = (self.sum_sq / n) - (mean * mean);
            variance.sqrt()
        }

        fn zscore(&self, value: f64) -> f64 {
            let std = self.std_dev();
            if std == 0.0 {
                return 0.0;
            }
            (value - self.mean()) / std
        }
    }

    /// Simulate process baseline
    struct ProcessBaseline {
        known_parents: HashSet<String>,
        known_children: HashSet<String>,
        known_destinations: HashSet<String>,
        event_rate: RollingStats,
    }

    impl ProcessBaseline {
        fn new() -> Self {
            Self {
                known_parents: HashSet::new(),
                known_children: HashSet::new(),
                known_destinations: HashSet::new(),
                event_rate: RollingStats::new(1000),
            }
        }

        fn update(&mut self, parent: &str, child: Option<&str>, dest: Option<&str>) {
            self.known_parents.insert(parent.to_string());
            if let Some(c) = child {
                self.known_children.insert(c.to_string());
            }
            if let Some(d) = dest {
                self.known_destinations.insert(d.to_string());
            }
            self.event_rate.add(1.0);
        }

        fn is_known_child(&self, child: &str) -> bool {
            self.known_children.contains(child)
        }

        fn is_anomalous_rate(&self, current: f64, threshold: f64) -> bool {
            self.zscore(current).abs() > threshold
        }

        fn zscore(&self, value: f64) -> f64 {
            self.event_rate.zscore(value)
        }
    }

    pub fn benchmark_behavioral_statistics(c: &mut Criterion) {
        let mut group = c.benchmark_group("behavioral_statistics");
        group.measurement_time(Duration::from_secs(10));

        // Rolling stats operations
        let mut stats = RollingStats::new(1000);
        for i in 0..500 {
            stats.add(i as f64);
        }

        group.bench_function("rolling_add", |b| {
            let mut stats = RollingStats::new(1000);
            b.iter(|| {
                stats.add(black_box(42.0));
            });
        });

        group.bench_function("rolling_mean", |b| {
            b.iter(|| {
                let mean = stats.mean();
                black_box(mean);
            });
        });

        group.bench_function("rolling_stddev", |b| {
            b.iter(|| {
                let std = stats.std_dev();
                black_box(std);
            });
        });

        group.bench_function("rolling_zscore", |b| {
            b.iter(|| {
                let z = stats.zscore(black_box(100.0));
                black_box(z);
            });
        });

        group.finish();
    }

    pub fn benchmark_behavioral_baseline_lookup(c: &mut Criterion) {
        let mut group = c.benchmark_group("behavioral_baseline_lookup");
        group.measurement_time(Duration::from_secs(15));

        // Create baselines for many processes
        let mut baselines: HashMap<String, ProcessBaseline> = HashMap::new();
        for i in 0..1000 {
            let name = format!("process_{}.exe", i);
            let mut baseline = ProcessBaseline::new();
            for j in 0..50 {
                baseline.update(
                    &format!("parent_{}", j % 10),
                    Some(&format!("child_{}", j)),
                    Some(&format!("192.168.{}.{}", j % 256, (j * 7) % 256)),
                );
            }
            baselines.insert(name, baseline);
        }

        group.bench_function("baseline_lookup", |b| {
            b.iter(|| {
                let baseline = baselines.get(black_box("process_500.exe"));
                black_box(baseline);
            });
        });

        group.bench_function("child_check", |b| {
            let baseline = baselines.get("process_500.exe").unwrap();
            b.iter(|| {
                let known = baseline.is_known_child(black_box("child_25"));
                black_box(known);
            });
        });

        group.bench_function("anomaly_check", |b| {
            let baseline = baselines.get("process_500.exe").unwrap();
            b.iter(|| {
                let anomalous = baseline.is_anomalous_rate(black_box(100.0), 3.0);
                black_box(anomalous);
            });
        });

        group.finish();
    }

    pub fn benchmark_behavioral_pattern_matching(c: &mut Criterion) {
        let mut group = c.benchmark_group("behavioral_pattern_matching");
        group.measurement_time(Duration::from_secs(15));

        // Suspicious patterns
        let suspicious_patterns = vec![
            (
                "office_shell_spawn",
                vec!["winword", "excel"],
                vec!["cmd.exe", "powershell"],
            ),
            (
                "browser_process_spawn",
                vec!["chrome", "firefox"],
                vec!["cmd.exe", "certutil"],
            ),
            (
                "wmiprvse_spawn",
                vec!["wmiprvse"],
                vec!["cmd.exe", "powershell"],
            ),
        ];

        let test_cases: Vec<(String, String)> = (0..1000)
            .map(|i| {
                let parent = if i % 10 == 0 {
                    "winword.exe".to_string()
                } else {
                    format!("process_{}.exe", i % 100)
                };
                let child = if i % 20 == 0 {
                    "cmd.exe".to_string()
                } else {
                    format!("child_{}.exe", i % 50)
                };
                (parent, child)
            })
            .collect();

        group.bench_function("pattern_match_single", |b| {
            let (parent, child) = &test_cases[0];
            b.iter(|| {
                let mut matched = false;
                for (_, parent_patterns, child_patterns) in &suspicious_patterns {
                    let parent_match = parent_patterns
                        .iter()
                        .any(|p| parent.to_lowercase().contains(p));
                    let child_match = child_patterns
                        .iter()
                        .any(|c| child.to_lowercase().contains(c));
                    if parent_match && child_match {
                        matched = true;
                        break;
                    }
                }
                black_box(matched);
            });
        });

        group.bench_function("pattern_match_batch_1000", |b| {
            b.iter(|| {
                let mut count = 0;
                for (parent, child) in &test_cases {
                    for (_, parent_patterns, child_patterns) in &suspicious_patterns {
                        let parent_match = parent_patterns
                            .iter()
                            .any(|p| parent.to_lowercase().contains(p));
                        let child_match = child_patterns
                            .iter()
                            .any(|c| child.to_lowercase().contains(c));
                        if parent_match && child_match {
                            count += 1;
                            break;
                        }
                    }
                }
                black_box(count);
            });
        });

        group.finish();
    }

    pub fn benchmark_behavioral_entropy(c: &mut Criterion) {
        let mut group = c.benchmark_group("behavioral_entropy");
        group.measurement_time(Duration::from_secs(10));

        fn calculate_string_entropy(s: &str) -> f64 {
            if s.is_empty() {
                return 0.0;
            }
            let mut freq: HashMap<char, u64> = HashMap::new();
            for c in s.chars() {
                *freq.entry(c).or_insert(0) += 1;
            }
            let len = s.len() as f64;
            let mut entropy = 0.0;
            for &count in freq.values() {
                let p = count as f64 / len;
                if p > 0.0 {
                    entropy -= p * p.log2();
                }
            }
            entropy
        }

        let test_strings = vec![
            "google.com",
            "xkcd7nq9mzplwo.tk",
            "login.microsoft.com",
            "qwertyuiopasdfghjklzxcvbnm1234567890.xyz",
        ];

        for s in test_strings {
            group.bench_with_input(
                BenchmarkId::new("entropy", s.len()),
                &s.to_string(),
                |b, s| {
                    b.iter(|| {
                        let entropy = calculate_string_entropy(black_box(s));
                        black_box(entropy);
                    });
                },
            );
        }

        group.finish();
    }
}

// ============================================================================
// Full Pipeline Benchmarks
// ============================================================================

mod pipeline_benchmarks {
    use super::*;

    fn generate_event(id: usize) -> HashMap<String, String> {
        let mut event = HashMap::new();
        event.insert("event_type".to_string(), "process_create".to_string());
        event.insert("pid".to_string(), format!("{}", 1000 + id));
        event.insert("ppid".to_string(), "1".to_string());
        event.insert("name".to_string(), format!("proc_{}.exe", id % 100));
        event.insert(
            "path".to_string(),
            format!("C:\\Windows\\System32\\proc_{}.exe", id % 100),
        );
        event.insert(
            "cmdline".to_string(),
            format!("proc_{}.exe --arg", id % 100),
        );
        event.insert("user".to_string(), "SYSTEM".to_string());
        event.insert(
            "sha256".to_string(),
            format!("{:064x}", id * 12345678901234567890u128),
        );
        event
    }

    pub fn benchmark_full_pipeline(c: &mut Criterion) {
        let mut group = c.benchmark_group("full_pipeline");
        group.measurement_time(Duration::from_secs(20));

        let events: Vec<_> = (0..10000).map(|i| generate_event(i)).collect();

        // Simulate IOC hash matching
        let ioc_hashes: HashSet<String> = (0..1000)
            .map(|i| format!("{:064x}", i * 98765432101234567890u128))
            .collect();

        group.bench_function("event_processing_single", |b| {
            let event = &events[0];
            b.iter(|| {
                // 1. Hash lookup
                let hash = event.get("sha256").unwrap();
                let _ioc_match = ioc_hashes.contains(hash);

                // 2. Field extraction
                let _cmdline = event.get("cmdline");
                let _path = event.get("path");

                // 3. Pattern check
                let _suspicious = event
                    .get("cmdline")
                    .map(|c| c.contains("powershell") || c.contains("cmd.exe"))
                    .unwrap_or(false);

                black_box(event);
            });
        });

        for batch_size in [100, 500, 1000, 5000].iter() {
            group.throughput(Throughput::Elements(*batch_size as u64));

            group.bench_with_input(
                BenchmarkId::new("event_processing_batch", batch_size),
                batch_size,
                |b, &size| {
                    b.iter(|| {
                        let mut matches = 0;
                        for event in events.iter().take(size) {
                            // 1. Hash lookup
                            let hash = event.get("sha256").unwrap();
                            if ioc_hashes.contains(hash) {
                                matches += 1;
                            }

                            // 2. Pattern check
                            if event
                                .get("cmdline")
                                .map(|c| c.contains("powershell"))
                                .unwrap_or(false)
                            {
                                matches += 1;
                            }
                        }
                        black_box(matches);
                    });
                },
            );
        }

        group.finish();
    }

    pub fn benchmark_event_throughput(c: &mut Criterion) {
        let mut group = c.benchmark_group("event_throughput");
        group.measurement_time(Duration::from_secs(30));
        group.sampling_mode(SamplingMode::Flat);

        let events: Vec<_> = (0..100000).map(|i| generate_event(i)).collect();

        // Measure maximum sustainable throughput
        for rate in [1000, 5000, 10000, 50000].iter() {
            group.throughput(Throughput::Elements(*rate as u64));

            group.bench_with_input(BenchmarkId::new("sustained", rate), rate, |b, &rate| {
                b.iter(|| {
                    let start = std::time::Instant::now();
                    let mut processed = 0;
                    for event in events.iter().take(rate) {
                        // Minimal processing
                        let _hash = event.get("sha256");
                        processed += 1;
                    }
                    let elapsed = start.elapsed();
                    black_box((processed, elapsed));
                });
            });
        }

        group.finish();
    }
}

// ============================================================================
// Criterion Group Configuration
// ============================================================================

criterion_group!(
    name = yara_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(50)
        .warm_up_time(Duration::from_secs(3));
    targets =
        yara_benchmarks::benchmark_yara_compilation,
        yara_benchmarks::benchmark_yara_scanning,
        yara_benchmarks::benchmark_yara_ruleset_scaling,
        yara_benchmarks::benchmark_yara_parallel_scanning
);

criterion_group!(
    name = sigma_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(100);
    targets =
        sigma_benchmarks::benchmark_sigma_parsing,
        sigma_benchmarks::benchmark_sigma_matching,
        sigma_benchmarks::benchmark_sigma_rule_scaling,
        sigma_benchmarks::benchmark_sigma_aggregation_window
);

criterion_group!(
    name = ml_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(50);
    targets =
        ml_benchmarks::benchmark_ml_preprocessing,
        ml_benchmarks::benchmark_ml_postprocessing,
        ml_benchmarks::benchmark_ml_inference,
        ml_benchmarks::benchmark_ml_model_loading
);

criterion_group!(
    name = behavioral_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(100);
    targets =
        behavioral_benchmarks::benchmark_behavioral_statistics,
        behavioral_benchmarks::benchmark_behavioral_baseline_lookup,
        behavioral_benchmarks::benchmark_behavioral_pattern_matching,
        behavioral_benchmarks::benchmark_behavioral_entropy
);

criterion_group!(
    name = pipeline_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(50);
    targets =
        pipeline_benchmarks::benchmark_full_pipeline,
        pipeline_benchmarks::benchmark_event_throughput
);

criterion_main!(
    yara_benches,
    sigma_benches,
    ml_benches,
    behavioral_benches,
    pipeline_benches
);
