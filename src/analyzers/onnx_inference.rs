//! ONNX Runtime Inference Wrapper for Malware-SMELL
//!
//! This module wraps ONNX Runtime to run the Malware-SMELL model locally on the
//! agent for offline malware detection. It replicates the Python preprocessing
//! pipeline from `tamandua_ml/src/preprocessing/binary_to_image.py`:
//!
//! 1. Read raw binary bytes
//! 2. Reshape into a square grayscale image (pad/truncate)
//! 3. Resize to the model's expected input size (default 64x64)
//! 4. Normalize pixel values to [0.0, 1.0]
//! 5. Expand to 3-channel (VGG-19 expects RGB input)
//! 6. Run ONNX inference -> class probabilities
//!
//! The model input shape is [1, 3, image_size, image_size] (NCHW).
//! The model output shape is [1, num_classes] with class probabilities.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

#[cfg(feature = "onnx")]
use ndarray::Array4;
#[cfg(feature = "onnx")]
use ort::{
    inputs,
    session::{Session, SessionOutputs},
    value::Value,
};

/// Labels for the output classes.  Index 0 must be "benign".
const DEFAULT_FAMILY_LABELS: &[&str] = &[
    "benign",
    "trojan",
    "ransomware",
    "spyware",
    "adware",
    "worm",
    "backdoor",
    "unknown_malware",
];

/// Result of an ONNX inference run.
#[derive(Debug, Clone)]
pub struct InferenceResult {
    /// Predicted class label (e.g. "benign", "trojan").
    pub predicted_class: String,
    /// Index of the predicted class in the output vector.
    pub predicted_index: usize,
    /// Confidence score for the predicted class (0.0 - 1.0).
    pub confidence: f32,
    /// Whether the prediction is malicious (any class other than index 0).
    pub is_malicious: bool,
    /// Raw (softmax-normalized) probabilities for every class.
    pub probabilities: Vec<f32>,
    /// Wall-clock inference time in milliseconds.
    pub inference_time_ms: u64,
}

/// Input format expected by the ONNX model.
///
/// - `ImageNCHW`: The SMELL model expects a 3-channel image [1, 3, H, W].
///   Raw bytes are converted to a grayscale image, resized, and replicated
///   to 3 channels.
/// - `RawBytes1D`: The Transformer and Ensemble models expect a 1D float
///   tensor [1, max_length] of byte values in [0, 255].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelInputFormat {
    /// SMELL-style: binary -> image -> [1, 3, image_size, image_size].
    ImageNCHW,
    /// Transformer/Ensemble-style: binary -> [1, max_length] float32.
    RawBytes1D,
}

/// Configuration for the ONNX inference engine.
#[derive(Debug, Clone)]
pub struct OnnxInferenceConfig {
    /// Path to the `.onnx` model file.
    pub model_path: PathBuf,
    /// Square image size the model expects (default: 64, matching Python training).
    /// Only used when `input_format` is `ImageNCHW`.
    pub image_size: usize,
    /// Number of intra-op threads for ONNX Runtime (default: 2).
    pub intra_threads: usize,
    /// Class labels; index 0 **must** be the benign class.
    pub family_labels: Vec<String>,
    /// Input format for the model.
    pub input_format: ModelInputFormat,
    /// Maximum input byte length for `RawBytes1D` format (default: 4096).
    /// The binary is truncated or zero-padded to this length.
    pub max_input_length: usize,
}

impl Default for OnnxInferenceConfig {
    fn default() -> Self {
        Self {
            model_path: Self::default_model_path(),
            image_size: 64,
            intra_threads: 2,
            family_labels: DEFAULT_FAMILY_LABELS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            input_format: ModelInputFormat::ImageNCHW,
            max_input_length: 4096,
        }
    }
}

impl OnnxInferenceConfig {
    fn default_model_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            PathBuf::from(r"C:\ProgramData\Tamandua\models\malware_smell.onnx")
        }
        #[cfg(target_os = "linux")]
        {
            PathBuf::from("/var/lib/tamandua/models/malware_smell.onnx")
        }
        #[cfg(target_os = "macos")]
        {
            PathBuf::from("/Library/Application Support/Tamandua/models/malware_smell.onnx")
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from("./models/malware_smell.onnx")
        }
    }
}

// ---------------------------------------------------------------------------
// OnnxInferenceEngine
// ---------------------------------------------------------------------------

/// Thin wrapper around an ONNX Runtime session for the Malware-SMELL model.
///
/// All public methods are **synchronous** and should be called from a blocking
/// thread (`tokio::task::spawn_blocking`) to avoid stalling the async runtime.
pub struct OnnxInferenceEngine {
    #[cfg(feature = "onnx")]
    session: Option<Session>,
    #[cfg(not(feature = "onnx"))]
    _session: (),
    config: OnnxInferenceConfig,
    operational: bool,
}

impl OnnxInferenceEngine {
    /// Create a new inference engine, loading the ONNX model from disk.
    ///
    /// If the model file is missing or fails to load the engine is created in
    /// a non-operational state and all calls to [`predict`] will return `None`.
    pub fn new(config: OnnxInferenceConfig) -> Self {
        let (session, operational) = Self::try_load_model(&config);

        if operational {
            info!(
                model_path = %config.model_path.display(),
                image_size = config.image_size,
                "ONNX inference engine loaded"
            );
        } else {
            warn!(
                model_path = %config.model_path.display(),
                "ONNX inference engine not operational -- ML detection disabled"
            );
        }

        #[cfg(feature = "onnx")]
        {
            Self {
                session,
                config,
                operational,
            }
        }
        #[cfg(not(feature = "onnx"))]
        {
            let _ = session; // suppress unused warning
            Self {
                _session: (),
                config,
                operational: false,
            }
        }
    }

    /// Returns `true` when the model is loaded and ready for inference.
    pub fn is_operational(&self) -> bool {
        self.operational
    }

    /// Current model path.
    pub fn model_path(&self) -> &Path {
        &self.config.model_path
    }

    /// Run inference on raw binary bytes.
    ///
    /// Returns `None` when the engine is not operational.
    pub fn predict(&mut self, binary_data: &[u8]) -> Option<InferenceResult> {
        if !self.operational {
            return None;
        }

        #[cfg(feature = "onnx")]
        {
            let start = std::time::Instant::now();
            match self.run_inference_inner(binary_data) {
                Ok(mut result) => {
                    result.inference_time_ms = start.elapsed().as_millis() as u64;
                    Some(result)
                }
                Err(e) => {
                    error!(error = %e, "ONNX inference failed");
                    None
                }
            }
        }
        #[cfg(not(feature = "onnx"))]
        {
            let _ = binary_data;
            None
        }
    }

    /// Hot-reload the model from a new byte slice (e.g. received via config
    /// update channel).  Returns `Ok(true)` when the new model was loaded
    /// successfully or `Ok(false)` / `Err` on failure.
    #[cfg(feature = "onnx")]
    pub fn reload_from_bytes(&mut self, model_bytes: &[u8]) -> Result<bool> {
        // Write to a temporary file and load from there (ort requires a path).
        let tmp_path = self.config.model_path.with_extension("onnx.tmp");
        std::fs::write(&tmp_path, model_bytes).context("Failed to write temporary ONNX model")?;

        let mut tmp_config = self.config.clone();
        tmp_config.model_path = tmp_path.clone();
        let (session, ok) = Self::try_load_model(&tmp_config);

        if ok {
            // Atomically replace old model file.
            std::fs::rename(&tmp_path, &self.config.model_path)
                .context("Failed to replace ONNX model on disk")?;
            self.session = session;
            self.operational = true;
            info!("ONNX model hot-reloaded successfully");
            Ok(true)
        } else {
            let _ = std::fs::remove_file(&tmp_path);
            warn!("Hot-reload failed -- keeping previous model");
            Ok(false)
        }
    }

    #[cfg(not(feature = "onnx"))]
    pub fn reload_from_bytes(&mut self, _model_bytes: &[u8]) -> Result<bool> {
        Ok(false)
    }

    /// Reload the model from disk (same path as original config).
    pub fn reload_from_disk(&mut self) -> Result<bool> {
        let (session, ok) = Self::try_load_model(&self.config);
        #[cfg(feature = "onnx")]
        {
            self.session = session;
        }
        #[cfg(not(feature = "onnx"))]
        {
            let _ = session;
        }
        self.operational = ok;
        if ok {
            info!("ONNX model reloaded from disk");
        }
        Ok(ok)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    #[cfg(feature = "onnx")]
    fn try_load_model(config: &OnnxInferenceConfig) -> (Option<Session>, bool) {
        if !config.model_path.exists() {
            warn!(
                path = %config.model_path.display(),
                "ONNX model file not found"
            );
            return (None, false);
        }

        let builder = match Session::builder() {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "Failed to create ONNX session builder");
                return (None, false);
            }
        };

        let builder = match builder
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
        {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "Failed to set ONNX optimization level");
                return (None, false);
            }
        };

        let builder = match builder.with_intra_threads(config.intra_threads) {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, "Failed to set intra-op threads");
                return (None, false);
            }
        };

        match builder.commit_from_file(&config.model_path) {
            Ok(session) => {
                info!(
                    model_path = %config.model_path.display(),
                    "ONNX model loaded"
                );
                (Some(session), true)
            }
            Err(e) => {
                error!(
                    model_path = %config.model_path.display(),
                    error = %e,
                    "Failed to load ONNX model"
                );
                (None, false)
            }
        }
    }

    #[cfg(not(feature = "onnx"))]
    fn try_load_model(_config: &OnnxInferenceConfig) -> ((), bool) {
        warn!("ONNX feature not compiled in -- inference unavailable");
        ((), false)
    }

    // -----------------------------------------------------------------------
    // Binary-to-image preprocessing  (mirrors Python pipeline exactly)
    // -----------------------------------------------------------------------

    /// Convert raw binary bytes into a model-ready tensor.
    ///
    /// **Pipeline** (matches `binary_to_image.py`):
    /// 1. Interpret bytes as `u8` pixel values.
    /// 2. Compute a square side length: `ceil(sqrt(len))`.
    /// 3. Pad with zeros (or truncate) so the byte stream fills `side x side`.
    /// 4. Reshape to a 2D grayscale image.
    /// 5. Resize (bilinear) to `image_size x image_size`.
    /// 6. Normalize to `[0.0, 1.0]`.
    /// 7. Expand single channel to 3 identical channels (VGG expects RGB).
    /// 8. Wrap in NCHW tensor: `[1, 3, image_size, image_size]`.
    #[cfg(feature = "onnx")]
    fn binary_to_tensor(&self, data: &[u8]) -> Array4<f32> {
        let size = self.config.image_size;

        if data.is_empty() {
            // Match Python: return zeros for empty input.
            return Array4::<f32>::zeros((1, 3, size, size));
        }

        // Step 1-3: Compute square side, pad/truncate.
        let side = (data.len() as f64).sqrt().ceil() as usize;
        let total = side * side;

        let mut buf = vec![0u8; total];
        let copy_len = data.len().min(total);
        buf[..copy_len].copy_from_slice(&data[..copy_len]);

        // Step 4-5: Resize to target image_size using bilinear interpolation.
        //
        // We use the `image` crate when compiled with the `onnx` feature
        // (which pulls in `image`).  If the square side already matches the
        // target we skip resizing.
        let pixels: Vec<f32> = if side == size {
            // No resize needed -- just normalize.
            buf.iter().map(|&b| b as f32 / 255.0).collect()
        } else {
            self.resize_bilinear(&buf, side, side, size, size)
        };

        // Step 7-8: Expand to 3 channels (repeat grayscale).
        let mut tensor = Array4::<f32>::zeros((1, 3, size, size));
        for row in 0..size {
            for col in 0..size {
                let v = pixels[row * size + col];
                tensor[[0, 0, row, col]] = v;
                tensor[[0, 1, row, col]] = v;
                tensor[[0, 2, row, col]] = v;
            }
        }

        tensor
    }

    /// Simple bilinear resize matching PIL's `Image.Resampling.BILINEAR`.
    #[cfg(feature = "onnx")]
    fn resize_bilinear(
        &self,
        src: &[u8],
        src_h: usize,
        src_w: usize,
        dst_h: usize,
        dst_w: usize,
    ) -> Vec<f32> {
        // Try to use the `image` crate for quality/correctness parity with PIL.
        #[cfg(feature = "onnx")]
        {
            use image::{imageops::FilterType, GrayImage};

            let img = GrayImage::from_raw(src_w as u32, src_h as u32, src.to_vec())
                .unwrap_or_else(|| GrayImage::new(src_w as u32, src_h as u32));

            let resized = image::imageops::resize(
                &img,
                dst_w as u32,
                dst_h as u32,
                FilterType::Triangle, // bilinear
            );

            resized
                .into_raw()
                .iter()
                .map(|&b| b as f32 / 255.0)
                .collect()
        }
    }

    /// Convert raw binary bytes to a 1D float tensor for transformer/ensemble models.
    ///
    /// **Pipeline** (matches Python `ByteTransformerInference` and ensemble export):
    /// 1. Cast each byte to f32 (range [0, 255]).
    /// 2. Truncate to `max_input_length` or zero-pad if shorter.
    /// 3. Wrap in [1, max_input_length] tensor.
    #[cfg(feature = "onnx")]
    fn binary_to_raw_tensor(&self, data: &[u8]) -> ndarray::Array2<f32> {
        let max_len = self.config.max_input_length;
        let mut buf = vec![0.0f32; max_len];
        let copy_len = data.len().min(max_len);
        for i in 0..copy_len {
            buf[i] = data[i] as f32;
        }
        ndarray::Array2::from_shape_vec((1, max_len), buf).expect("raw tensor shape mismatch")
    }

    /// Run the full inference pipeline and interpret the result.
    #[cfg(feature = "onnx")]
    fn run_inference_inner(&mut self, data: &[u8]) -> Result<InferenceResult> {
        // Select preprocessing and input name before borrowing the session mutably.
        let (input_name, input_value) = match self.config.input_format {
            ModelInputFormat::ImageNCHW => {
                // SMELL model: binary -> image tensor.
                let input_tensor = self.binary_to_tensor(data);
                let input_value =
                    Value::from_array(input_tensor).context("Failed to create ONNX input value")?;
                ("input", input_value)
            }
            ModelInputFormat::RawBytes1D => {
                // Transformer / Ensemble model: binary -> raw byte tensor.
                let input_tensor = self.binary_to_raw_tensor(data);
                let input_value =
                    Value::from_array(input_tensor).context("Failed to create ONNX input value")?;
                ("raw_bytes", input_value)
            }
        };

        let raw: Vec<f32> = {
            let session = self
                .session
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("ONNX session not initialized"))?;

            let outputs: SessionOutputs = match input_name {
                "input" => session
                    .run(inputs!["input" => input_value])
                    .context("ONNX inference failed")?,
                "raw_bytes" => session
                    .run(inputs!["raw_bytes" => input_value])
                    .context("ONNX inference failed")?,
                _ => unreachable!("unsupported ONNX input name"),
            };

            // Extract raw logits / probabilities.
            let output = outputs
                .iter()
                .find(|(name, _)| *name == "output")
                .or_else(|| outputs.iter().next())
                .map(|(_, value)| value)
                .ok_or_else(|| anyhow::anyhow!("No output tensor in ONNX model"))?;

            output
                .try_extract_tensor::<f32>()
                .context("Failed to extract output tensor")?
                .1
                .iter()
                .copied()
                .collect()
        };

        self.interpret(raw)
    }

    /// Convert raw model output to an [`InferenceResult`].
    #[cfg(feature = "onnx")]
    fn interpret(&self, raw: Vec<f32>) -> Result<InferenceResult> {
        if raw.is_empty() {
            anyhow::bail!("Model returned empty output");
        }

        // Apply softmax if the output is not already normalized.
        let sum: f32 = raw.iter().sum();
        let probs = if (sum - 1.0).abs() > 0.01 {
            let max_val = raw.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
            let exps: Vec<f32> = raw.iter().map(|&x| (x - max_val).exp()).collect();
            let exp_sum: f32 = exps.iter().sum();
            exps.iter().map(|&e| e / exp_sum).collect::<Vec<f32>>()
        } else {
            raw
        };

        // Find predicted class.
        let (pred_idx, &pred_prob) = probs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, &0.0));

        let pred_label = self
            .config
            .family_labels
            .get(pred_idx)
            .cloned()
            .unwrap_or_else(|| format!("class_{}", pred_idx));

        let is_malicious = pred_idx != 0; // index 0 = benign

        Ok(InferenceResult {
            predicted_class: pred_label,
            predicted_index: pred_idx,
            confidence: pred_prob,
            is_malicious,
            probabilities: probs,
            inference_time_ms: 0, // filled by caller
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = OnnxInferenceConfig::default();
        assert_eq!(cfg.image_size, 64);
        assert_eq!(cfg.family_labels[0], "benign");
    }

    #[test]
    fn test_engine_missing_model() {
        let cfg = OnnxInferenceConfig {
            model_path: PathBuf::from("/nonexistent/model.onnx"),
            ..Default::default()
        };
        let mut engine = OnnxInferenceEngine::new(cfg);
        assert!(!engine.is_operational());
        assert!(engine.predict(&[0u8; 100]).is_none());
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn test_binary_to_tensor_empty() {
        let cfg = OnnxInferenceConfig::default();
        let engine = OnnxInferenceEngine::new(cfg);
        let tensor = engine.binary_to_tensor(&[]);
        assert_eq!(tensor.shape(), &[1, 3, 64, 64]);
        // All zeros for empty input.
        assert_eq!(tensor[[0, 0, 0, 0]], 0.0);
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn test_binary_to_tensor_small() {
        let cfg = OnnxInferenceConfig {
            image_size: 4,
            ..Default::default()
        };
        let engine = OnnxInferenceEngine::new(cfg);
        // 9 bytes -> ceil(sqrt(9))=3 -> 3x3 padded to 9 -> resize to 4x4
        let data = vec![255u8; 9];
        let tensor = engine.binary_to_tensor(&data);
        assert_eq!(tensor.shape(), &[1, 3, 4, 4]);
        // All three channels should be identical.
        for r in 0..4 {
            for c in 0..4 {
                assert_eq!(tensor[[0, 0, r, c]], tensor[[0, 1, r, c]]);
                assert_eq!(tensor[[0, 0, r, c]], tensor[[0, 2, r, c]]);
            }
        }
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn test_interpret_benign() {
        let cfg = OnnxInferenceConfig::default();
        let engine = OnnxInferenceEngine::new(cfg);
        let result = engine.interpret(vec![0.9, 0.05, 0.03, 0.02]).unwrap();
        assert!(!result.is_malicious);
        assert_eq!(result.predicted_class, "benign");
        assert!(result.confidence > 0.85);
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn test_interpret_malicious() {
        let cfg = OnnxInferenceConfig::default();
        let engine = OnnxInferenceEngine::new(cfg);
        let result = engine.interpret(vec![0.1, 0.8, 0.05, 0.05]).unwrap();
        assert!(result.is_malicious);
        assert_eq!(result.predicted_class, "trojan");
        assert!(result.confidence > 0.7);
    }

    #[cfg(feature = "onnx")]
    #[test]
    fn test_interpret_softmax_unnormalized() {
        let cfg = OnnxInferenceConfig::default();
        let engine = OnnxInferenceEngine::new(cfg);
        // Raw logits that need softmax.
        let result = engine.interpret(vec![10.0, 1.0, 0.5, 0.1]).unwrap();
        assert!(!result.is_malicious); // index 0 wins
        assert!(result.confidence > 0.9);
        // Probabilities should sum to ~1.
        let sum: f32 = result.probabilities.iter().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }
}
