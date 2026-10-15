//! Embedded LLM inference using llama.cpp (via llama-cpp-2 Rust bindings)
//!
//! Provides local LLM inference as a fallback when Ollama is unavailable.
//! Uses GGUF model files loaded from disk.

use anyhow::{anyhow, Context, Result};
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::AddBos;
use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::TokenToStringError;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tracing::{debug, info, trace};

/// Configuration for embedded LLM inference
#[derive(Debug, Clone)]
pub struct InferenceConfig {
    /// Context size (number of tokens)
    pub context_size: u32,
    /// Maximum tokens to generate
    pub max_tokens: usize,
    /// Temperature (0.0 = deterministic, 1.0+ = creative)
    pub temperature: f32,
    /// Top-p (nucleus sampling)
    pub top_p: f32,
    /// Number of GPU layers to offload (0 = CPU only, u32::MAX = auto-detect)
    pub n_gpu_layers: u32,
    /// Number of threads (0 = auto-detect)
    pub n_threads: u32,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        Self {
            context_size: 4096,
            max_tokens: 2048,
            temperature: 0.7,
            top_p: 0.9,
            n_gpu_layers: u32::MAX, // Auto-detect and use all available GPU layers
            n_threads: 0,           // Auto-detect optimal thread count
        }
    }
}

/// Model information for debugging and display
#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub path: PathBuf,
    pub context_size: u32,
    pub max_tokens: usize,
    pub backend: String,
    pub vocab_size: Option<i32>,
}

/// The process's llama.cpp backend. llama-cpp-2 refuses a second `LlamaBackend::init()` while
/// one is alive (`BackendAlreadyInitialized`), so every model load and every inference shares
/// this one, and it lives for the rest of the process.
fn shared_backend() -> Result<Arc<LlamaBackend>> {
    static BACKEND: OnceLock<std::result::Result<Arc<LlamaBackend>, String>> = OnceLock::new();
    BACKEND
        .get_or_init(|| {
            LlamaBackend::init()
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(|e| anyhow!("Failed to initialize llama.cpp backend: {e}"))
}

/// Embedded LLM backend using llama.cpp
pub struct EmbeddedLLMBackend {
    model: Arc<LlamaModel>,
    config: InferenceConfig,
    model_path: PathBuf,
    /// The process-wide llama.cpp backend (see [`shared_backend`])
    backend: Arc<LlamaBackend>,
}

impl EmbeddedLLMBackend {
    /// Load GGUF model from disk
    ///
    /// # Arguments
    /// * `model_path` - Path to GGUF model file (e.g., "mistral-7b.Q4_K_M.gguf")
    ///
    /// # Example
    /// ```no_run
    /// # use netget::llm::embedded_inference::EmbeddedLLMBackend;
    /// # async fn example() -> anyhow::Result<()> {
    /// let backend = EmbeddedLLMBackend::new("./models/mistral-7b.Q4_K_M.gguf").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(model_path: impl AsRef<Path>) -> Result<Self> {
        Self::new_with_config(model_path, InferenceConfig::default()).await
    }

    /// Load model with custom configuration
    pub async fn new_with_config(
        model_path: impl AsRef<Path>,
        config: InferenceConfig,
    ) -> Result<Self> {
        let path = model_path.as_ref();
        if !path.exists() {
            return Err(anyhow!(
                "Model file not found: {}. Download a GGUF model from https://huggingface.co/TheBloke",
                path.display()
            ));
        }

        info!("Loading embedded LLM from: {}", path.display());
        debug!(
            "Config: context_size={}, max_tokens={}, temp={}, top_p={}, gpu_layers={}",
            config.context_size,
            config.max_tokens,
            config.temperature,
            config.top_p,
            if config.n_gpu_layers == u32::MAX {
                "auto".to_string()
            } else {
                config.n_gpu_layers.to_string()
            }
        );

        let backend = shared_backend()?;

        // Load model (blocking operation, run in spawn_blocking)
        let model_path_clone = path.to_path_buf();
        let n_gpu_layers = config.n_gpu_layers;
        let backend_clone = backend.clone();

        let model = tokio::task::spawn_blocking(move || {
            // Create model params with GPU layers
            let model_params = LlamaModelParams::default().with_n_gpu_layers(n_gpu_layers);

            // Load model from file
            LlamaModel::load_from_file(&backend_clone, model_path_clone, &model_params)
                .context("Failed to load GGUF model")
        })
        .await??;

        let vocab_size = model.n_vocab();
        info!(
            "Embedded LLM loaded successfully (vocab_size: {}, context_size: {})",
            vocab_size, config.context_size
        );

        Ok(Self {
            model: Arc::new(model),
            config,
            model_path: path.to_path_buf(),
            backend,
        })
    }

    /// Generate completion from prompt (non-streaming)
    ///
    /// # Arguments
    /// * `prompt` - Input text prompt
    ///
    /// # Returns
    /// Generated text completion
    ///
    /// # Example
    /// ```no_run
    /// # use netget::llm::embedded_inference::EmbeddedLLMBackend;
    /// # async fn example() -> anyhow::Result<()> {
    /// # let backend = EmbeddedLLMBackend::new("model.gguf").await?;
    /// let response = backend.generate(&"Hello, how are you?").await?;
    /// println!("Response: {}", response);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn generate(&self, prompt: &str) -> Result<String> {
        let model = self.model.clone();
        let backend = self.backend.clone();
        let prompt = prompt.to_string();
        let config = self.config.clone();

        // Run inference in blocking task (CPU/GPU-intensive)
        let response = tokio::task::spawn_blocking(move || {
            Self::run_inference_sync(&backend, &model, &prompt, &config)
        })
        .await
        .context("Inference task panicked")??;

        Ok(response)
    }

    /// Synchronous inference (runs in blocking task)
    fn run_inference_sync(
        backend: &LlamaBackend,
        model: &LlamaModel,
        prompt: &str,
        config: &InferenceConfig,
    ) -> Result<String> {
        // Create context params
        let n_ctx =
            NonZeroU32::new(config.context_size).context("Context size must be non-zero")?;

        let mut ctx_params = LlamaContextParams::default().with_n_ctx(Some(n_ctx));

        if config.n_threads > 0 {
            ctx_params = ctx_params.with_n_threads(config.n_threads as i32);
        }

        // Create inference context
        let mut ctx = model
            .new_context(backend, ctx_params)
            .context("Failed to create inference context")?;

        // Create sampler (greedy for now, can be enhanced later)
        let mut sampler = LlamaSampler::greedy();

        // Tokenize prompt
        let tokens = model
            .str_to_token(prompt, AddBos::Always)
            .context("Failed to tokenize prompt")?;

        debug!("Tokenized prompt: {} tokens", tokens.len());

        if tokens.len() >= config.context_size as usize {
            return Err(anyhow!(
                "Prompt too long: {} tokens (max: {})",
                tokens.len(),
                config.context_size
            ));
        }

        // Prepare batch
        let mut batch = LlamaBatch::new(config.context_size as usize, 1);

        // Add prompt tokens to batch
        for (i, token) in tokens.iter().enumerate() {
            let is_last = i == tokens.len() - 1;
            batch.add(*token, i as i32, &[0], is_last)?;
        }

        // Decode prompt
        ctx.decode(&mut batch).context("Failed to decode prompt")?;

        // Generate tokens
        let mut generated_text = String::new();
        let mut n_cur = tokens.len();
        let mut n_decode = 0;

        while n_cur < config.context_size as usize && n_decode < config.max_tokens {
            // Sample next token using sampler
            let new_token_id = sampler.sample(&ctx, batch.n_tokens() - 1);

            // Check for end of generation
            if model.is_eog_token(new_token_id) {
                trace!("End of generation token encountered");
                break;
            }

            // Decode token to text, rendering special tokens. A piece longer than the first
            // buffer is answered with its size, negated.
            let output_bytes = match model.token_to_piece_bytes(new_token_id, 8, true, None) {
                Err(TokenToStringError::InsufficientBufferSpace(needed)) => model
                    .token_to_piece_bytes(new_token_id, needed.unsigned_abs() as usize, true, None),
                other => other,
            }
            .context("Failed to decode token")?;
            let output_str = String::from_utf8_lossy(&output_bytes);
            generated_text.push_str(&output_str);

            trace!("Generated token: {:?}", output_str);

            // Prepare next batch
            batch.clear();
            batch.add(new_token_id, n_cur as i32, &[0], true)?;

            // Decode
            ctx.decode(&mut batch).context("Failed to decode batch")?;

            n_cur += 1;
            n_decode += 1;
        }

        debug!("Generation complete: {} tokens generated", n_decode);

        Ok(generated_text.trim().to_string())
    }

    /// Get model information (useful for debugging and display)
    pub fn get_model_info(&self) -> ModelInfo {
        ModelInfo {
            path: self.model_path.clone(),
            context_size: self.config.context_size,
            max_tokens: self.config.max_tokens,
            backend: "llama.cpp".to_string(),
            vocab_size: Some(self.model.n_vocab()),
        }
    }

    /// Get model path
    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    /// Check if model is loaded and ready
    pub fn is_ready(&self) -> bool {
        true // If we constructed successfully, we're ready
    }
}
