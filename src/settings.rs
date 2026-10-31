//! Application settings management

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

use crate::state::app_state::{ScriptingMode, WebSearchMode};

/// Application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Ollama model name (None = auto-select from available models)
    #[serde(default)]
    pub model: Option<String>,

    /// Scripting mode, any spelling `-e`/`--env` accepts (see [`ScriptingMode::SPELLINGS`])
    #[serde(default)]
    pub scripting_mode: Option<String>,

    /// Web search mode (on, off, ask)
    #[serde(default = "default_web_search_mode")]
    pub web_search_mode: String,

    /// Legacy field for migration (deprecated)
    #[serde(skip_serializing, default)]
    web_search_enabled: Option<bool>,
}

fn default_web_search_mode() -> String {
    "on".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            model: None,
            scripting_mode: None,
            web_search_mode: default_web_search_mode(),
            web_search_enabled: None,
        }
    }
}

impl Settings {
    /// The canonical settings path; an existing legacy file is read until the
    /// next explicit save safely migrates it into the shared config directory.
    pub fn settings_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| Self::path_at(&home))
    }

    fn path_at(home: &Path) -> PathBuf {
        let root = home.join(".netget");
        if root.is_file() {
            root
        } else if !root.exists() && home.join(".netget-legacy.json").is_file() {
            home.join(".netget-legacy.json")
        } else {
            root.join("settings.json")
        }
    }

    pub fn load() -> Self {
        let result = dirs::home_dir()
            .context("Cannot find home directory")
            .and_then(|home| Self::load_at(&home));
        result.unwrap_or_else(|error| {
            warn!("Failed to load settings: {error:#}; using defaults");
            Self::default()
        })
    }

    /// Explicit home path permits migration tests without mutating process HOME.
    pub fn load_at(home: &Path) -> Result<Self> {
        let path = Self::path_at(home);
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = crate::utils::file_io::read_text(&path, 1024 * 1024)?;
        let mut settings: Self = serde_json::from_str(&contents).context("parse settings")?;
        if let Some(enabled) = settings.web_search_enabled.take() {
            if settings.web_search_mode == default_web_search_mode() {
                settings.web_search_mode = if enabled { "on" } else { "off" }.into();
            }
        }
        Ok(settings)
    }

    pub fn save(&self) -> Result<()> {
        self.save_at(&dirs::home_dir().context("Cannot find home directory")?)
    }

    pub fn save_at(&self, home: &Path) -> Result<()> {
        let directory = crate::utils::file_io::ensure_config_directory(home)?;
        let contents = serde_json::to_vec_pretty(self).context("serialize settings")?;
        crate::utils::file_io::write_atomic(&directory.join("settings.json"), &contents)?;
        debug!("Saved settings in {}", directory.display());
        Ok(())
    }

    /// Update model and save
    pub fn set_model(&mut self, model: Option<String>) -> Result<()> {
        self.model = model;
        self.save()
    }

    /// Record a scripting mode, in its canonical spelling ([`ScriptingMode::config_name`]),
    /// without saving. What is written here is exactly what [`Self::parse_scripting_mode`]
    /// reads back.
    pub fn record_scripting_mode(&mut self, mode: ScriptingMode) {
        self.scripting_mode = Some(mode.config_name().to_string());
    }

    /// Update scripting mode and save
    pub fn set_scripting_mode(&mut self, mode: ScriptingMode) -> Result<()> {
        self.record_scripting_mode(mode);
        self.save()
    }

    /// Get web search mode
    pub fn get_web_search_mode(&self) -> WebSearchMode {
        self.web_search_mode.parse().unwrap_or_else(|e| {
            warn!(
                "Invalid web search mode in settings: '{}' ({}), using default",
                self.web_search_mode, e
            );
            WebSearchMode::On
        })
    }

    /// Update web search mode and save
    pub fn set_web_search_mode(&mut self, mode: WebSearchMode) -> Result<()> {
        self.web_search_mode = mode.to_string();
        self.save()
    }

    /// Parse saved scripting mode.
    ///
    /// Reads through [`ScriptingMode::parse`], the parser `-e`/`--env` uses, so every
    /// spelling the command line accepts (`on`, `auto`, `off`, `llm`, `perl`, …) is accepted
    /// here too, and whatever [`Self::record_scripting_mode`] writes parses back.
    pub fn parse_scripting_mode(&self) -> Option<ScriptingMode> {
        let mode_str = self.scripting_mode.as_ref()?;
        match ScriptingMode::parse(mode_str) {
            Ok(mode) => Some(mode),
            Err(e) => {
                warn!("Invalid scripting mode in settings, ignoring: {}", e);
                None
            }
        }
    }
}
