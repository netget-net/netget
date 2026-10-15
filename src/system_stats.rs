//! System statistics monitoring

use std::sync::Arc;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use tokio::sync::RwLock;

/// GPU stats come from `gfxinfo`, and **not on macOS** — see `get_stats`.
#[cfg(any(all(unix, feature = "gpu", not(target_os = "macos")), all(not(unix), feature = "gpu")))]
use gfxinfo::active_gpu;

/// System statistics (CPU, memory, GPU)
#[derive(Debug, Clone)]
pub struct SystemStats {
    /// CPU usage percentage (0-100)
    pub cpu_usage: f32,
    /// Memory usage in bytes
    pub memory_used: u64,
    /// Total memory in bytes
    pub memory_total: u64,
    /// GPU usage percentage (0-100, None if not available)
    pub gpu_usage: Option<f32>,
    /// GPU memory used in bytes (None if not available)
    pub gpu_memory_used: Option<u64>,
    /// GPU memory total in bytes (None if not available)
    pub gpu_memory_total: Option<u64>,
}

impl Default for SystemStats {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_used: 0,
            memory_total: 0,
            gpu_usage: None,
            gpu_memory_used: None,
            gpu_memory_total: None,
        }
    }
}

impl SystemStats {
    /// Get memory usage percentage
    pub fn memory_percent(&self) -> f32 {
        if self.memory_total == 0 {
            0.0
        } else {
            (self.memory_used as f64 / self.memory_total as f64 * 100.0) as f32
        }
    }

    /// Format memory usage as human-readable string
    pub fn memory_used_str(&self) -> String {
        format_bytes(self.memory_used)
    }

    /// Format total memory as human-readable string
    pub fn memory_total_str(&self) -> String {
        format_bytes(self.memory_total)
    }

    /// Format GPU memory usage as human-readable string
    pub fn gpu_memory_used_str(&self) -> String {
        self.gpu_memory_used
            .map(format_bytes)
            .unwrap_or_else(|| "N/A".to_string())
    }

    /// Format GPU memory total as human-readable string
    pub fn gpu_memory_total_str(&self) -> String {
        self.gpu_memory_total
            .map(format_bytes)
            .unwrap_or_else(|| "N/A".to_string())
    }
}

/// Format bytes as human-readable string (KB, MB, GB, etc.)
///
/// `pub` so `tests/system_stats_test.rs` can exercise it directly — CLAUDE.md
/// forbids unit-test modules in `src/`, so an internal helper has to be
/// reachable to be tested.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", value as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", value, UNITS[unit_index])
    }
}

/// System statistics monitor that updates at most once per second
pub struct SystemStatsMonitor {
    system: Arc<RwLock<System>>,
    last_update: Arc<RwLock<crate::utils::clock::Instant>>,
}

impl SystemStatsMonitor {
    /// Create a new system stats monitor
    pub fn new() -> Self {
        let system = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );

        Self {
            system: Arc::new(RwLock::new(system)),
            last_update: Arc::new(RwLock::new(crate::utils::clock::Instant::now())),
        }
    }

    /// Get current system stats (updates at most once per second)
    pub async fn get_stats(&self) -> SystemStats {
        let now = crate::utils::clock::Instant::now();
        let mut last_update = self.last_update.write().await;

        // Only update if more than 1 second has passed
        if now.duration_since(*last_update).as_secs() >= 1 {
            let mut system = self.system.write().await;
            system.refresh_cpu_all();
            system.refresh_memory();
            *last_update = now;
        }

        // Read stats
        let system = self.system.read().await;

        // Get GPU stats if available (NVIDIA, AMD, Intel — not macOS, see below)
        #[cfg(any(all(unix, feature = "gpu", not(target_os = "macos")), all(not(unix), feature = "gpu")))]
        let (gpu_usage, gpu_memory_used, gpu_memory_total) = {
            // active_gpu() returns Result<Box<dyn Gpu>, _>
            match active_gpu() {
                Ok(gpu) => {
                    let info = gpu.info();

                    // gfxinfo returns 0 for unsupported/unavailable stats
                    let gpu_usage = {
                        let load = info.load_pct();
                        if load > 0 {
                            Some(load as f32)
                        } else {
                            None
                        }
                    };
                    let gpu_memory_used = {
                        let used = info.used_vram();
                        if used > 0 {
                            Some(used)
                        } else {
                            None
                        }
                    };
                    let gpu_memory_total = {
                        let total = info.total_vram();
                        if total > 0 {
                            Some(total)
                        } else {
                            None
                        }
                    };

                    (gpu_usage, gpu_memory_used, gpu_memory_total)
                }
                Err(_) => {
                    // GPU detection failed (no GPU or drivers not available)
                    (None, None, None)
                }
            }
        };

        // No GPU stats: either the feature is off, or this is macOS.
        //
        // **`gfxinfo` 0.1 crashes the process on macOS, and it is not a panic that can be
        // caught.** `MacGpuInfo::load_pct()` calls `gfxinfo::macos::performance_stat`, which
        // over-releases the `CFDictionary` it builds; the extra `CFRelease` raises
        // `EXC_BREAKPOINT`/`SIGTRAP` inside CoreFoundation, bypassing Rust's unwinding entirely.
        // The crash is in a `Drop`, so there is no fallible call to wrap and
        // `catch_unwind` cannot see it.
        //
        // It only ever showed up in the rolling TUI because `run_rolling_tui` (since removed) was the only caller
        // of `get_stats` — the dashboard never asks for GPU stats — and it ticks once a second,
        // so a `--features gpu` build died a second or two after painting. That is what the
        // `crash_restore` handler was catching: the terminal was restored
        // and the process still died.
        //
        // Reporting `N/A` on macOS is what the operator saw anyway on the machines where the
        // stat was unsupported, so nothing is lost that was working. Linux and Windows still get
        // real numbers. Revisit if `gfxinfo` fixes the double release.
        #[cfg(any(all(unix, any(not(feature = "gpu"), target_os = "macos")), all(not(unix), not(feature = "gpu"))))]
        let (gpu_usage, gpu_memory_used, gpu_memory_total) = (None, None, None);

        SystemStats {
            cpu_usage: system.global_cpu_usage(),
            memory_used: system.used_memory(),
            memory_total: system.total_memory(),
            gpu_usage,
            gpu_memory_used,
            gpu_memory_total,
        }
    }
}

impl Default for SystemStatsMonitor {
    fn default() -> Self {
        Self::new()
    }
}
