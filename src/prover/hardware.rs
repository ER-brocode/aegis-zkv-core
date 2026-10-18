//! Hardware acceleration detector and execution scheduler.

use serde::{Deserialize, Serialize};

/// Hardware capabilities report for zero-knowledge cryptographic acceleration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub logical_cores: usize,
    pub has_avx2: bool,
    pub has_avx512f: bool,
    pub has_neon: bool,
    pub multithreading_enabled: bool,
    pub simd_acceleration: bool,
}

/// Hardware acceleration orchestrator for Aegis ZKV.
pub struct HardwareAccelerator;

impl HardwareAccelerator {
    /// Detects CPU features and builds capabilities report.
    pub fn detect_capabilities() -> HardwareCapabilities {
        let logical_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        #[cfg(target_arch = "x86_64")]
        let (has_avx2, has_avx512f) = {
            (
                is_x86_feature_detected!("avx2"),
                is_x86_feature_detected!("avx512f"),
            )
        };

        #[cfg(not(target_arch = "x86_64"))]
        let (has_avx2, has_avx512f) = (false, false);

        #[cfg(target_arch = "aarch64")]
        let has_neon = true;

        #[cfg(not(target_arch = "aarch64"))]
        let has_neon = false;

        let simd_acceleration = has_avx2 || has_avx512f || has_neon;

        HardwareCapabilities {
            logical_cores,
            has_avx2,
            has_avx512f,
            has_neon,
            multithreading_enabled: cfg!(feature = "parallel"),
            simd_acceleration,
        }
    }

    /// Configures global Rayon threadpool for optimal multi-scalar multiplication (MSM) chunking.
    pub fn configure_threads(num_threads: Option<usize>) {
        #[cfg(feature = "parallel")]
        {
            if let Some(threads) = num_threads {
                let _ = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build_global();
            }
        }
        #[cfg(not(feature = "parallel"))]
        {
            let _ = num_threads;
        }
    }
}
