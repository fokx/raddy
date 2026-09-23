use std::sync::Arc;
use arc_swap::ArcSwap;
use crate::config::Config;

/// Global application state with lock-free atomic hot reload capabilities.
pub struct AppState {
    config: ArcSwap<Config>,
}

impl AppState {
    pub fn new(initial_config: Config) -> Self {
        Self {
            config: ArcSwap::new(Arc::new(initial_config)),
        }
    }

    /// Obtain a reference-counted handle to the current running configuration.
    pub fn config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    /// Atomically swap the running configuration with a new one.
    pub fn swap_config(&self, new_config: Config) -> Arc<Config> {
        self.config.swap(Arc::new(new_config))
    }
}
