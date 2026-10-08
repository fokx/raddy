use crate::error::{CoreError, Result};
use crate::handler::Handler;
use std::collections::HashMap;
use std::sync::Arc;

pub type HandlerFactory = fn(serde_json::Value) -> Result<Arc<dyn Handler>>;

/// A registration entry collected via `inventory`.
pub struct ModuleRegistration {
    pub id: &'static str,
    pub factory: HandlerFactory,
}

inventory::collect!(ModuleRegistration);

/// Registry that resolves module IDs to Handler factories.
pub struct ModuleRegistry {
    factories: HashMap<&'static str, HandlerFactory>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleRegistry {
    pub fn new() -> Self {
        let mut factories = HashMap::new();
        for reg in inventory::iter::<ModuleRegistration> {
            factories.insert(reg.id, reg.factory);
        }
        Self { factories }
    }

    pub fn register(&mut self, id: &'static str, factory: HandlerFactory) {
        self.factories.insert(id, factory);
    }

    pub fn create_handler(&self, id: &str, config: serde_json::Value) -> Result<Arc<dyn Handler>> {
        if let Some(factory) = self.factories.get(id) {
            factory(config)
        } else {
            Err(CoreError::Module(format!(
                "Unknown handler module ID '{}'",
                id
            )))
        }
    }

    pub fn list_modules(&self) -> Vec<&'static str> {
        self.factories.keys().copied().collect()
    }
}
