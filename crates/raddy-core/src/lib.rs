//! Raddy Core crate
//! Contains core traits, internal configuration model, context, placeholder evaluation,
//! and module registry.

pub mod config;
pub mod context;
pub mod error;
pub mod handler;
pub mod matcher;
pub mod module;
pub mod placeholder;
pub mod state;

pub use config::{Config, HttpApp, HttpServer, Route, MatcherSet, HandlerConfig};
pub use context::Context;
pub use error::{CoreError, Result};
pub use handler::{Handler, HandlerChain};
pub use matcher::Matcher;
pub use module::{ModuleRegistration, ModuleRegistry};
pub use placeholder::{eval_placeholders, PlaceholderProvider};
pub use state::AppState;
