//! Raddy Core crate
//! Contains core traits, internal configuration model, context, placeholder evaluation,
//! and module registry.

pub mod config;
pub mod context;
pub mod error;
pub mod handler;
pub mod matcher;
pub mod module;
pub mod network;
pub mod placeholder;
pub mod state;

pub use config::{Config, HandlerConfig, HttpApp, HttpServer, MatcherSet, Route};
pub use context::Context;
pub use error::{CoreError, Result};
pub use handler::{Handler, HandlerChain};
pub use matcher::{
    CompiledMatcherSet, HeaderMatcher, HeaderRegexpMatcher, HostMatcher, Matcher, MethodMatcher,
    NotMatcher, PathMatcher, PathRegexpMatcher, QueryMatcher, RemoteIpMatcher,
};
pub use module::{ModuleRegistration, ModuleRegistry};
pub use network::{
    join_network_address, parse_network_address, parse_network_address_with_defaults,
    split_network_address, NetworkAddress,
};
pub use placeholder::{eval_placeholders, PlaceholderProvider, Replacer};
pub use state::AppState;
