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

pub use config::{
    Config, HandlerConfig, HttpApp, HttpServer, LETS_ENCRYPT_PRODUCTION, LETS_ENCRYPT_STAGING,
    MatcherSet, Route, ZEROSSL_PRODUCTION, resolve_acme_ca,
};
pub use context::Context;
pub use error::{CoreError, Result};
pub use handler::{Handler, HandlerChain};
pub use matcher::{
    CompiledMatcherSet, ExpressionMatcher, HeaderMatcher, HeaderRegexpMatcher, HostMatcher,
    Matcher, MethodMatcher, NotMatcher, PathMatcher, PathRegexpMatcher, QueryMatcher,
    RemoteIpMatcher,
};
pub use module::{ModuleRegistration, ModuleRegistry};
pub use network::{
    NetworkAddress, join_network_address, parse_network_address,
    parse_network_address_with_defaults, split_network_address,
};
pub use placeholder::{PlaceholderProvider, Replacer, eval_placeholders};
pub use state::AppState;
