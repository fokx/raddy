//! Raddy Admin REST API and Hot Reload engine
//! Provides Caddy-compatible endpoints at localhost:2019 for inspecting,
//! traversing, dynamically mutating, and reloading configuration with zero downtime.

pub mod address;
pub mod api;
pub mod client;
pub mod error;
pub mod path_ops;
pub mod server;
pub mod state;

pub use address::{ParsedAdminAddr, parse_admin_addr};
pub use api::build_admin_router;
pub use client::{AdminClient, AdminResponse};
pub use error::{AdminError, Result};
pub use path_ops::{check_host, origin_allowed, unsynced_config_access};
pub use server::AdminServer;
pub use state::AppState;
