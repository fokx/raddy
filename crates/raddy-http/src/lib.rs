//! Raddy HTTP engine and server crate
//! Provides the core request routing engine, VirtualHostRouter,
//! static file server handler, Hyper HTTP/1.1 and HTTP/2 connection server,
//! and server coordination.

pub mod error;
pub mod fileserver;
pub mod http3;
pub mod router;
pub mod server;
pub mod service;

pub use error::{HttpServerError, Result};
pub use fileserver::FileServerHandler;
pub use router::{
    compile_virtual_host_router, CompiledRoute, Router, SubrouteHandler, VirtualHostRouter,
};
pub use server::{HttpServerInstance, ServerManager};
pub use service::handle_request;
