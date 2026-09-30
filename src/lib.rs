use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub mod commands;

#[derive(Parser, Debug)]
#[command(
    name = "raddy",
    version,
    about = "Raddy - Fast, extensible web server in Rust (Caddy compatible)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Runs Raddy with the specified configuration file
    Run {
        /// Path to the Caddyfile or JSON config
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Configuration adapter to use (caddyfile, json)
        #[arg(long)]
        adapter: Option<String>,

        /// Path to file where the process ID will be stored
        #[arg(short, long)]
        pidfile: Option<PathBuf>,

        /// Automatically reload configuration when file changes on disk
        #[arg(short, long)]
        watch: bool,

        /// Print the runtime environment variables on startup
        #[arg(short, long)]
        environ: bool,

        /// ACME directory URL or provider alias (e.g. staging, zerossl)
        #[arg(long = "ca")]
        ca: Option<String>,

        /// Use ACME staging/development CA for testing certificates without rate limits
        #[arg(long = "acme-staging", alias = "staging", alias = "dev")]
        staging: bool,

        /// Enable verbose debug logging for TLS, ACME, and HTTP
        #[arg(long = "debug", short = 'd')]
        debug: bool,
    },

    /// Starts Raddy in the background (daemon mode)
    Start {
        /// Path to the Caddyfile or JSON config
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Configuration adapter to use (caddyfile, json)
        #[arg(long)]
        adapter: Option<String>,

        /// Path to file where the process ID will be stored
        #[arg(short, long)]
        pidfile: Option<PathBuf>,

        /// Automatically reload configuration when file changes on disk
        #[arg(short, long)]
        watch: bool,

        /// ACME directory URL or provider alias (e.g. staging, zerossl)
        #[arg(long = "ca")]
        ca: Option<String>,

        /// Use ACME staging/development CA for testing certificates without rate limits
        #[arg(long = "acme-staging", alias = "staging", alias = "dev")]
        staging: bool,

        /// Enable verbose debug logging for TLS, ACME, and HTTP
        #[arg(long = "debug", short = 'd')]
        debug: bool,
    },

    /// Stops a running Raddy instance via Admin API
    Stop {
        /// Admin API address
        #[arg(short, long, default_value = "http://127.0.0.1:2019")]
        address: String,
    },

    /// Sends a configuration reload request to a running Raddy instance via Admin API
    Reload {
        /// Path to the Caddyfile or JSON config
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Configuration adapter to use (caddyfile, json)
        #[arg(long)]
        adapter: Option<String>,

        /// Admin API address
        #[arg(long, default_value = "http://127.0.0.1:2019")]
        address: String,

        /// Force reload even if configuration appears identical
        #[arg(short, long)]
        force: bool,
    },

    /// Validates a Caddyfile or JSON configuration without starting the server
    Validate {
        /// Path to the Caddyfile or JSON config
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Configuration adapter to use (caddyfile, json)
        #[arg(long)]
        adapter: Option<String>,
    },

    /// Adapts a Caddyfile to Raddy internal JSON configuration (like caddy adapt)
    Adapt {
        /// Path to the Caddyfile or JSON config
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Configuration adapter to use (caddyfile, json)
        #[arg(long)]
        adapter: Option<String>,

        /// Format the JSON configuration with indentation
        #[arg(short, long)]
        pretty: bool,

        /// Validate the adapted configuration
        #[arg(long)]
        validate: bool,
    },

    /// Formats a Caddyfile according to standard formatting rules (like caddy fmt)
    Fmt {
        /// Path to the Caddyfile
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Overwrite the original file in-place instead of printing to stdout
        #[arg(short, long)]
        overwrite: bool,
    },

    /// Lists installed modules and handlers registered with the server
    ListModules {
        /// Output module list in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Prints the runtime environment variables visible to the server
    Environ,

    /// Prints the server version
    Version,

    /// Quick file server (like caddy file-server)
    FileServer {
        /// Listener address
        #[arg(short, long, default_value = "localhost:8080")]
        listen: String,

        /// Root directory of the file server
        #[arg(short, long, default_value = ".")]
        root: PathBuf,

        /// Enable directory browsing
        #[arg(short, long)]
        browse: bool,

        /// Enable request access logging
        #[arg(long = "access-log")]
        access_log: bool,
    },

    /// Hashes a password using bcrypt (like caddy hash-password)
    HashPassword {
        /// Plaintext password to hash
        plaintext: String,

        /// Algorithm (bcrypt)
        #[arg(short, long, default_value = "bcrypt")]
        algorithm: String,

        /// Cost factor for bcrypt (4 to 31, default 10)
        #[arg(short, long, default_value_t = 10)]
        cost: u32,
    },

    /// Quick respond server (like caddy respond)
    Respond {
        /// Listener address
        #[arg(short, long, default_value = "localhost:8080")]
        listen: String,

        /// HTTP status code to return
        #[arg(short, long, default_value_t = 200)]
        status: u16,

        /// Header to send down to client (Key: Value)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Enable request access logging
        #[arg(short, long)]
        access_log: bool,

        /// Response body content
        #[arg(default_value = "")]
        body: String,
    },

    /// Quick reverse proxy (like caddy reverse-proxy)
    ReverseProxy {
        /// Address to listen on (e.g. localhost:8080)
        #[arg(short, long, default_value = "localhost:8080")]
        from: String,

        /// Upstream backend addresses to proxy to
        #[arg(short, long, required = true, num_args = 1..)]
        to: Vec<String>,

        /// Header to send to upstream (header_up)
        #[arg(long = "header-up")]
        headers_up: Vec<String>,

        /// Header to send down to client (header_down)
        #[arg(long = "header-down")]
        headers_down: Vec<String>,

        /// Disable upstream TLS certificate verification
        #[arg(long = "insecure")]
        insecure: bool,

        /// Enable request access logging
        #[arg(short, long)]
        access_log: bool,
    },
}

pub async fn run_cli() -> anyhow::Result<()> {
    let is_debug = std::env::args().any(|arg| arg == "--debug" || arg == "-d")
        || std::env::var("RADDY_DEBUG").map(|v| v == "1" || v == "true").unwrap_or(false)
        || std::env::var("DEBUG").map(|v| v == "1" || v == "true").unwrap_or(false);

    let default_filter = if is_debug {
        "debug,raddy=debug,raddy_tls=debug,raddy_http=debug,raddy_admin=debug,raddy_caddyfile=debug"
    } else {
        "info"
    };

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            adapter,
            pidfile,
            watch,
            environ,
            ca,
            staging,
            debug,
        } => {
            commands::run::run_command(
                &config,
                adapter.as_deref(),
                pidfile.as_deref(),
                watch,
                environ,
                ca,
                staging,
                debug,
            )
            .await?;
        }

        Commands::Start {
            config,
            adapter,
            pidfile,
            watch,
            ca,
            staging,
            debug,
        } => {
            commands::daemon::start_command(
                &config,
                adapter.as_deref(),
                pidfile.as_deref(),
                watch,
                ca,
                staging,
                debug,
            )
            .await?;
        }

        Commands::Stop { address } => {
            commands::daemon::stop_command(&address).await?;
        }

        Commands::Reload {
            config,
            adapter,
            address,
            force,
        } => {
            commands::reload::reload_command(&config, adapter.as_deref(), &address, force).await?;
        }

        Commands::Validate { config, adapter } => {
            commands::config_ops::validate_command(&config, adapter.as_deref())?;
        }

        Commands::Adapt {
            config,
            adapter,
            pretty,
            validate,
        } => {
            commands::config_ops::adapt_command(
                &config,
                adapter.as_deref(),
                pretty,
                validate,
            )?;
        }

        Commands::Fmt { config, overwrite } => {
            commands::config_ops::fmt_command(&config, overwrite)?;
        }

        Commands::ListModules { json } => {
            commands::info::list_modules(json);
        }

        Commands::Environ => {
            commands::info::print_environ();
        }

        Commands::Version => {
            commands::info::print_version();
        }

        Commands::FileServer {
            listen,
            root,
            browse,
            access_log,
        } => {
            commands::run::file_server_command(&listen, &root, browse, access_log).await?;
        }

        Commands::HashPassword {
            plaintext,
            algorithm,
            cost,
        } => {
            commands::hash_password::hash_password_command(
                Some(plaintext),
                Some(&algorithm),
                Some(cost),
            )?;
        }

        Commands::Respond {
            listen,
            status,
            headers,
            access_log,
            body,
        } => {
            commands::run::respond_command(&listen, status, &body, &headers, access_log).await?;
        }

        Commands::ReverseProxy {
            from,
            to,
            headers_up,
            headers_down,
            insecure,
            access_log,
        } => {
            commands::run::reverse_proxy_command(
                &from,
                &to,
                &headers_up,
                &headers_down,
                insecure,
                access_log,
            )
            .await?;
        }
    }

    Ok(())
}
