use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod commands;

#[derive(Parser, Debug)]
#[command(
    name = "raddy",
    version,
    about = "Raddy - Fast, extensible web server in Rust (Caddy compatible)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
        /// Path to the Caddyfile
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Configuration adapter to use (caddyfile, json)
        #[arg(long)]
        adapter: Option<String>,

        /// Format output with nice indentation
        #[arg(short, long, default_value_t = true)]
        pretty: bool,

        /// Validate configuration along with adaptation
        #[arg(short, long)]
        validate: bool,
    },

    /// Formats or normalizes a Caddyfile to canonical syntax
    Fmt {
        /// Path to the Caddyfile
        #[arg(short, long, default_value = "Caddyfile")]
        config: PathBuf,

        /// Overwrite original file in-place
        #[arg(short, long)]
        overwrite: bool,
    },

    /// Lists all installed and registered modules and directives
    #[command(name = "list-modules")]
    ListModules {
        /// Output module list in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Prints runtime environment information
    Environ,

    /// Prints detailed version information
    Version,

    /// Instant zero-config static file server
    #[command(name = "file-server")]
    FileServer {
        /// Address to listen on
        #[arg(short, long, default_value = "127.0.0.1:8000")]
        listen: String,

        /// Root directory to serve
        #[arg(short, long, default_value = ".")]
        root: PathBuf,

        /// Enable directory browsing
        #[arg(short, long)]
        browse: bool,

        /// Enable request access logging
        #[arg(short, long)]
        access_log: bool,
    },

    /// Hashes a password and writes the output
    #[command(name = "hash-password")]
    HashPassword {
        /// The plaintext password to hash
        #[arg(short, long)]
        plaintext: Option<String>,

        /// The hashing algorithm (bcrypt)
        #[arg(short, long, default_value = "bcrypt")]
        algorithm: String,

        /// Cost factor for the algorithm
        #[arg(short, long)]
        cost: Option<u32>,
    },

    /// Instant zero-config HTTP response server
    Respond {
        /// Address to listen on
        #[arg(short, long, default_value = "127.0.0.1:8000")]
        listen: String,

        /// The HTTP status code
        #[arg(short, long, default_value_t = 200)]
        status: u16,

        /// Custom response header (can be used multiple times)
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Enable request access logging
        #[arg(short, long)]
        access_log: bool,

        /// Body content to respond with
        #[arg(default_value = "")]
        body: String,
    },

    /// Instant zero-config reverse proxy server
    #[command(name = "reverse-proxy")]
    ReverseProxy {
        /// Address on which to listen
        #[arg(short, long, default_value = "127.0.0.1:8000")]
        from: String,

        /// Upstream address(es) to proxy to
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
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
        } => {
            commands::run::run_command(
                &config,
                adapter.as_deref(),
                pidfile.as_deref(),
                watch,
                environ,
            )
            .await?;
        }

        Commands::Start {
            config,
            adapter,
            pidfile,
            watch,
        } => {
            commands::daemon::start_command(
                &config,
                adapter.as_deref(),
                pidfile.as_deref(),
                watch,
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
                plaintext,
                Some(&algorithm),
                cost,
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
