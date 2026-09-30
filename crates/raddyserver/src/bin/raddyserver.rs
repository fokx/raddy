#[tokio::main]
async fn main() -> anyhow::Result<()> {
    raddy_server::run_cli().await
}
