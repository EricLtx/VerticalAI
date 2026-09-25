//! The `vkd` binary: a terminal's way into the daemon. Everything it does is
//! in the `vkd` library beside it, because the Windows service host runs the
//! same code in its own process (`crates/vk-service`).
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    vkd::init_tracing();
    vkd::run(vkd::Args::parse()).await
}
