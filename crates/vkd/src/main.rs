//! `vkd`: the VerticalAI kernel daemon. It opens the store, boots the kernel
//! and serves syscalls on the local endpoint — one daemon per user account.
//!
//! Everything that decides *who* a caller is lives behind the endpoint, in
//! `vk_ipc::server`: this binary only says where the state, the master key and
//! the node's device key come from.
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "vkd", about = "VerticalAI kernel daemon", version)]
struct Args {
    /// State directory (default: this user's local app data; never a synced folder).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long, default_value = "node-1")]
    node_id: String,
    /// Endpoint to listen on (default: this user's named pipe / socket).
    #[arg(long)]
    endpoint: Option<String>,
    /// Master key file, for tests and CI; without it the OS keyring holds it.
    #[arg(long)]
    master_key_file: Option<PathBuf>,
    /// Node device key file, for tests and CI; without it the OS keyring holds it.
    #[arg(long)]
    node_key_file: Option<PathBuf>,
    /// SP1a convenience: enroll this node's own device key at first start, so
    /// the interactive machine can be the human this node knows. SP1b replaces
    /// it with the passkey enrolment ceremony.
    #[arg(long)]
    auto_enroll_node: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let a = Args::parse();
    let state_dir = vk_store::paths::state_dir(a.state_dir)?;
    let key_source = match a.master_key_file {
        Some(p) => vk_store::keys::KeySource::File(p),
        None => vk_store::keys::KeySource::Keyring {
            service: "vk".into(),
            user: "master".into(),
        },
    };
    let mut kernel = vk_kernel::RealKernel::open(&state_dir, key_source, &a.node_id)?;
    if a.auto_enroll_node {
        let source = match a.node_key_file {
            Some(p) => vk_kernel::presence::KeySource::File(p),
            None => vk_kernel::presence::KeySource::Keyring,
        };
        let device = vk_kernel::presence::NodeDevice::load_or_create(source, &a.node_id)?;
        kernel.enroll_node_device(&device)?;
    }
    let report = kernel.boot()?;
    tracing::info!(
        ledger_ok = report.ledger_ok,
        ledger_len = report.ledger_len,
        state_dir = %state_dir.display(),
        "vkd booted"
    );
    let endpoint = a
        .endpoint
        .map(vk_ipc::transport::Endpoint)
        .unwrap_or_else(vk_ipc::transport::default_endpoint);
    tracing::info!(endpoint = %endpoint.0, "vkd listening");
    vk_ipc::server::serve(Arc::new(Mutex::new(kernel)), endpoint).await
}
