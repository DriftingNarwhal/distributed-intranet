//! Protocol conformance harness — Reference Test Harness Spec.
//!
//! # What this tool is, and what it deliberately is not
//!
//! A CLI, never a UI, speaking only the vocabulary of the specs: identities,
//! networks, groups, capabilities, invites, connections, tiers. There is no
//! command here that mentions a message, a channel, or a page — application
//! concepts smuggle in product decisions, which is exactly how the earlier
//! chat-app-as-test-harness went wrong, and avoiding that is the reason this
//! tool exists at all.
//!
//! Its centerpiece is cross-NAT connection testing (§2), which is the thing
//! that actually blocked prior progress: validating it previously required a
//! second physical network and another person's cooperation, making it slow,
//! unrepeatable, and impossible to run in CI.
//!
//! # Assertions are tier-specific
//!
//! `dial --expect-tier` fails when a connection succeeds through the *wrong*
//! tier, not merely when none succeeds. A bug that silently forces every
//! connection through the relay fallback is functionally working and defeats
//! the entire point of tiers 1 and 2, so it has to fail the suite.

mod commands;

use clap::{Parser, Subcommand};

/// Protocol conformance harness for the distributed intranet.
#[derive(Parser)]
#[command(name = "intranet-harness", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Identity derivation and inspection (Core Protocol Spec §1).
    #[command(subcommand)]
    Identity(commands::identity::IdentityCommand),

    /// Run a relay and bootstrap node (§5.2–5.5).
    Relay(commands::relay::RelayArgs),

    /// Dial a peer and assert which connection tier succeeded (§5.2, §2.4).
    Dial(commands::dial::DialArgs),

    /// Listen for connections, optionally reserving a relay circuit slot (§5.2).
    Listen(commands::listen::ListenArgs),

    /// Governance log operations (§2.7).
    #[command(subcommand)]
    Governance(commands::governance::GovernanceCommand),
}

/// Initialises logging from `RUST_LOG`.
///
/// Without this `RUST_LOG` is inert and every swarm event the node has no
/// opinion on vanishes. A relay defect that killed tiers 2 and 3 was invisible
/// from the outside for exactly that reason, so this is deliberately wired up
/// before anything else runs.
///
/// Defaults to `warn` so ordinary scenario output stays readable; diagnosis uses
/// `RUST_LOG=intranet_transport=trace,libp2p_dcutr=debug,libp2p_relay=debug`.
fn init_logging() {
    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr)
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_logging();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Identity(command) => command.run(),
        Command::Relay(args) => args.run().await,
        Command::Dial(args) => args.run().await,
        Command::Listen(args) => args.run().await,
        Command::Governance(command) => command.run(),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
