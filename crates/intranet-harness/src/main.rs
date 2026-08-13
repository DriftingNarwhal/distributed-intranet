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

#[tokio::main]
async fn main() -> std::process::ExitCode {
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
