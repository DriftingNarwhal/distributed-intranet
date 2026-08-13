//! Identity subcommands — Core Protocol Spec §1.

use super::{CliResult, parse_network, resolve_identity};
use clap::Subcommand;
use intranet_identity::MasterSeed;

#[derive(Subcommand)]
pub enum IdentityCommand {
    /// Generate a new master identity and print its backup phrase.
    New,

    /// Derive and print a per-network identity and its libp2p PeerId.
    Derive {
        /// BIP-39 backup phrase for the master seed.
        #[arg(long, conflicts_with = "seed")]
        phrase: Option<String>,
        /// Deterministic seed byte, for reproducible multi-node scenarios.
        #[arg(long)]
        seed: Option<u8>,
        /// Network identifier, as hex or a small integer.
        #[arg(long)]
        network: String,
    },

    /// Show that one master seed is unlinkable across two networks.
    ///
    /// Prints both per-network identities and PeerIds so a scenario can assert
    /// they share nothing — the observable half of §1.2's guarantee.
    Unlinkability {
        /// Deterministic seed byte.
        #[arg(long, default_value_t = 1)]
        seed: u8,
        /// First network.
        #[arg(long, default_value = "1")]
        network_a: String,
        /// Second network.
        #[arg(long, default_value = "2")]
        network_b: String,
    },
}

impl IdentityCommand {
    pub fn run(self) -> CliResult {
        match self {
            Self::New => {
                let master = MasterSeed::generate().map_err(|e| e.to_string())?;
                let phrase = master.to_backup_phrase().map_err(|e| e.to_string())?;
                println!("backup-phrase: {phrase}");
                println!(
                    "note: this phrase is the entire identity across every network; \
                     it is never transmitted and cannot be recovered if lost"
                );
                Ok(())
            }

            Self::Derive {
                phrase,
                seed,
                network,
            } => {
                let network = parse_network(&network)?;
                let identity = resolve_identity(phrase.as_deref(), seed, &network)?;
                println!("network:  {network}");
                println!("identity: {}", identity.id());
                println!("peer-id:  {}", identity.peer_id());
                Ok(())
            }

            Self::Unlinkability {
                seed,
                network_a,
                network_b,
            } => {
                let a = parse_network(&network_a)?;
                let b = parse_network(&network_b)?;
                let here = resolve_identity(None, Some(seed), &a)?;
                let there = resolve_identity(None, Some(seed), &b)?;

                println!("network-a-identity: {}", here.id());
                println!("network-a-peer-id:  {}", here.peer_id());
                println!("network-b-identity: {}", there.id());
                println!("network-b-peer-id:  {}", there.peer_id());

                if here.id() == there.id() || here.peer_id() == there.peer_id() {
                    return Err(
                        "identities or peer ids are shared across networks: unlinkability is broken"
                            .into(),
                    );
                }
                println!("result: distinct in both key and transport layers");
                Ok(())
            }
        }
    }
}
