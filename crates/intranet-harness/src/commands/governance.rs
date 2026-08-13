//! Governance subcommands — Core Protocol Spec §2.7.

use super::{CliResult, parse_network, resolve_identity};
use clap::Subcommand;
use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GovernanceLog, GovernanceState, LogEntry, NetworkPolicy,
};

#[derive(Subcommand)]
pub enum GovernanceCommand {
    /// Create a network and print the resulting state hash.
    ///
    /// The state hash is the deterministic-replay assertion: two nodes that
    /// replayed the same chain must print the same value, and the harness
    /// treats a mismatch as a hard failure rather than an approximate check.
    Genesis {
        /// Deterministic seed byte for the founder.
        #[arg(long, default_value_t = 1)]
        seed: u8,
        /// Network identifier, as hex or a small integer.
        #[arg(long)]
        network: String,
        /// Grant `everyone` the ability to read content.
        #[arg(long, default_value_t = true)]
        everyone_reads: bool,
    },

    /// Report the bounded-finality thresholds this build enforces.
    ///
    /// Both must be met (§2.7.1). Printing them lets a scenario confirm the
    /// values it is timing against rather than hardcoding them separately and
    /// silently drifting out of step with the implementation.
    Finality,

    /// Demonstrate that capability-free entries cannot grind a branch.
    ///
    /// Builds a fork where the losing side is padded with device enrollments
    /// and confirms the branch with more *capability-gated* actions still wins.
    GrindingCheck {
        /// How many capability-free entries to pad the losing branch with.
        #[arg(long, default_value_t = 20)]
        padding: u32,
    },
}

impl GovernanceCommand {
    pub fn run(self) -> CliResult {
        match self {
            Self::Genesis {
                seed,
                network,
                everyone_reads,
            } => {
                let network = parse_network(&network)?;
                let founder = resolve_identity(None, Some(seed), &network)?;

                let everyone_capabilities = if everyone_reads {
                    vec![Capability::ReadContent]
                } else {
                    Vec::new()
                };

                let genesis = LogEntry::create(
                    &founder,
                    None,
                    Timestamp::from_millis(0),
                    EntryBody::Genesis {
                        network,
                        policy: NetworkPolicy::conservative_default(),
                        everyone_capabilities: everyone_capabilities.into_iter().collect(),
                    },
                );

                let state = GovernanceState::genesis(&genesis).map_err(|e| e.to_string())?;
                println!("network:     {network}");
                println!("founder:     {}", founder.id());
                println!("genesis:     {}", genesis.hash());
                println!("state-hash:  {}", state.state_hash());
                println!("groups:      {}", state.groups.len());
                Ok(())
            }

            Self::Finality => {
                let params = NetworkPolicy::conservative_default().finality;
                println!("k: {} capability-gated actions", params.k);
                println!("T: {} ms", params.t_millis);
                println!("rule: both conditions required, not either");
                Ok(())
            }

            Self::GrindingCheck { padding } => {
                let network = parse_network("1")?;
                let founder = resolve_identity(None, Some(1), &network)?;
                let attacker = resolve_identity(None, Some(2), &network)?;

                let mut log = GovernanceLog::new();
                let genesis = LogEntry::create(
                    &founder,
                    None,
                    Timestamp::from_millis(0),
                    EntryBody::Genesis {
                        network,
                        policy: NetworkPolicy::conservative_default(),
                        everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
                    },
                );
                let root = log.insert(genesis).map_err(|e| e.to_string())?;

                let setup = LogEntry::create(
                    &founder,
                    Some(root),
                    Timestamp::from_millis(5),
                    EntryBody::MembershipChange {
                        group: intranet_governance::GroupId::everyone(),
                        identity: attacker.id(),
                        action: intranet_governance::MembershipAction::Add { via_invite: None },
                    },
                );
                let fork_point = log.insert(setup).map_err(|e| e.to_string())?;

                // Honest branch: two genuine capability-gated actions.
                let mut parent = fork_point;
                let mut honest_tip = fork_point;
                for i in 0..2 {
                    let entry = LogEntry::create(
                        &founder,
                        Some(parent),
                        Timestamp::from_millis(10 + i),
                        EntryBody::DefineGroup {
                            group: intranet_governance::GroupId::new(format!("honest{i}")),
                            capabilities: intranet_governance::CapabilitySet::explicit([
                                Capability::ReadContent,
                            ]),
                        },
                    );
                    parent = log.insert(entry).map_err(|e| e.to_string())?;
                    honest_tip = parent;
                }

                // Attacker branch: capability-free padding.
                let mut parent = fork_point;
                for i in 0..padding {
                    let device_seed = intranet_identity::DeviceSeed::from_entropy([
                        (100 + i % 100) as u8;
                        32
                    ]);
                    let key = device_seed
                        .key_for(&network)
                        .map_err(|e| e.to_string())?;
                    let device = intranet_identity::DevicePublicKey::from_verifying_key(
                        *key.id().verifying_key(),
                    );
                    let certificate = intranet_identity::DeviceCertificate::issue(
                        &attacker,
                        device,
                        format!("grind{i}"),
                        Timestamp::from_millis(100 + i64::from(i)),
                    );
                    let entry = LogEntry::create(
                        &attacker,
                        Some(parent),
                        Timestamp::from_millis(100 + i64::from(i)),
                        EntryBody::DeviceEnrollment(certificate),
                    );
                    parent = log.insert(entry).map_err(|e| e.to_string())?;
                }

                let canonical = log.canonical_chain();
                let tip = canonical.last().copied();

                println!("honest-branch:   2 capability-gated actions");
                println!("attacker-branch: {padding} capability-free entries");
                println!("canonical-tip:   {}", tip.map(|h| h.to_string()).unwrap_or_default());

                if tip == Some(honest_tip) {
                    println!("result: capability-free padding did not win the branch");
                    Ok(())
                } else {
                    Err("branch grinding succeeded: capability-free entries won the fork".into())
                }
            }
        }
    }
}
