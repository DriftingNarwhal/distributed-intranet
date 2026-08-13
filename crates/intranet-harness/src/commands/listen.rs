//! Listen subcommand — makes a peer reachable, including via a relay reservation.
//!
//! Tiers 2 and 3 are impossible without this. A NAT'd peer cannot be dialled
//! directly, so before anyone can reach it, it must reserve a slot on a relay
//! and learn its own circuit address (`/…relay…/p2p-circuit/p2p/<self>`). The
//! dialling side then dials that circuit address, and DCUtR either upgrades it
//! to direct (tier 2) or it stays relayed (tier 3).

use super::{CliResult, parse_network, resolve_identity};
use clap::Args;
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use std::time::Duration;

#[derive(Args)]
pub struct ListenArgs {
    /// BIP-39 backup phrase for this node's master seed.
    #[arg(long, conflicts_with = "seed")]
    phrase: Option<String>,
    /// Deterministic seed byte, for reproducible scenarios.
    #[arg(long)]
    seed: Option<u8>,
    /// Network identifier, as hex or a small integer.
    #[arg(long)]
    network: String,
    /// Addresses to listen on directly. Repeatable.
    #[arg(long = "listen")]
    listen: Vec<String>,
    /// Relay to reserve a circuit slot through, as a full multiaddr with peer id.
    #[arg(long)]
    relay: Option<String>,
    /// How long to stay up.
    #[arg(long, default_value_t = 120)]
    hold_secs: u64,
}

impl ListenArgs {
    pub async fn run(self) -> CliResult {
        let network = parse_network(&self.network)?;
        let identity = resolve_identity(self.phrase.as_deref(), self.seed, &network)?;
        let mut node = MemberNode::new(&identity).map_err(|e| e.to_string())?;
        let me = node.peer_id();

        println!("peer-id: {me}");

        for address in &self.listen {
            let address: Multiaddr = address
                .parse()
                .map_err(|e| format!("bad listen address '{address}': {e}"))?;
            node.listen_on(address).map_err(|e| e.to_string())?;
        }

        if let Some(relay) = &self.relay {
            let relay_address: Multiaddr = relay
                .parse()
                .map_err(|e| format!("bad relay address '{relay}': {e}"))?;

            // Asking for a reservation is what makes this node reachable from
            // behind its NAT. It goes through `reserve_via_relay` rather than a
            // bare `listen_on` because the reservation connection must originate
            // from a port this node listens on — see that method for why binding
            // a wildcard address and reserving immediately silently breaks
            // hole-punching while leaving every other tier working.
            println!("reserving: {relay_address}/p2p-circuit");
            node.reserve_via_relay(relay_address)
                .await
                .map_err(|e| e.to_string())?;
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(self.hold_secs);
        while tokio::time::Instant::now() < deadline {
            let Ok(event) =
                tokio::time::timeout(Duration::from_millis(500), node.next_event()).await
            else {
                continue;
            };
            match event {
                NodeEvent::Listening(address) => {
                    // A scenario greps this line for the circuit address to dial.
                    println!("listening: {address}/p2p/{me}");
                }
                NodeEvent::Connected { peer, tier, .. } => {
                    println!("connected: peer={peer} tier={}", tier.label());
                }
                NodeEvent::HolePunchSucceeded { peer } => {
                    println!("hole-punch: succeeded peer={peer}");
                }
                NodeEvent::HolePunchFailed { peer } => {
                    println!("hole-punch: failed peer={peer}");
                }
                NodeEvent::LocallyDiscovered { peers } => {
                    for (peer, address) in peers {
                        println!("mdns-discovered: peer={peer} address={address} (not dialled)");
                    }
                }
                NodeEvent::Disconnected { peer } => {
                    println!("disconnected: peer={peer}");
                }
                // The address a peer reports seeing us at is exactly what DCUtR
                // will hand to a remote peer to dial. Printing it is what makes
                // a hole-punch failure diagnosable: if this is not a port we
                // listen on, tier 2 cannot work and nothing else will say so.
                NodeEvent::ExternalAddressCandidate { address } => {
                    println!("external-candidate: {address}");
                }
                NodeEvent::ExternalAddressConfirmed { address } => {
                    println!("external-confirmed: {address}");
                }
            }
        }

        Ok(())
    }
}
