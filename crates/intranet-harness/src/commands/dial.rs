//! Dial subcommand with tier assertions — Core Protocol Spec §5.2, Harness §2.4.

use super::{CliResult, parse_network, resolve_identity};
use clap::{Args, ValueEnum};
use intranet_transport::{AddressFamily, ConnectionTier, MemberNode, NodeEvent};
use libp2p::Multiaddr;
use std::time::Duration;

/// The tier a scenario expects a connection to succeed through.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum ExpectedTier {
    /// Any direct connection, either IP family.
    Direct,
    /// Direct over IPv6 specifically.
    DirectIpv6,
    /// Direct over IPv4 specifically.
    DirectIpv4,
    /// Relayed connection upgraded to direct via DCUtR.
    HolePunched,
    /// Sustained relay circuit — the fallback.
    Relayed,
}

impl ExpectedTier {
    fn matches(self, actual: ConnectionTier) -> bool {
        match self {
            Self::Direct => matches!(actual, ConnectionTier::Direct(_)),
            Self::DirectIpv6 => actual == ConnectionTier::Direct(AddressFamily::Ipv6),
            Self::DirectIpv4 => actual == ConnectionTier::Direct(AddressFamily::Ipv4),
            Self::HolePunched => actual == ConnectionTier::HolePunched,
            Self::Relayed => actual == ConnectionTier::Relayed,
        }
    }
}

#[derive(Args)]
pub struct DialArgs {
    /// BIP-39 backup phrase for this node's master seed.
    #[arg(long, conflicts_with = "seed")]
    phrase: Option<String>,
    /// Deterministic seed byte, for reproducible scenarios.
    #[arg(long)]
    seed: Option<u8>,
    /// Network identifier, as hex or a small integer.
    #[arg(long)]
    network: String,
    /// Candidate addresses to dial. Repeatable.
    #[arg(long = "peer", required = true)]
    peers: Vec<String>,
    /// Also listen, so the remote side can dial back and hole-punching can work.
    #[arg(long = "listen")]
    listen: Vec<String>,
    /// Relay to reserve a circuit slot through, so this side is reachable too.
    ///
    /// DCUtR negotiates between two peers, so a hole-punch can only succeed if
    /// *both* sides are reachable through the relay. A scenario expecting tier 2
    /// must pass this on the dialling side as well.
    #[arg(long)]
    relay: Option<String>,
    /// Which tier the connection is expected to succeed through.
    #[arg(long)]
    expect_tier: Option<ExpectedTier>,
    /// How long to wait for a connection.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
    /// Keep running after connecting, so the other side can complete its own test.
    #[arg(long, default_value_t = 0)]
    hold_secs: u64,
}

impl DialArgs {
    pub async fn run(self) -> CliResult {
        let network = parse_network(&self.network)?;
        let identity = resolve_identity(self.phrase.as_deref(), self.seed, &network)?;
        let mut node = MemberNode::new(&identity).map_err(|e| e.to_string())?;

        println!("peer-id: {}", node.peer_id());

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
            let circuit = relay_address.with(libp2p::multiaddr::Protocol::P2pCircuit);
            println!("reserving: {circuit}");
            node.listen_on(circuit).map_err(|e| e.to_string())?;
        }

        let candidates: Vec<Multiaddr> = self
            .peers
            .iter()
            .map(|address| {
                address
                    .parse()
                    .map_err(|e| format!("bad peer address '{address}': {e}"))
            })
            .collect::<Result<_, _>>()?;

        node.dial_candidates(candidates).map_err(|e| e.to_string())?;

        let outcome = tokio::time::timeout(Duration::from_secs(self.timeout_secs), async {
            loop {
                match node.next_event().await {
                    NodeEvent::Connected { peer, tier, address } => {
                        println!("connected: peer={peer} tier={} via={address}", tier.label());
                        // A hole-punch upgrade arrives after the initial relayed
                        // connection, so a relayed result is not final yet —
                        // reporting it immediately would classify every
                        // successful tier-2 connection as tier 3.
                        if !tier.relay_in_data_path() {
                            return (peer, tier);
                        }
                    }
                    NodeEvent::HolePunchSucceeded { peer } => {
                        println!("hole-punch: succeeded peer={peer}");
                        return (peer, ConnectionTier::HolePunched);
                    }
                    NodeEvent::HolePunchFailed { peer } => {
                        println!("hole-punch: failed peer={peer}, staying relayed");
                        return (peer, ConnectionTier::Relayed);
                    }
                    NodeEvent::Listening(address) => {
                        println!("listening: {address}");
                    }
                    NodeEvent::LocallyDiscovered { peers } => {
                        // §5.1: discovery informs address caching only. Printed
                        // so a scenario can assert discovery happened *without*
                        // a connection following from it.
                        for (peer, address) in peers {
                            println!("mdns-discovered: peer={peer} address={address} (not dialled)");
                        }
                    }
                    NodeEvent::Disconnected { peer } => {
                        println!("disconnected: peer={peer}");
                    }
                }
            }
        })
        .await;

        let Ok((peer, tier)) = outcome else {
            return Err(format!(
                "no connection established within {}s",
                self.timeout_secs
            ));
        };

        println!("result: peer={peer} tier={}", tier.label());

        if let Some(expected) = self.expect_tier
            && !expected.matches(tier)
        {
            // The assertion that matters: a connection through the *wrong* tier
            // is a failure, not a pass. A bug that forces everything through the
            // relay fallback still connects, and would otherwise look healthy.
            return Err(format!(
                "expected tier {:?}, got {} \u{2014} a connection through the wrong tier is a \
                 conformance failure, not a success",
                expected,
                tier.label()
            ));
        }

        if self.hold_secs > 0 {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(self.hold_secs);
            while tokio::time::Instant::now() < deadline {
                let _ = tokio::time::timeout(Duration::from_millis(200), node.next_event()).await;
            }
        }

        Ok(())
    }
}
