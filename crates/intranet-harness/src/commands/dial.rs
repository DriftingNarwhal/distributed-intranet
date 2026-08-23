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
    /// Sustained relay circuit.
    ///
    /// **No conformant scenario should expect this.** §5.2 was corrected to say
    /// there is no third tier: a circuit carries the DCUtR negotiation and is
    /// closed when the upgrade fails. The variant is kept so a scenario can
    /// detect a relayed connection that wrongly persists, which is the defect
    /// the correction exists to prevent and which looks exactly like success.
    Relayed,
    /// No surviving connection to the target — the §5.2 outcome when a pair
    /// cannot hole-punch and has no other path.
    ///
    /// Satisfied two ways, because both are the same fact from different
    /// vantage points: nothing ever connected within the timeout, or a relayed
    /// connection was established for the negotiation and then closed without
    /// upgrading. A scenario asserting this is asserting an *absence*, so it
    /// necessarily costs the full timeout.
    None,
}

impl ExpectedTier {
    fn matches(self, actual: ConnectionTier) -> bool {
        match self {
            Self::Direct => matches!(actual, ConnectionTier::Direct(_)),
            Self::DirectIpv6 => actual == ConnectionTier::Direct(AddressFamily::Ipv6),
            Self::DirectIpv4 => actual == ConnectionTier::Direct(AddressFamily::Ipv4),
            Self::HolePunched => actual == ConnectionTier::HolePunched,
            Self::Relayed => actual == ConnectionTier::Relayed,
            // Handled before this is reached: `None` is a statement about
            // there being no connection, so there is no tier to compare.
            Self::None => false,
        }
    }
}

/// What the dial settled on, which is not always a connection.
///
/// Distinguishing "closed" from "never connected" matters for diagnosis rather
/// than for the assertion: both satisfy [`ExpectedTier::None`], but only the
/// first tells you the negotiation actually happened and the circuit was torn
/// down as §5.2 requires, rather than nothing having reached the peer at all.
enum Settled {
    Connected(libp2p::PeerId, ConnectionTier),
    /// A relayed connection to the target existed and was closed without ever
    /// upgrading — the circuit carried its negotiation and nothing more.
    CircuitClosed(libp2p::PeerId),
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
    /// How long to let a relayed connection try to upgrade before accepting it
    /// as the settled tier.
    ///
    /// A relayed connection is not reported the moment it is established — that
    /// would classify every successful tier-2 connection as tier 3, since a
    /// hole-punch is always relayed first. But a failed hole-punch does not
    /// reliably produce a dcutr event either: when the direct dial fails at the
    /// transport level the attempt is simply abandoned, so waiting for one hangs
    /// until the overall timeout and reports no connection at all — even though
    /// a working tier-3 circuit is open the whole time.
    ///
    /// **This must outlast the transport's own circuit deadline, and the default
    /// is chosen to.** The transport now closes a circuit that has not upgraded
    /// (Core §5.2), which is what makes a §5.2 conformance assertion possible at
    /// all — but only the *later* of the two timers decides what this command
    /// reports. At fifteen seconds against the transport's twenty-five, this
    /// window expired first and reported `relayed` for a circuit that was about
    /// to be closed, so scenarios 4 and 6 failed while the node under test was
    /// behaving correctly. A harness that pre-empts the behaviour it is
    /// measuring reports on itself.
    #[arg(long, default_value_t = 35)]
    upgrade_secs: u64,
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
            // Via `reserve_via_relay` for the same reason as `listen`: a
            // hole punch needs both sides reachable at a port they listen on,
            // and reserving straight after a wildcard bind loses that.
            println!("reserving: {relay_address}/p2p-circuit");
            node.reserve_via_relay(relay_address)
                .await
                .map_err(|e| e.to_string())?;
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

        // The peer this dial is actually about. Taken from the last `/p2p/` of a
        // candidate, which for a circuit address is the target rather than the
        // relay that fronts it.
        //
        // Reserving above opens a *direct connection to the relay itself*, and
        // that fires `Connected` long before the target is reached. Without this
        // filter the relay's own connection wins the race, so every scenario
        // passing `--relay` reports `direct` no matter which tier the target was
        // eventually reached through — which silently defeats the tier assertion
        // that is the entire point of the suite (§2.4).
        // `multiaddr::Iter` is not double-ended, so fold forward and keep the
        // last match rather than reversing.
        let target = candidates.iter().find_map(|address| {
            address.iter().fold(None, |found, part| match part {
                libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
                _ => found,
            })
        });
        if let Some(target) = target {
            println!("target: {target}");
        }
        let is_target = |peer| target.is_none_or(|target| target == peer);

        // A circuit candidate cannot be dialled until this node's own
        // reservation has been granted; doing so fails as an unsupported
        // transport rather than as anything resembling "too early". Reserving
        // only asks, so wait for the answer before dialling.
        //
        // Unconditional rather than only for circuit candidates: a scenario that
        // passes `--relay` intends the relay to be usable, and a direct
        // candidate that succeeds returns immediately anyway.
        if self.relay.is_some() && !node.await_reservation().await {
            println!("reservation: not granted; circuit candidates will fail");
        }

        node.dial_candidates(candidates).map_err(|e| e.to_string())?;

        let upgrade_window = Duration::from_secs(self.upgrade_secs);
        let outcome = tokio::time::timeout(Duration::from_secs(self.timeout_secs), async {
            // Set once a relayed connection to the target exists: the deadline
            // by which it must have been upgraded to count as anything better.
            let mut settle: Option<(tokio::time::Instant, libp2p::PeerId)> = None;
            loop {
                let event = match settle {
                    Some((deadline, peer)) => {
                        match tokio::time::timeout_at(deadline, node.next_event()).await {
                            Ok(event) => event,
                            Err(_) => {
                                println!("relayed: no upgrade within {}s", self.upgrade_secs);
                                return Settled::Connected(peer, ConnectionTier::Relayed);
                            }
                        }
                    }
                    None => node.next_event().await,
                };
                match event {
                    NodeEvent::Connected { peer, tier, address } => {
                        println!("connected: peer={peer} tier={} via={address}", tier.label());
                        // A hole-punch upgrade arrives after the initial relayed
                        // connection, so a relayed result is not final yet —
                        // reporting it immediately would classify every
                        // successful tier-2 connection as tier 3.
                        if is_target(peer) {
                            if !tier.relay_in_data_path() {
                                return Settled::Connected(peer, tier);
                            }
                            // Start the upgrade window on the first relayed
                            // connection to the target, and do not restart it on
                            // later ones.
                            settle.get_or_insert_with(|| {
                                (tokio::time::Instant::now() + upgrade_window, peer)
                            });
                        }
                    }
                    NodeEvent::HolePunchSucceeded { peer } if is_target(peer) => {
                        println!("hole-punch: succeeded peer={peer}");
                        return Settled::Connected(peer, ConnectionTier::HolePunched);
                    }
                    NodeEvent::HolePunchFailed { peer } if is_target(peer) => {
                        // Reported, but deliberately *not* returned on.
                        //
                        // DCUtR has both peers dial simultaneously, and only our
                        // own dial's outcome reaches us as success or failure. If
                        // ours fails while the peer's succeeds, their connection
                        // still arrives here as an ordinary inbound one — so
                        // returning at this point would report `relayed` while a
                        // direct connection was moments away, and would explain a
                        // peer that appears to establish a direct connection we
                        // never see.
                        //
                        // Waiting out the upgrade window instead costs nothing
                        // when the punch has genuinely failed: the window expires
                        // and `relayed` is reported anyway.
                        println!("hole-punch: our dial failed peer={peer}; \
                                  waiting out the upgrade window in case theirs lands");
                        settle.get_or_insert_with(|| {
                            (tokio::time::Instant::now() + upgrade_window, peer)
                        });
                    }
                    NodeEvent::DialFailed { peer, error } => {
                        // The reason a punch failed, which is otherwise invisible:
                        // refused, timed out and never left are different faults.
                        match peer {
                            Some(peer) => println!("dial-failed: peer={peer} error={error}"),
                            None => println!("dial-failed: error={error}"),
                        }
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
                        // §5.2's outcome, and it must not be read as "still
                        // relayed". The transport closes a circuit whose
                        // hole-punch failed, so the settle window would
                        // otherwise expire and report `relayed` for a peer this
                        // node is no longer connected to — asserting the tier
                        // the correction exists to abolish.
                        if is_target(peer) && settle.is_some() {
                            println!("circuit: closed without upgrading");
                            return Settled::CircuitClosed(peer);
                        }
                    }
                    // Hole-punch results for a peer other than the target — the
                    // relay's own connection, typically.
                    _ => {}
                }
            }
        })
        .await;

        // Three outcomes, not two: connected, connected-then-closed, and never
        // connected. The last is a timeout rather than an error whenever the
        // scenario asked for it, since §5.2 makes "these two peers do not
        // connect" a conformant result that a matrix must be able to assert.
        let expects_none = self.expect_tier == Some(ExpectedTier::None);

        let settled = match outcome {
            Ok(settled) => settled,
            Err(_) => {
                println!("result: no connection within {}s", self.timeout_secs);
                if expects_none {
                    println!("expected: none \u{2014} nothing reached the target, as required");
                    return self.hold(node).await;
                }
                return Err(format!(
                    "no connection established within {}s",
                    self.timeout_secs
                ));
            }
        };

        let connected = match settled {
            Settled::CircuitClosed(peer) => {
                println!("result: peer={peer} circuit closed without upgrading");
                if expects_none {
                    println!(
                        "expected: none \u{2014} the circuit carried its negotiation and was \
                         closed, which is what \u{a7}5.2 requires"
                    );
                    return self.hold(node).await;
                }
                return Err(format!(
                    "expected tier {:?}, got no surviving connection \u{2014} the relayed \
                     circuit was closed after the hole punch failed",
                    self.expect_tier
                ));
            }
            Settled::Connected(peer, tier) => (peer, tier),
        };
        let (peer, tier) = connected;

        println!("result: peer={peer} tier={}", tier.label());

        if expects_none {
            // The inverse assertion, and the one that catches a regression of
            // the rule rather than of the code: a pair that must not connect
            // has connected, which under \u{a7}5.2 is a conformance failure however
            // healthy it looks.
            return Err(format!(
                "expected no connection, got {} \u{2014} \u{a7}5.2 says a pair that cannot \
                 hole-punch reaches each other over IPv6 or not at all",
                tier.label()
            ));
        }

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

        self.hold(node).await
    }

    /// Keeps the node running so the other side can finish its own test.
    ///
    /// Reached from every passing path, including the two that pass by *not*
    /// connecting — a peer that exits the moment it decides nothing arrived
    /// would tear its listener down under whichever side is still dialling.
    async fn hold(&self, mut node: MemberNode) -> CliResult {
        if self.hold_secs > 0 {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(self.hold_secs);
            while tokio::time::Instant::now() < deadline {
                let _ = tokio::time::timeout(Duration::from_millis(200), node.next_event()).await;
            }
        }
        Ok(())
    }
}
