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
                // Printed with the rejection count, not just the acceptance one.
                // A sync that accepted nothing because every entry was refused
                // and one that accepted nothing because there was nothing to
                // send are the same line otherwise, and they mean opposite
                // things about whether the network is converging.
                NodeEvent::Synced {
                    peer,
                    accepted,
                    rejected,
                    truncated,
                } => {
                    println!(
                        "synced: peer={peer} accepted={accepted} rejected={rejected} \
                         more={truncated}"
                    );
                }
                NodeEvent::BallotsReceived {
                    peer,
                    vote_id,
                    accepted,
                    rejected,
                    truncated,
                } => {
                    println!(
                        "ballots-received: peer={peer} vote={} accepted={accepted} \
                         rejected={rejected} more={truncated}",
                        vote_id.short()
                    );
                }
                NodeEvent::BallotSyncRefused { peer, vote_id, reason } => {
                    println!(
                        "ballot-sync-refused: peer={peer} vote={} reason={reason}",
                        vote_id.short()
                    );
                }
                NodeEvent::PointerDigest {
                    peer,
                    offered,
                    wanted,
                    truncated,
                } => {
                    println!(
                        "pointer-digest: peer={peer} offered={offered} wanted={wanted} \
                         more={truncated}"
                    );
                }
                NodeEvent::PointersReceived {
                    peer,
                    accepted,
                    rejected,
                    wrappings,
                    truncated,
                } => {
                    println!(
                        "pointers-received: peer={peer} accepted={accepted} \
                         rejected={rejected} wrappings={wrappings} more={truncated}"
                    );
                }
                NodeEvent::PointerSyncRefused { peer, reason } => {
                    println!("pointer-sync-refused: peer={peer} reason={reason}");
                }
                // Joins are surfaced and never answered, for the same reason
                // key deliveries are not: admitting somebody to a network is
                // the operator's decision, not a connectivity harness's.
                NodeEvent::JoinRequested { peer, joiner, invite, .. } => {
                    println!(
                        "join-requested: peer={peer} joiner={} invite={} (not answered)",
                        joiner.short(),
                        invite.short()
                    );
                }
                NodeEvent::Admitted { peer, entry } => {
                    println!("admitted: peer={peer} entry={}", entry.short());
                }
                NodeEvent::AwaitingAdmission { peer } => {
                    println!("awaiting-admission: peer={peer}");
                }
                NodeEvent::JoinRefused { peer, reason } => {
                    println!("join-refused: peer={peer} reason={reason}");
                }
                // Key delivery is surfaced but never answered here. Answering
                // means admitting somebody to the network's MLS group, which is
                // a decision for whoever runs the node, not something a
                // connectivity harness should make on their behalf — so the
                // line records the request and the requester goes unanswered.
                NodeEvent::EpochKeyRequested { peer, requester, .. } => {
                    println!(
                        "epoch-key-requested: peer={peer} requester={} (not answered)",
                        requester.short()
                    );
                }
                NodeEvent::EpochKeyDelivered {
                    peer,
                    rotation_ref,
                    historical_keys,
                } => {
                    println!(
                        "epoch-key-delivered: peer={peer} rotation={} history={historical_keys}",
                        rotation_ref.short()
                    );
                }
                NodeEvent::EpochKeyUnavailable { peer, reason } => {
                    println!("epoch-key-unavailable: peer={peer} reason={reason}");
                }
                NodeEvent::LedgerSynced {
                    peer,
                    accepted,
                    rejected,
                    truncated,
                } => {
                    println!(
                        "ledger-synced: peer={peer} accepted={accepted} rejected={rejected} \
                         more={truncated}"
                    );
                }
                NodeEvent::ChunkReceived { peer, cid, bytes } => {
                    println!("chunk-received: peer={peer} cid={} bytes={bytes}", cid.short());
                }
                NodeEvent::ChunkUnavailable {
                    peer,
                    cid,
                    reason,
                    counted_against_peer,
                } => {
                    println!(
                        "chunk-unavailable: peer={peer} cid={} reason={reason} \
                         counted={counted_against_peer}",
                        cid.short()
                    );
                }
                NodeEvent::ProvidersFound {
                    cid,
                    providers,
                    holder_count,
                } => {
                    println!(
                        "providers: cid={} holders={holder_count} [{}]",
                        cid.short(),
                        providers
                            .iter()
                            .map(|p| p.short())
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
                NodeEvent::FetchComplete {
                    received,
                    unavailable,
                } => {
                    // Both halves, because a partial fetch is a real outcome and
                    // "the fetch finished" alone would hide which chunks are
                    // actually missing.
                    println!(
                        "fetch-complete: received={} unavailable={}",
                        received.len(),
                        unavailable.len()
                    );
                }
                NodeEvent::CollectionProviders {
                    collection_id,
                    providers,
                } => {
                    println!(
                        "collection-providers: id={} count={}",
                        collection_id.short(),
                        providers.len()
                    );
                }
                NodeEvent::CollectionEnumerated {
                    collection_id,
                    peer,
                    payloads,
                    truncated,
                } => {
                    println!(
                        "collection-entries: id={} peer={peer} entries={} more={truncated}",
                        collection_id.short(),
                        payloads.len()
                    );
                }
                NodeEvent::SignalReceived { signal } => {
                    println!("call-signal: from={} kind={}",
                        signal.sender.short(),
                        match &signal.body {
                            intranet_realtime::SignalBody::Invite { .. } => "invite",
                            intranet_realtime::SignalBody::Propose { .. } => "propose",
                            intranet_realtime::SignalBody::Leave { .. } => "leave",
                        });
                }
                NodeEvent::MediaReceived { envelope } => {
                    // Bytes and sequence only. Printing anything derived from
                    // the frame's contents would require opening it, which this
                    // layer neither can nor should do.
                    println!(
                        "call-media: call={} from={} seq={} bytes={}",
                        envelope.call.short(),
                        envelope.from.short(),
                        envelope.frame.sequence,
                        envelope.frame.ciphertext.len()
                    );
                }
                NodeEvent::MediaForwarded { call, from, to } => {
                    // Every recipient, not a count: the fan-out set is the
                    // routing metadata §2.2 says a relay operator may see, and
                    // its size is the amplification this node agreed to when it
                    // took the call (§2.2.1).
                    println!(
                        "call-relayed: call={} from={} to={}",
                        call.short(),
                        from.short(),
                        to.iter().map(|id| id.short()).collect::<Vec<_>>().join(",")
                    );
                }
                NodeEvent::MediaRefused { call, from, reason } => {
                    // Printed, not swallowed. A run of these is what "I
                    // volunteered more bandwidth than I have" looks like from
                    // inside the node, and it is invisible any other way.
                    println!(
                        "call-refused: call={} from={} reason={}",
                        call.short(),
                        from.short(),
                        reason
                    );
                }
                NodeEvent::SyncFailed { peer, error } => {
                    println!("sync-failed: peer={peer} error={error}");
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
                // Emitted only by a relay, but the event type is shared. Handled
                // explicitly rather than with a catch-all: a wildcard here is how
                // a future variant goes unnoticed, which is the failure mode that
                // hid the relay's missing external address.
                NodeEvent::DialFailed { peer, error } => {
                    match peer {
                        Some(peer) => println!("dial-failed: peer={peer} error={error}"),
                        None => println!("dial-failed: error={error}"),
                    }
                }
                NodeEvent::ReservationGranted { peer } => {
                    println!("reservation-granted: peer={peer}");
                }
                NodeEvent::ReservationDenied { peer } => {
                    println!("reservation-denied: peer={peer}");
                }
                NodeEvent::ReservationReleased { peer } => {
                    println!("reservation-released: peer={peer}");
                }
            }
        }

        Ok(())
    }
}
