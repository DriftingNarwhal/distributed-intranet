//! Call signalling and blind media relay — Real-Time Spec §1.3–1.4, §2.2.
//!
//! # What these close
//!
//! Call keying, topology renegotiation and relay selection were all implemented
//! and tested against calls that existed entirely inside one process. The
//! central claim of §2 — that a relay is *architecturally incapable* of
//! decrypting what it forwards, "not merely asked not to" — is a claim about
//! what happens on a wire between three nodes, and could not be tested at all
//! until frames actually crossed one.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_realtime::{
    CallId, CallKey, CallKeyEnvelope, MediaEnvelope, RenegotiationTrigger, SignalBody, Topology,
    TopologyProposal,
};
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32]).identity_for(&NETWORK).unwrap()
}

fn genesis(founder: &PerNetworkIdentity) -> LogEntry {
    LogEntry::create(
        founder,
        None,
        Timestamp::from_millis(0),
        EntryBody::Genesis {
            network: NETWORK,
            policy: NetworkPolicy::conservative_default(),
            everyone_capabilities: [Capability::ReadContent].into_iter().collect(),
        },
    )
}

fn admit(
    founder: &PerNetworkIdentity,
    parent: intranet_crypto::Hash,
    who: &PerNetworkIdentity,
    at: i64,
) -> LogEntry {
    LogEntry::create(
        founder,
        Some(parent),
        Timestamp::from_millis(at),
        EntryBody::MembershipChange {
            group: GroupId::everyone(),
            identity: who.id(),
            action: MembershipAction::Add { via_invite: None },
        },
    )
}

async fn node(seed: u8) -> (MemberNode, Multiaddr) {
    let identity = identity(seed);
    let mut node = MemberNode::new(&identity).unwrap();
    node.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    let address = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let NodeEvent::Listening(address) = node.next_event().await
                && address.iter().any(|p| matches!(p, Protocol::Tcp(_)))
            {
                return address;
            }
        }
    })
    .await
    .expect("the node should listen");

    (node, address.with(Protocol::P2p(identity.peer_id())))
}

/// Drives three nodes until `done`, or the deadline passes.
async fn drive(
    a: &mut MemberNode,
    b: &mut MemberNode,
    c: &mut MemberNode,
    limit: Duration,
    done: impl Fn(&MemberNode, &MemberNode, &MemberNode) -> bool,
) -> bool {
    tokio::time::timeout(limit, async {
        loop {
            if done(a, b, c) {
                return true;
            }
            tokio::select! {
                _ = a.next_event() => {}
                _ = b.next_event() => {}
                _ = c.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Three connected nodes that agree on governance: caller, callee, relay.
async fn trio() -> (MemberNode, MemberNode, MemberNode) {
    let founder = identity(1);
    let (mut caller, _) = node(1).await;
    let (mut callee, callee_addr) = node(2).await;
    let (mut relay, relay_addr) = node(3).await;

    let root = caller.append_entry(genesis(&founder)).unwrap();
    let next = caller
        .append_entry(admit(&founder, root, &identity(2), 5))
        .unwrap();
    caller
        .append_entry(admit(&founder, next, &identity(3), 6))
        .unwrap();

    caller.dial_candidates([callee_addr.clone()]).unwrap();
    caller.dial_candidates([relay_addr.clone()]).unwrap();
    callee.dial_candidates([relay_addr]).unwrap();

    assert!(
        drive(&mut caller, &mut callee, &mut relay, Duration::from_secs(25), |a, b, c| {
            a.governance_log().len() == 3
                && b.governance_log().len() == 3
                && c.governance_log().len() == 3
        })
        .await,
        "all three should agree on governance"
    );

    (caller, callee, relay)
}

/// Waits for the callee's next media frame.
async fn await_media(
    receiver: &mut MemberNode,
    a: &mut MemberNode,
    b: &mut MemberNode,
) -> Option<MediaEnvelope> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NodeEvent::MediaReceived { envelope } = event {
                        return Some(envelope);
                    }
                }
                _ = a.next_event() => {}
                _ = b.next_event() => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
}

#[tokio::test]
async fn a_call_key_reaches_the_callee_and_opens_media() {
    // §1.3 end to end: the key travels sealed under a pairwise secret derived
    // from the two identities, and the callee can then open frames the caller
    // sealed. Nothing about this depends on the transport's own encryption —
    // that is the point, and it is what makes §2 possible.
    let (mut caller, mut callee, mut relay) = trio().await;
    let caller_identity = identity(1);
    let callee_identity = identity(2);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();
    let envelope =
        CallKeyEnvelope::seal(&caller_identity, &callee_identity.id(), call, &key).unwrap();

    caller.send_signal(
        callee_identity.id(),
        &caller_identity,
        SignalBody::Invite { envelope },
    );

    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = callee.next_event() => {
                    if let NodeEvent::SignalReceived { signal } = event {
                        return Some(signal);
                    }
                }
                _ = caller.next_event() => {}
                _ = relay.next_event() => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
    .expect("the invite should arrive");

    let SignalBody::Invite { envelope } = received.body else {
        panic!("expected an invite");
    };
    let callee_key = envelope.open(&callee_identity).unwrap();
    assert_eq!(callee_key.fingerprint(), key.fingerprint());

    // And the key actually works on media the caller sealed.
    let frame = key.seal_frame(&call, 1, b"hello, can you hear me");
    caller.send_media(
        callee_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: callee_identity.id(),
            frame,
        },
    );

    let arrived = await_media(&mut callee, &mut caller, &mut relay)
        .await
        .expect("the frame should arrive");
    assert_eq!(
        callee_key.open_frame(&call, &arrived.frame).unwrap(),
        b"hello, can you hear me"
    );
}

#[tokio::test]
async fn a_relay_forwards_media_it_cannot_read() {
    // The central claim of §2.2, tested where it has to be true: on the wire,
    // with a third node in the media path.
    //
    // Three things are asserted together, because any one alone is weak. The
    // frame reaches the callee *through* the relay. The relay observes that it
    // forwarded something. And the relay, holding the ciphertext and the call
    // id, cannot produce the plaintext — not because it declines to, but because
    // no key it could construct opens it.
    let (mut caller, mut callee, mut relay) = trio().await;
    let caller_identity = identity(1);
    let callee_identity = identity(2);
    let relay_identity = identity(3);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();
    let envelope =
        CallKeyEnvelope::seal(&caller_identity, &callee_identity.id(), call, &key).unwrap();

    // The relay agrees to carry the call. This is the entirety of what it is
    // told: the call id and who is in it.
    relay.relay_call(call, [caller_identity.id(), callee_identity.id()]);
    assert!(relay.is_relaying(&call));

    let plaintext = b"this must never reach the relay in the clear";
    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: callee_identity.id(),
            frame: key.seal_frame(&call, 1, plaintext),
        },
    );

    let mut forwarded = false;
    let arrived = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = callee.next_event() => {
                    if let NodeEvent::MediaReceived { envelope } = event {
                        return Some(envelope);
                    }
                }
                event = relay.next_event() => {
                    if let NodeEvent::MediaForwarded { call: got, .. } = event
                        && got == call
                    {
                        forwarded = true;
                    }
                }
                _ = caller.next_event() => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
    .expect("the frame should reach the callee through the relay");

    assert!(forwarded, "the relay should have observed forwarding it");
    assert_eq!(
        key.open_frame(&call, &arrived.frame).unwrap(),
        plaintext,
        "the callee should read exactly what the caller sent"
    );

    // The relay was never a recipient of the key, and cannot become one: the
    // envelope is sealed to the callee under a secret only the caller and callee
    // can derive.
    assert!(
        envelope.open(&relay_identity).is_err(),
        "a relay must not be able to open a key envelope addressed to a participant"
    );
}

#[tokio::test]
async fn a_relay_refuses_to_forward_for_a_call_it_never_agreed_to_carry() {
    // Without this a media relay is an open reflector: anyone knowing its
    // address could have it forward arbitrary traffic to arbitrary members, at
    // the relay's bandwidth expense and with the relay's address on it.
    let (mut caller, mut callee, mut relay) = trio().await;
    let caller_identity = identity(1);
    let callee_identity = identity(2);
    let relay_identity = identity(3);

    let key = CallKey::generate().unwrap();

    // Control first, so a silent drop cannot be mistaken for enforcement. The
    // relay carries *this* call, and the frame gets through — which establishes
    // that the path works and the caller can reach the relay at all.
    let carried = CallId::generate().unwrap();
    relay.relay_call(carried, [caller_identity.id(), callee_identity.id()]);
    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call: carried,
            from: caller_identity.id(),
            to: callee_identity.id(),
            frame: key.seal_frame(&carried, 1, b"control"),
        },
    );
    assert!(
        await_media(&mut callee, &mut caller, &mut relay).await.is_some(),
        "precondition: the relay does forward for a call it agreed to carry"
    );

    let call = CallId::generate().unwrap();
    // Deliberately no `relay_call` for this one — the relay never agreed.
    assert!(!relay.is_relaying(&call));

    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: callee_identity.id(),
            frame: key.seal_frame(&call, 1, b"unsolicited"),
        },
    );

    let leaked = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            tokio::select! {
                event = callee.next_event() => {
                    if matches!(event, NodeEvent::MediaReceived { .. }) {
                        return true;
                    }
                }
                event = relay.next_event() => {
                    if matches!(event, NodeEvent::MediaForwarded { .. }) {
                        return true;
                    }
                }
                _ = caller.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        !leaked,
        "a relay must drop traffic for a call it never agreed to carry"
    );
}

#[tokio::test]
async fn a_relay_will_not_forward_to_a_non_participant() {
    // The participant set is not decoration. A relay that forwarded to whoever
    // the `to` field named could be pointed at any member of the network by
    // anyone already in a call it carries.
    let (mut caller, mut callee, mut relay) = trio().await;
    let caller_identity = identity(1);
    let callee_identity = identity(2);
    let relay_identity = identity(3);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();

    // Control: with the callee in the participant set, the frame is forwarded.
    // Same call, same route, same everything except who the relay was told is
    // in it — so what the assertion below observes is the participant check and
    // not some unrelated failure to deliver.
    relay.relay_call(call, [caller_identity.id(), callee_identity.id()]);
    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: callee_identity.id(),
            frame: key.seal_frame(&call, 1, b"control"),
        },
    );
    assert!(
        await_media(&mut callee, &mut caller, &mut relay).await.is_some(),
        "precondition: the relay forwards to a participant"
    );

    // Now the callee is no longer a participant as far as the relay was told.
    relay.relay_call(call, [caller_identity.id(), relay_identity.id()]);

    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: callee_identity.id(),
            frame: key.seal_frame(&call, 1, b"redirected"),
        },
    );

    let leaked = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            tokio::select! {
                event = callee.next_event() => {
                    if matches!(event, NodeEvent::MediaReceived { .. }) {
                        return true;
                    }
                }
                _ = relay.next_event() => {}
                _ = caller.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        !leaked,
        "a frame addressed outside the call's participant set must not be forwarded"
    );
}

#[tokio::test]
async fn a_topology_proposal_reaches_the_other_participant() {
    // §1.4 step 2: renegotiation reuses the signalling channel rather than
    // introducing separate infrastructure. This is the wire half of the
    // trigger-propose-converge loop whose logic `CallSession` already holds.
    let (mut caller, mut callee, mut relay) = trio().await;
    let caller_identity = identity(1);
    let callee_identity = identity(2);
    let relay_identity = identity(3);

    let call = CallId::generate().unwrap();
    let proposal = TopologyProposal {
        proposer: caller_identity.id(),
        topology: Topology::Relayed {
            relay: relay_identity.id(),
        },
        trigger: RenegotiationTrigger::ThresholdReached,
        proposed_at: Timestamp::from_millis(500),
    };

    caller.send_signal(
        callee_identity.id(),
        &caller_identity,
        SignalBody::Propose {
            call,
            proposal: proposal.clone(),
        },
    );

    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = callee.next_event() => {
                    if let NodeEvent::SignalReceived { signal } = event {
                        return Some(signal);
                    }
                }
                _ = caller.next_event() => {}
                _ = relay.next_event() => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
    .expect("the proposal should arrive");

    let SignalBody::Propose {
        call: got_call,
        proposal: got,
    } = received.body
    else {
        panic!("expected a proposal");
    };
    assert_eq!(got_call, call);
    assert_eq!(got, proposal);
    assert_eq!(
        received.sender,
        caller_identity.id(),
        "the proposal must be attributable, since §1.4 converges on proposer and timing"
    );
}
