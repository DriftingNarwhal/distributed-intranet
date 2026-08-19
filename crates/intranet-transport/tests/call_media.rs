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
    CallId, CallKey, CallKeyEnvelope, MediaEnvelope, Recipient, RenegotiationTrigger, SignalBody,
    Topology,
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

/// Drives four nodes until `done`, or the deadline passes.
async fn drive4(
    nodes: &mut [MemberNode; 4],
    limit: Duration,
    done: impl Fn(&[MemberNode; 4]) -> bool,
) -> bool {
    tokio::time::timeout(limit, async {
        loop {
            if done(nodes) {
                return true;
            }
            let [a, b, c, d] = nodes;
            tokio::select! {
                _ = a.next_event() => {}
                _ = b.next_event() => {}
                _ = c.next_event() => {}
                _ = d.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// Four connected nodes that agree on governance: caller, two callees, relay.
///
/// Three participants is the smallest call where fan-out and the per-recipient
/// form differ at all — with two, "everyone but the sender" is one node and the
/// two forms cost the same. So this is the minimum honest test of §1.1's claim.
async fn quartet() -> [MemberNode; 4] {
    let founder = identity(1);
    let (caller, caller_addr) = node(1).await;
    let (callee_a, a_addr) = node(2).await;
    let (relay, relay_addr) = node(3).await;
    let (callee_b, b_addr) = node(4).await;
    let mut nodes = [caller, callee_a, relay, callee_b];

    let mut parent = nodes[0].append_entry(genesis(&founder)).unwrap();
    for (seed, at) in [(2u8, 5i64), (3, 6), (4, 7)] {
        parent = nodes[0]
            .append_entry(admit(&founder, parent, &identity(seed), at))
            .unwrap();
    }

    // Dialled pairwise rather than through the relay: governance is pull-based,
    // so a node with no connection to a holder of the log simply never learns
    // it, and a media test that failed for that reason would look like a
    // forwarding bug.
    let addrs = [caller_addr, a_addr, relay_addr, b_addr];
    for (i, node) in nodes.iter_mut().enumerate() {
        for addr in addrs.iter().skip(i + 1) {
            node.dial_candidates([addr.clone()]).unwrap();
        }
    }

    assert!(
        drive4(&mut nodes, Duration::from_secs(30), |n| n
            .iter()
            .all(|node| node.governance_log().len() == 4))
        .await,
        "all four should agree on governance"
    );

    nodes
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
            to: Recipient::One(callee_identity.id()),
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
            to: Recipient::One(callee_identity.id()),
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
async fn a_relay_fans_one_envelope_out_to_the_rest_of_the_call() {
    // Real-Time Spec §2.2.1, and the reason a relay exists at all (§1.1). The
    // claim under test is a ratio: the sender emits **one** envelope per frame
    // and the relay emits N−1, regardless of N. Before this landed the sender
    // emitted N−1 itself and the relay emitted one each — a relay that saved
    // nobody anything and added a hop while not saving it.
    let [mut caller, mut callee_a, mut relay, mut callee_b] = quartet().await;
    let caller_identity = identity(1);
    let a_identity = identity(2);
    let relay_identity = identity(3);
    let b_identity = identity(4);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();
    relay.relay_call(
        call,
        [caller_identity.id(), a_identity.id(), b_identity.id()],
    );

    let plaintext = b"one envelope in, two out";
    // One send. Not one per recipient — that is the whole measurement.
    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call, 1, plaintext),
        },
    );

    let mut got_a = None;
    let mut got_b = None;
    let mut forwarded_to = Vec::new();
    let delivered = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            tokio::select! {
                event = callee_a.next_event() => {
                    if let NodeEvent::MediaReceived { envelope } = event {
                        got_a = Some(envelope);
                    }
                }
                event = callee_b.next_event() => {
                    if let NodeEvent::MediaReceived { envelope } = event {
                        got_b = Some(envelope);
                    }
                }
                event = relay.next_event() => {
                    if let NodeEvent::MediaForwarded { call: got, to, .. } = event
                        && got == call
                    {
                        forwarded_to = to;
                    }
                }
                _ = caller.next_event() => {}
            }
            if got_a.is_some() && got_b.is_some() {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        delivered,
        "one envelope from the sender must reach every other participant"
    );
    let (a, b) = (got_a.unwrap(), got_b.unwrap());
    assert_eq!(key.open_frame(&call, &a.frame).unwrap(), plaintext);
    assert_eq!(key.open_frame(&call, &b.frame).unwrap(), plaintext);

    // §2.2.1 rule 4. Each copy is readdressed to the participant receiving it,
    // so what arrives is a named envelope — a participant never holds a fan-out
    // envelope, which is what leaves a forwarding loop nowhere to start.
    assert_eq!(a.to, Recipient::One(a_identity.id()));
    assert_eq!(b.to, Recipient::One(b_identity.id()));
    assert_eq!(a.from, caller_identity.id(), "the sender is not rewritten");

    // The ratio, asserted rather than described: one in, N−1 out, and the sender
    // is not one of them.
    forwarded_to.sort();
    let mut expected = vec![a_identity.id(), b_identity.id()];
    expected.sort();
    assert_eq!(
        forwarded_to, expected,
        "the relay forwards to the participant set minus the sender"
    );

    // The relay still cannot read a byte of what it multiplied.
    assert!(
        CallKeyEnvelope::seal(&caller_identity, &a_identity.id(), call, &key)
            .unwrap()
            .open(&relay_identity)
            .is_err(),
        "fanning out must not have given the relay a way in"
    );
}

#[tokio::test]
async fn a_relay_refuses_to_fan_out_for_a_sender_outside_the_call() {
    // Under the named form the relay checked both ends, and the recipient check
    // was the one doing the work. Fan-out removes that check entirely — there is
    // no recipient in the envelope to check — so the sender check is now the
    // only thing standing between a carried call's id and having this node spray
    // a frame at every participant. Anyone who learns a call id could otherwise
    // do it.
    let [mut caller, mut callee_a, mut relay, mut callee_b] = quartet().await;
    let caller_identity = identity(1);
    let a_identity = identity(2);
    let relay_identity = identity(3);
    let b_identity = identity(4);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();

    // Control first, so a silent drop cannot be mistaken for enforcement: the
    // relay does fan out for this call when the sender is in it.
    relay.relay_call(call, [caller_identity.id(), a_identity.id()]);
    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call, 1, b"control"),
        },
    );
    assert!(
        await_media(&mut callee_a, &mut caller, &mut relay).await.is_some(),
        "precondition: the relay fans out for a sender who is in the call"
    );

    // Now callee_b — a member of the network, not a participant of this call —
    // asks for the same fan-out.
    callee_b.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: b_identity.id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call, 2, b"unsolicited"),
        },
    );

    let leaked = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            tokio::select! {
                event = callee_a.next_event() => {
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
                _ = callee_b.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        !leaked,
        "a relay must not fan out for a sender who is not in the call"
    );
}

#[tokio::test]
async fn a_relay_will_not_fan_out_for_a_spoofed_sender() {
    // A media envelope carries no signature, so `from` is a claim, and a blind
    // relay is precisely the node that cannot check a claim against the frame.
    // Fan-out is what makes that matter: the claim used to be worth one
    // forwarded frame and is now worth N−1 sends at the relay's expense, to
    // anyone who knows a carried call's id and one participant's identity.
    //
    // The relay therefore binds `from` to the connection it arrived on, the same
    // way a chunk request and a signalling message are already bound. Note where
    // the check does *not* apply: a participant receiving a relayed frame sees
    // the relay's peer id and the sender's `from`, which is what relaying is.
    let [mut caller, mut callee_a, mut relay, mut callee_b] = quartet().await;
    let caller_identity = identity(1);
    let a_identity = identity(2);
    let relay_identity = identity(3);
    let b_identity = identity(4);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();
    relay.relay_call(
        call,
        [caller_identity.id(), a_identity.id(), b_identity.id()],
    );

    // Control: the real caller's fan-out is carried.
    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call, 1, b"control"),
        },
    );
    assert!(
        await_media(&mut callee_a, &mut caller, &mut relay).await.is_some(),
        "precondition: the relay fans out for the participant that really sent it"
    );

    // callee_b is a participant of this call, so the participant check passes —
    // and it claims to be the caller, so only the connection binding can catch
    // it. Without that check this frame reaches everyone.
    callee_b.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call, 2, b"spoofed"),
        },
    );

    let leaked = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            tokio::select! {
                event = callee_a.next_event() => {
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
                _ = callee_b.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        !leaked,
        "a relay must not fan out an envelope whose sender is not the peer that sent it"
    );
}

#[tokio::test]
async fn a_relay_that_is_also_a_participant_receives_as_well_as_forwards() {
    // A participant with spare upload carrying the call for everyone else is a
    // sensible topology, not an exotic one, and it is the case where fan-out
    // could quietly go wrong: the obvious loop sends the node a copy of a frame
    // it is already holding. It should receive it locally and forward to the
    // others, exactly once each.
    let [mut caller, mut callee_a, mut relay, mut callee_b] = quartet().await;
    let caller_identity = identity(1);
    let a_identity = identity(2);
    let relay_identity = identity(3);
    let b_identity = identity(4);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();
    // The relay is in the call this time.
    relay.relay_call(
        call,
        [
            caller_identity.id(),
            a_identity.id(),
            relay_identity.id(),
            b_identity.id(),
        ],
    );

    let plaintext = b"the carrier is listening too";
    caller.send_media(
        relay_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call, 1, plaintext),
        },
    );

    let mut relay_heard = None;
    let mut forwarded_to = Vec::new();
    let mut others = 0;
    let done = tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            tokio::select! {
                event = relay.next_event() => match event {
                    NodeEvent::MediaReceived { envelope } => relay_heard = Some(envelope),
                    NodeEvent::MediaForwarded { call: got, to, .. } if got == call => {
                        forwarded_to = to;
                    }
                    _ => {}
                },
                event = callee_a.next_event() => {
                    if matches!(event, NodeEvent::MediaReceived { .. }) { others += 1; }
                }
                event = callee_b.next_event() => {
                    if matches!(event, NodeEvent::MediaReceived { .. }) { others += 1; }
                }
                _ = caller.next_event() => {}
            }
            if relay_heard.is_some() && others == 2 {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        done,
        "a relaying participant should hear the frame and the others should still get it"
    );
    assert_eq!(
        key.open_frame(&call, &relay_heard.unwrap().frame).unwrap(),
        plaintext,
        "a participant that is relaying can still open frames it is entitled to"
    );
    assert!(
        !forwarded_to.contains(&relay_identity.id()),
        "a relay must not send a frame to itself over the network"
    );
    assert!(
        !forwarded_to.contains(&caller_identity.id()),
        "the sender is never a recipient of its own frame"
    );
}

#[tokio::test]
async fn a_relaying_participant_hears_a_frame_it_has_nobody_to_forward_to() {
    // The degenerate fan-out: two participants, one of whom is carrying the
    // call. "Everyone but the sender" is just the carrier, so there is nothing
    // to forward and the only thing to do with the frame is hear it.
    //
    // This is a trap rather than a corner. `next_swarm_event` drains its buffered
    // events on entry only, so an event pushed from inside its loop is delivered
    // when some *other* event returns — and here there is no other event coming.
    // Buffering the local delivery would strand it until unrelated traffic
    // happened to arrive, which is a bug that only shows up on a quiet call.
    let (mut caller, mut callee, mut idle) = trio().await;
    let caller_identity = identity(1);
    let callee_identity = identity(2);

    let call = CallId::generate().unwrap();
    let key = CallKey::generate().unwrap();
    // The callee carries the call *and* is in it, with nobody else present.
    callee.relay_call(call, [caller_identity.id(), callee_identity.id()]);

    let plaintext = b"nobody to pass this on to";
    caller.send_media(
        callee_identity.id(),
        MediaEnvelope {
            call,
            from: caller_identity.id(),
            to: Recipient::Participants,
            frame: key.seal_frame(&call, 1, plaintext),
        },
    );

    // Deliberately tight. On loopback a correct implementation delivers this in
    // one round trip; a buffered one delivers it whenever unrelated traffic next
    // happens to return an event, which on an otherwise quiet call is a keepalive
    // interval away. A generous deadline here would pass under both and pin
    // nothing.
    let heard = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! {
                event = callee.next_event() => {
                    if let NodeEvent::MediaReceived { envelope } = event {
                        return envelope;
                    }
                }
                _ = caller.next_event() => {}
                _ = idle.next_event() => {}
            }
        }
    })
    .await
    .expect("the carrier is a participant and must hear the frame promptly");
    assert_eq!(
        key.open_frame(&call, &heard.frame).unwrap(),
        plaintext,
        "a fanned-out frame with no onward recipients still reaches the carrier"
    );
    assert_eq!(
        heard.to,
        Recipient::One(callee_identity.id()),
        "and arrives readdressed, like any other delivery"
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
            to: Recipient::One(callee_identity.id()),
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
            to: Recipient::One(callee_identity.id()),
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
            to: Recipient::One(callee_identity.id()),
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
            to: Recipient::One(callee_identity.id()),
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
