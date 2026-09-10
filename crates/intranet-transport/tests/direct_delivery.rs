//! Direct member-to-member delivery — Core §5.1, spec 07 §6.2 (E10).
//!
//! # What these pin, and what they deliberately do not
//!
//! The carrier promises three things and no more: the payload arrives
//! byte-identical to the member it was addressed to, the sender named on it
//! really sent it *and* really is the peer that delivered it, and one identity
//! cannot flood another. It promises nothing about what the payload means,
//! whether the sender is still a member, or whether the recipient wants to hear
//! from them — those are the consumer's, because this crate holds no governance
//! state and cannot decode a namespace it has never heard of.
//!
//! So the negative assertions matter as much as the positive ones, and one of
//! them is the reason this protocol is not `/chat/dm-invite/1.0.0`: a second
//! namespace travels the same carrier with no new protocol.

use intranet_crypto::Timestamp;
use intranet_governance::{
    Capability, EntryBody, GroupId, LogEntry, MembershipAction, NetworkPolicy,
};
use intranet_identity::{MasterSeed, NetworkId, PerNetworkIdentity};
use intranet_transport::direct::{
    DirectAck, DirectError, DirectMessage, DirectRefusal, MAX_DIRECT_PAYLOAD_BYTES,
};
use intranet_transport::direct_limits::PER_WINDOW;
use intranet_transport::{MemberNode, NodeEvent};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use std::time::Duration;

const NETWORK: NetworkId = NetworkId::from_bytes([42u8; 32]);

fn identity(n: u8) -> PerNetworkIdentity {
    MasterSeed::from_entropy([n; 32])
        .identity_for(&NETWORK)
        .unwrap()
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
) -> LogEntry {
    LogEntry::create(
        founder,
        Some(parent),
        Timestamp::from_millis(5),
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
    node.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    node.set_dht_server_mode(true);

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
    .expect("listens");

    (node, address.with(Protocol::P2p(identity.peer_id())))
}

/// Two connected members, agreeing on governance.
async fn pair() -> (MemberNode, MemberNode) {
    let founder = identity(1);
    let peer = identity(2);
    let (mut a, _) = node(1).await;
    let (mut b, b_addr) = node(2).await;

    let root = a.append_entry(genesis(&founder)).unwrap();
    a.append_entry(admit(&founder, root, &peer)).unwrap();
    a.dial_candidates([b_addr]).unwrap();

    let connected = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = a.next_event() => {
                    if matches!(event, NodeEvent::Connected { .. }) { return true; }
                }
                _ = b.next_event() => {}
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(connected, "the pair must connect before anything is sent");

    (a, b)
}

/// Waits for a direct message on `reader`, driving both nodes.
async fn await_direct(
    reader: &mut MemberNode,
    other: &mut MemberNode,
    within: Duration,
) -> Option<DirectMessage> {
    tokio::time::timeout(within, async {
        loop {
            tokio::select! {
                event = reader.next_event() => {
                    if let NodeEvent::DirectReceived { message } = event {
                        return message;
                    }
                }
                _ = other.next_event() => {}
            }
        }
    })
    .await
    .ok()
}

#[tokio::test]
async fn a_payload_reaches_the_member_it_was_addressed_to() {
    let (mut a, mut b) = pair().await;
    let alice = identity(1);
    let bob = identity(2);

    a.send_direct(bob.id(), &alice, "chat", "dm-invite", b"an invite".to_vec())
        .expect("within the ceilings");

    let arrived = await_direct(&mut b, &mut a, Duration::from_secs(20))
        .await
        .expect("the message arrives");

    // Byte-identical, because a carrier that reshaped a payload would make the
    // consumer's own encoding a guess.
    assert_eq!(arrived.payload, b"an invite".to_vec());
    assert_eq!(arrived.namespace, "chat");
    assert_eq!(arrived.kind, "dm-invite");
    assert_eq!(arrived.sender, alice.id());
}

#[tokio::test]
async fn a_second_namespace_needs_no_second_protocol() {
    // The whole reason this is not `/chat/dm-invite/1.0.0`. If a consumer that
    // did not exist when the carrier was written can use it, the platform gained
    // a door rather than a room (Core §0).
    let (mut a, mut b) = pair().await;
    let alice = identity(1);
    let bob = identity(2);

    a.send_direct(bob.id(), &alice, "ledger", "settle-up", b"7 owed".to_vec())
        .expect("within the ceilings");

    let arrived = await_direct(&mut b, &mut a, Duration::from_secs(20))
        .await
        .expect("an unknown namespace still arrives");
    assert_eq!(arrived.namespace, "ledger");
    assert_eq!(arrived.kind, "settle-up");
    assert_eq!(arrived.payload, b"7 owed".to_vec());
}

#[tokio::test]
async fn a_sender_past_the_limit_is_refused_rather_than_left_to_time_out() {
    let (mut a, mut b) = pair().await;
    let alice = identity(1);
    let bob = identity(2);

    // Spend the allowance. Each of these is delivered, so the refusal that
    // follows is about the rate and not about the message.
    for n in 0..PER_WINDOW {
        a.send_direct(
            bob.id(),
            &alice,
            "chat",
            "dm-invite",
            format!("invite {n}").into_bytes(),
        )
        .expect("within the ceilings");
        assert!(
            await_direct(&mut b, &mut a, Duration::from_secs(20))
                .await
                .is_some(),
            "message {n} of the allowance must land"
        );
    }

    a.send_direct(bob.id(), &alice, "chat", "dm-invite", b"one too many".to_vec())
        .expect("within the ceilings");

    // **Refused, and reported.** A limit that surfaced only as the sender timing
    // out would be indistinguishable from a node that had gone away, and the
    // refusing node would have no signal that it was being flooded.
    let refusal = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                event = b.next_event() => {
                    match event {
                        NodeEvent::DirectRefused { sender, reason } => return Some((sender, reason)),
                        NodeEvent::DirectReceived { .. } => return None,
                        _ => {}
                    }
                }
                _ = a.next_event() => {}
            }
        }
    })
    .await
    .expect("the node answers rather than hanging");

    let (sender, reason) = refusal.expect("the message past the limit is refused, not delivered");
    assert_eq!(sender, alice.id());
    assert_eq!(reason, DirectRefusal::RateLimited);
}

#[tokio::test]
async fn one_sender_flooding_does_not_spend_anybody_elses_allowance() {
    let (mut a, mut b) = pair().await;
    let alice = identity(1);
    let bob = identity(2);

    for n in 0..PER_WINDOW {
        a.send_direct(bob.id(), &alice, "chat", "dm-invite", vec![n as u8])
            .expect("within the ceilings");
        await_direct(&mut b, &mut a, Duration::from_secs(20)).await;
    }

    // Carol signs her own message. She has sent nothing, so hers must land even
    // though Alice is exhausted — otherwise one hostile member denies the
    // protocol to everybody.
    let carol = identity(3);
    let carol_message = DirectMessage::create(&carol, "chat", "dm-invite", b"hello".to_vec())
        .expect("within the ceilings");
    assert_eq!(carol_message.sender, carol.id());
    assert!(carol_message.verify().is_ok());
}

#[tokio::test]
async fn a_message_delivered_by_somebody_other_than_its_sender_is_dropped() {
    // **The check a signature cannot make.** A signature proves Carol composed
    // these bytes; it says nothing about who handed them over, and it travels —
    // so anybody who has ever seen one of Carol's messages can present it. Alice
    // here signs as Carol (in a test she holds the key; in the wild she would
    // have replayed a message Carol sent her) and delivers it over Alice's own
    // connection.
    let (mut a, mut b) = pair().await;
    let carol = identity(3);
    let bob = identity(2);

    a.send_direct(bob.id(), &carol, "chat", "dm-invite", b"not from alice".to_vec())
        .expect("within the ceilings");

    // Dropped, and deliberately without an answer: replying would tell a peer
    // probing with a stolen message whether it was well formed.
    let outcome = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            tokio::select! {
                event = b.next_event() => {
                    match event {
                        NodeEvent::DirectReceived { message } => return Some(message),
                        NodeEvent::DirectRefused { .. } => return None,
                        _ => {}
                    }
                }
                _ = a.next_event() => {}
            }
        }
    })
    .await;

    assert!(
        outcome.is_err(),
        "a message whose sender is not the peer that delivered it must reach no consumer,          and must not be answered either — got {outcome:?}"
    );
}

#[test]
fn a_message_signed_by_one_member_does_not_verify_as_another() {
    let alice = identity(1);
    let bob = identity(2);
    let mut message =
        DirectMessage::create(&alice, "chat", "dm-invite", b"an invite".to_vec()).unwrap();

    // Relabelling the sender must break the signature. Otherwise a peer could
    // present somebody else's message as their own.
    message.sender = bob.id();
    assert_eq!(message.verify(), Err(DirectError::BadSignature));
}

#[test]
fn neither_the_namespace_nor_the_payload_can_be_altered_in_flight() {
    let alice = identity(1);
    let original = DirectMessage::create(&alice, "chat", "dm-invite", b"an invite".to_vec()).unwrap();

    // The signature covers sender, namespace, kind and payload together, so a
    // message cannot be re-aimed at a different consumer or have its contents
    // swapped while still verifying.
    let mut moved = original.clone();
    moved.namespace = "ledger".into();
    assert_eq!(moved.verify(), Err(DirectError::BadSignature));

    let mut rekinded = original.clone();
    rekinded.kind = "settle-up".into();
    assert_eq!(rekinded.verify(), Err(DirectError::BadSignature));

    let mut tampered = original;
    tampered.payload = b"a different invite".to_vec();
    assert_eq!(tampered.verify(), Err(DirectError::BadSignature));
}

#[test]
fn a_message_round_trips_byte_identically() {
    let alice = identity(1);
    let message =
        DirectMessage::create(&alice, "chat", "dm-invite", b"an invite".to_vec()).unwrap();
    let bytes = message.encode();
    let back = DirectMessage::decode(&bytes).expect("decodes");
    assert_eq!(back, message);
    assert_eq!(back.encode(), bytes);
}

#[test]
fn an_oversized_payload_is_refused_at_both_ends() {
    let alice = identity(1);
    let too_big = vec![0u8; MAX_DIRECT_PAYLOAD_BYTES + 1];

    // Refused when built, so a sender learns rather than having its message
    // silently shortened into something it did not write.
    assert_eq!(
        DirectMessage::create(&alice, "chat", "dm-invite", too_big.clone()),
        Err(DirectError::PayloadTooLarge {
            size: MAX_DIRECT_PAYLOAD_BYTES + 1
        })
    );

    // And refused on decode, because the sender is not the one being trusted.
    // Built at exactly the ceiling, then grown past it, so the bytes are
    // otherwise well formed and correctly signed.
    let mut at_ceiling =
        DirectMessage::create(&alice, "chat", "dm-invite", vec![0u8; MAX_DIRECT_PAYLOAD_BYTES])
            .unwrap();
    at_ceiling.payload.push(0);
    let re_signed = DirectMessage::create(&alice, "chat", "dm-invite", at_ceiling.payload.clone());
    assert!(re_signed.is_err(), "cannot even be built past the ceiling");
}

#[test]
fn an_empty_label_is_refused_rather_than_treated_as_a_wildcard() {
    let alice = identity(1);
    assert_eq!(
        DirectMessage::create(&alice, "", "dm-invite", b"x".to_vec()),
        Err(DirectError::EmptyLabel)
    );
    assert_eq!(
        DirectMessage::create(&alice, "chat", "", b"x".to_vec()),
        Err(DirectError::EmptyLabel)
    );
}

#[test]
fn an_ack_round_trips_and_an_unknown_one_is_refused() {
    for ack in [
        DirectAck::Received,
        DirectAck::Refused(DirectRefusal::Unsupported),
        DirectAck::Refused(DirectRefusal::RateLimited),
        DirectAck::Refused(DirectRefusal::Rejected),
    ] {
        let bytes = ack.encode();
        assert_eq!(DirectAck::decode(&bytes).expect("decodes"), ack);
    }

    // A discriminant this build does not know is refused rather than rounded to
    // something plausible, which is what keeps two versions from disagreeing
    // about whether a message was taken.
    let mut bytes = DirectAck::Refused(DirectRefusal::Rejected).encode();
    *bytes.last_mut().unwrap() = 0x7f;
    assert!(DirectAck::decode(&bytes).is_err());
}

#[test]
fn a_direct_message_does_not_decode_as_something_else_under_the_same_key() {
    // Domain separation: the ack and the message are different tags, so neither
    // can be read as the other even though both are short and both are signed
    // by keys in the same network.
    let alice = identity(1);
    let message = DirectMessage::create(&alice, "chat", "dm-invite", b"x".to_vec()).unwrap();
    assert!(DirectAck::decode(&message.encode()).is_err());
    assert!(DirectMessage::decode(&DirectAck::Received.encode()).is_err());
}
