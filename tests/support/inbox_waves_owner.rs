//! The wave door actions on the retained Vault of a real member: the member's
//! action is recorded before any proof, the host worker's jobs survive failure,
//! and a blocked peer is refused on this device in both directions.
use super::profile_owner_tests::{open_as, ProfileOwner};
use super::*;
use crate::door::inbox_waves::{
    Answer, Command, ContactRequest, Decision, Delivered, Envelope, HandleRequest, Hello, JobDone,
    JobResult, Policy, Stage, Terms, WaveDecide, WaveIncoming, WaveMessage, WavePorts, WavePunish,
    WaveSend, WAVE_VERSION,
};
use cwlt::wave::{
    VerifiedWaveOutcome, VerifiedWaveReservation, WaveContext, WaveOutcome, WaveOutcomeStatement,
    WaveStatement,
};

const ME: &str = "ab";
const PEER: &str = "cd";

pub(super) fn fake_signature(nonce: &[u8; 32]) -> Vec<u8> {
    [nonce.as_slice(), nonce.as_slice()].concat()
}

/// The scripted handle announcement of this fixture: only the one bound to the wave's
/// conversation is accepted, as the real port accepts only an announcement bound to it.
pub(super) fn scripted_handle(conversation: &[u8; 32]) -> Vec<u8> {
    [b"scripted handle:".as_slice(), conversation.as_slice()].concat()
}

/// The fixture's lineage as the one authority for the peer.
struct Peer(ckmg::Lineage);
impl cnbx::DeviceAuthority for Peer {
    async fn current(
        &mut self,
        _: &ckmg::Binding,
    ) -> std::result::Result<ckmg::Lineage, cnbx::ContactError> {
        Ok(self.0.clone())
    }
}

pub(super) struct Ports {
    pub(super) lineage: ckmg::Lineage,
    /// Seconds an offer stays open; 0 makes every Terms late.
    pub(super) lifetime: u64,
    /// The peer is a current member of the verified roster.
    pub(super) member: bool,
    /// A handle for the peer was verified and retained, so its lineage can be read.
    pub(super) readable: bool,
}
impl WavePorts for Ports {
    fn policy(&self, _: u64) -> Result<Policy> {
        Ok(Policy {
            group: [1; 32],
            contact_policy: [2; 32],
            history: [3; 32],
            authority: [4; 32],
            lifetime: self.lifetime,
            window: 0,
        })
    }
    fn terms<'a>(
        &'a self,
        nonce: &'a [u8; 32],
        _: &'a Hello,
        _: &'a str,
        _: u64,
        _: &'a dyn crate::door::inbox_waves::AccountSigner,
    ) -> facades::OwnedFuture<'a, Terms> {
        let nonce = *nonce;
        Box::pin(async move {
            Ok(Terms {
                recipient_authority: [5; 32],
                recipient_challenge: [6; 32],
                contact_signature: fake_signature(&nonce),
                recipient_handle: vec![],
            })
        })
    }
    fn sign_contact<'a>(
        &'a self,
        request: ContactRequest<'a>,
        _: u64,
        _: &'a dyn crate::door::inbox_waves::AccountSigner,
    ) -> facades::OwnedFuture<'a, Vec<u8>> {
        // The scripted signature of this fixture: the nonce repeated, the same for both roles.
        let nonce = *request.nonce;
        Box::pin(async move { Ok(fake_signature(&nonce)) })
    }
    fn verify_contact<'a>(
        &'a self,
        request: ContactRequest<'a>,
        signature: &'a [u8],
        _: u64,
    ) -> facades::OwnedFuture<'a, ()> {
        let ok = signature == fake_signature(request.nonce).as_slice();
        Box::pin(async move { ok.then_some(()).ok_or(ErrorCode::Refused) })
    }
    fn verify_reservation<'a>(
        &'a self,
        _: &'a WaveStatement,
        _: &'a [u8],
        _: &'a WaveContext,
        _: u64,
    ) -> facades::OwnedFuture<'a, VerifiedWaveReservation> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn verify_outcome<'a>(
        &'a self,
        _: &'a WaveOutcomeStatement,
        _: &'a [u8],
        _: &'a WaveContext,
        _: WaveOutcome,
        _: &'a [u8; 32],
        _: u64,
    ) -> facades::OwnedFuture<'a, VerifiedWaveOutcome> {
        Box::pin(async { Err(ErrorCode::Unavailable) })
    }
    fn own_record<'a>(&'a self, _: &'a ckmg::Binding) -> facades::OwnedFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn member<'a>(&'a self, _: &'a ckmg::Binding, _: u64) -> facades::OwnedFuture<'a, ()> {
        let member = self.member;
        Box::pin(async move { member.then_some(()).ok_or(ErrorCode::Refused) })
    }
    fn accept_handle<'a>(&'a self, request: HandleRequest<'a>) -> facades::OwnedFuture<'a, ()> {
        Box::pin(async move {
            // The scripted peers of the single-owner tests announce the scripted handle.
            if request.announcement == scripted_handle(request.conversation).as_slice() {
                return Ok(());
            }
            // A real peer's announcement is verified as the production port does, against
            // this fixture's lineage for the peer.
            let announcement: cnbx::HandleAnnouncement =
                serde_json::from_slice(request.announcement).map_err(|_| ErrorCode::Refused)?;
            if announcement.binding() != request.peer
                || announcement.conversation() != request.conversation
            {
                return Err(ErrorCode::Refused);
            }
            let mut lineage = self.lineage.clone();
            lineage.binding = request.peer.clone();
            announcement
                .verify(request.own, &mut Peer(lineage))
                .await
                .map_err(|_| ErrorCode::Refused)
        })
    }
    fn peer_lineage<'a>(
        &'a self,
        binding: &'a ckmg::Binding,
    ) -> facades::OwnedFuture<'a, ckmg::Lineage> {
        Box::pin(async move {
            if !self.readable {
                return Err(ErrorCode::Unavailable);
            }
            let mut lineage = self.lineage.clone();
            lineage.binding = binding.clone();
            Ok(lineage)
        })
    }
}

pub(super) fn member(byte: &str) -> String {
    byte.repeat(48)
}

async fn open() -> (ProfileOwner, Ports) {
    let (owner, _, _) = open_as(&member(ME), false).await;
    let lineage = owner
        .retained
        .lock()
        .await
        .as_mut()
        .unwrap()
        .vault
        .keys()
        .lineage()
        .await
        .unwrap();
    (
        owner,
        Ports {
            lineage,
            lifetime: 3600,
            member: true,
            readable: true,
        },
    )
}

async fn status(
    owner: &mut ProfileOwner,
    ports: &Ports,
    command: Command,
) -> Result<crate::door::inbox_waves::WaveStatus> {
    match owner.waves(command, ports).await? {
        Answer::Status(status) => Ok(status),
        _ => panic!("a wave status"),
    }
}

#[tokio::test]
async fn a_sent_wave_is_recorded_first_and_its_job_survives_every_failed_proof() {
    let (mut owner, ports) = open().await;
    let sent = status(
        &mut owner,
        &ports,
        Command::Send(WaveSend { peer: member(PEER) }),
    )
    .await
    .unwrap();
    assert_eq!((sent.role, sent.stage, sent.pending), (0, Stage::Hello, 1));
    assert_eq!(sent.conversation, None);
    let nonce = sent.nonce;
    let conversation = {
        let Answer::Outbox(outbox) = owner.waves(Command::Outbox, &ports).await.unwrap() else {
            panic!("an outbox")
        };
        outbox.messages[0].envelope.conversation
    };
    let terms_envelope = |nonce, terms, sender: &str, sequence, conversation| Envelope {
        version: WAVE_VERSION,
        conversation,
        sender: member(sender),
        sequence,
        message: WaveMessage::Terms { nonce, terms },
    };
    // The first message is the queued hello; the host confirms its delivery once.
    let Answer::Outbox(outbox) = owner.waves(Command::Outbox, &ports).await.unwrap() else {
        panic!("an outbox")
    };
    assert!(matches!(
        outbox.messages.as_slice(),
        [crate::door::inbox_waves::Queued {
            envelope: Envelope {
                message: WaveMessage::Hello { .. },
                ..
            },
            ..
        }]
    ));
    let delivered = Delivered {
        nonce,
        kind: "hello".into(),
    };
    assert!(matches!(
        owner
            .waves(Command::Delivered(delivered.clone()), &ports)
            .await,
        Ok(Answer::Done)
    ));
    assert!(owner
        .waves(Command::Delivered(delivered), &ports)
        .await
        .is_err());
    // A hello or terms from a stranger or from the wrong peer is refused.
    let terms = Terms {
        recipient_authority: [5; 32],
        recipient_challenge: [6; 32],
        contact_signature: fake_signature(&nonce),
        recipient_handle: scripted_handle(&conversation),
    };
    let wrong = WaveIncoming {
        peer: member("ef"),
        envelope: terms_envelope(nonce, terms.clone(), "ef", 0, conversation),
    };
    assert_eq!(
        status(&mut owner, &ports, Command::Receive(wrong)).await,
        Err(ErrorCode::Refused)
    );
    // A wrong version, a mis-bound conversation and a stale sequence are refused.
    for envelope in [
        Envelope {
            version: 2,
            ..terms_envelope(nonce, terms.clone(), PEER, 0, conversation)
        },
        terms_envelope(nonce, terms.clone(), PEER, 0, [0xee; 32]),
    ] {
        let bad = WaveIncoming {
            peer: member(PEER),
            envelope,
        };
        assert_eq!(
            status(&mut owner, &ports, Command::Receive(bad)).await,
            Err(ErrorCode::Refused)
        );
    }
    // Terms without the recipient's handle, or with one bound to another conversation (a
    // substituted handle), are refused before anything is offered or reserved.
    for handle in [vec![], scripted_handle(&[0xee; 32])] {
        let bad = Terms {
            recipient_handle: handle,
            ..terms.clone()
        };
        assert_eq!(
            status(
                &mut owner,
                &ports,
                Command::Receive(WaveIncoming {
                    peer: member(PEER),
                    envelope: terms_envelope(nonce, bad, PEER, 0, conversation),
                }),
            )
            .await,
            Err(ErrorCode::Refused)
        );
    }
    // Terms whose contact signature is missing or does not verify are refused before
    // anything is offered or reserved.
    for signature in [vec![], vec![0; 64], fake_signature(&nonce)[..63].to_vec()] {
        let bad = Terms {
            contact_signature: signature,
            ..terms.clone()
        };
        assert_eq!(
            status(
                &mut owner,
                &ports,
                Command::Receive(WaveIncoming {
                    peer: member(PEER),
                    envelope: terms_envelope(nonce, bad, PEER, 0, conversation),
                }),
            )
            .await,
            Err(ErrorCode::Refused)
        );
    }
    // The right terms record the reservation as work; nothing is proved yet.
    let reserving = status(
        &mut owner,
        &ports,
        Command::Receive(WaveIncoming {
            peer: member(PEER),
            envelope: terms_envelope(nonce, terms.clone(), PEER, 0, conversation),
        }),
    )
    .await
    .unwrap();
    assert_eq!((reserving.stage, reserving.pending), (Stage::Reserving, 1));
    assert_eq!(
        status(
            &mut owner,
            &ports,
            Command::Receive(WaveIncoming {
                peer: member(PEER),
                envelope: terms_envelope(nonce, terms, PEER, 1, conversation),
            }),
        )
        .await,
        Err(ErrorCode::Refused)
    );
    // The worker takes the job; a failed proof returns it, five failures stall it
    // visibly, a retry gives it a fresh set of attempts. The action is never lost.
    let mut last = [0; 32];
    for _ in 0..5 {
        let Answer::Job(offer) = owner.waves(Command::NextJob, &ports).await.unwrap() else {
            panic!("a job offer")
        };
        let job = offer.job.expect("the recorded reservation");
        last = job.id;
        assert_eq!((job.sender.role, job.recipient.role), (0, 1));
        assert_eq!(job.contact_signature, Some(fake_signature(&nonce)));
        assert_eq!(job.sender.owner, job.recipient.peer);
        let kept = status(
            &mut owner,
            &ports,
            Command::JobDone(JobDone {
                id: job.id,
                result: JobResult::Failed,
            }),
        )
        .await
        .unwrap();
        assert_eq!(kept.stage, Stage::Reserving);
    }
    let Answer::Job(none) = owner.waves(Command::NextJob, &ports).await.unwrap() else {
        panic!("a job offer")
    };
    assert!(none.job.is_none());
    let Answer::List(list) = owner.waves(Command::List, &ports).await.unwrap() else {
        panic!("a list")
    };
    assert_eq!((list.waves.len(), list.stalled), (1, 1));
    assert!(matches!(
        owner.waves(Command::Retry(last), &ports).await,
        Ok(Answer::Done)
    ));
    let Answer::Job(again) = owner.waves(Command::NextJob, &ports).await.unwrap() else {
        panic!("a job offer")
    };
    assert!(again.job.is_some());
    // A restart returns the job being proved to the queue.
    assert!(matches!(
        owner.waves(Command::Recover, &ports).await,
        Ok(Answer::Done)
    ));
    let Answer::Job(requeued) = owner.waves(Command::NextJob, &ports).await.unwrap() else {
        panic!("a job offer")
    };
    assert!(requeued.job.is_some());
}

#[tokio::test]
async fn a_blocked_peer_is_refused_on_this_device_in_both_directions() {
    let (mut owner, ports) = open().await;
    // The hello of an unblocked peer is accepted and answered with our terms.
    let hello = Hello {
        conversation: [9; 32],
        group: [1; 32],
        contact_policy: [2; 32],
        history: [3; 32],
        opened_at: 1,
        expires_at: u64::MAX,
        sender_authority: [4; 32],
        sender_challenge: [7; 32],
        sender_handle: scripted_handle(&[9; 32]),
    };
    let incoming = |peer: &str, nonce: u8| WaveIncoming {
        peer: member(peer),
        envelope: Envelope {
            version: WAVE_VERSION,
            conversation: hello.conversation,
            sender: member(peer),
            sequence: 0,
            message: WaveMessage::Hello {
                nonce: [nonce; 32],
                hello: hello.clone(),
            },
        },
    };
    let accepted = status(&mut owner, &ports, Command::Receive(incoming(PEER, 1)))
        .await
        .unwrap();
    assert_eq!((accepted.role, accepted.stage), (1, Stage::Hello));
    // The same wave twice, and a stranger's expired hello, are refused.
    assert_eq!(
        status(&mut owner, &ports, Command::Receive(incoming(PEER, 1))).await,
        Err(ErrorCode::Refused)
    );
    // The recipient cannot decide before its reservation exists.
    assert_eq!(
        status(
            &mut owner,
            &ports,
            Command::Decide(WaveDecide {
                nonce: [1; 32],
                decision: Decision::Answer
            })
        )
        .await,
        Err(ErrorCode::Refused)
    );
    // Punishing blocks at once, on this device, and records the punishment as work.
    let Answer::Relation(relation) = owner
        .waves(
            Command::Punish(WavePunish {
                peer: member(PEER),
                nonce: Some([1; 32]),
            }),
            &ports,
        )
        .await
        .unwrap()
    else {
        panic!("a relation")
    };
    assert_eq!(relation.state, cnbx::ContactState::Blocked);
    let list = match owner.waves(Command::List, &ports).await.unwrap() {
        Answer::List(list) => list,
        _ => panic!("a list"),
    };
    assert_eq!(list.waves[0].stage, Stage::Punished);
    // Neither side of the block can open a wave.
    assert_eq!(
        status(&mut owner, &ports, Command::Receive(incoming(PEER, 2))).await,
        Err(ErrorCode::Refused)
    );
    assert_eq!(
        status(
            &mut owner,
            &ports,
            Command::Send(WaveSend { peer: member(PEER) })
        )
        .await,
        Err(ErrorCode::Refused)
    );
    // Not oneself, and not a malformed member string.
    assert!(status(
        &mut owner,
        &ports,
        Command::Send(WaveSend { peer: member(ME) })
    )
    .await
    .is_err());
    assert!(status(
        &mut owner,
        &ports,
        Command::Send(WaveSend {
            peer: "short".into()
        })
    )
    .await
    .is_err());
}

#[tokio::test]
async fn an_unanswered_wave_gives_no_claim_so_the_pending_conversation_cannot_send() {
    use crate::door::inbox_conversation::{Command as Chat, ConversationRetry, ConversationSend};
    let (mut owner, ports) = open().await;
    let hello = Hello {
        conversation: [9; 32],
        group: [1; 32],
        contact_policy: [2; 32],
        history: [3; 32],
        opened_at: 1,
        expires_at: u64::MAX,
        sender_authority: [4; 32],
        sender_challenge: [7; 32],
        sender_handle: scripted_handle(&[9; 32]),
    };
    let accepted = status(
        &mut owner,
        &ports,
        Command::Receive(WaveIncoming {
            peer: member(PEER),
            envelope: Envelope {
                version: WAVE_VERSION,
                conversation: hello.conversation,
                sender: member(PEER),
                sequence: 0,
                message: WaveMessage::Hello {
                    nonce: [1; 32],
                    hello: hello.clone(),
                },
            },
        }),
    )
    .await
    .unwrap();
    assert_eq!((accepted.role, accepted.stage), (1, Stage::Hello));
    // The recipient has not answered: no Claimed Answer, no Established contact.
    assert!(owner
        .conversation(
            Chat::Send(ConversationSend {
                peer: member(PEER),
                conversation: hello.conversation,
                text: "too early".into(),
            }),
            &ports
        )
        .await
        .is_err());
    assert!(owner
        .conversation(
            Chat::Retry(ConversationRetry {
                peer: member(PEER),
                conversation: hello.conversation,
                message: [1; 32],
            }),
            &ports
        )
        .await
        .is_err());
}

#[tokio::test]
async fn terms_that_come_too_late_replace_the_hello_silently_and_boundedly() {
    let (mut owner, mut ports) = open().await;
    ports.lifetime = 0;
    let first = status(
        &mut owner,
        &ports,
        Command::Send(WaveSend { peer: member(PEER) }),
    )
    .await
    .unwrap();
    let mut nonce = first.nonce;
    let mut seen = vec![nonce];
    for round in 0..3 {
        let Answer::Outbox(outbox) = owner.waves(Command::Outbox, &ports).await.unwrap() else {
            panic!("an outbox")
        };
        let conversation = outbox.messages.last().unwrap().envelope.conversation;
        let late = WaveIncoming {
            peer: member(PEER),
            envelope: Envelope {
                version: WAVE_VERSION,
                conversation,
                sender: member(PEER),
                sequence: 0,
                message: WaveMessage::Terms {
                    nonce,
                    terms: Terms {
                        recipient_authority: [5; 32],
                        recipient_handle: scripted_handle(&conversation),
                        recipient_challenge: [6; 32],
                        contact_signature: fake_signature(&nonce),
                    },
                },
            },
        };
        // The human's wave is kept: one wave, a new Hello, still waiting for terms.
        let again = status(&mut owner, &ports, Command::Receive(late))
            .await
            .unwrap();
        assert_eq!(
            (again.role, again.stage),
            (0, Stage::Hello),
            "round {round}"
        );
        assert!(!seen.contains(&again.nonce));
        nonce = again.nonce;
        seen.push(nonce);
        let Answer::List(list) = owner.waves(Command::List, &ports).await.unwrap() else {
            panic!("a list")
        };
        assert_eq!(list.waves.len(), 1);
        assert_eq!(list.stalled, 0);
    }
    // The fourth replacement is refused: the retries are bounded.
    let Answer::Outbox(outbox) = owner.waves(Command::Outbox, &ports).await.unwrap() else {
        panic!("an outbox")
    };
    let conversation = outbox.messages.last().unwrap().envelope.conversation;
    let late = WaveIncoming {
        peer: member(PEER),
        envelope: Envelope {
            version: WAVE_VERSION,
            conversation,
            sender: member(PEER),
            sequence: 0,
            message: WaveMessage::Terms {
                nonce,
                terms: Terms {
                    recipient_authority: [5; 32],
                    recipient_handle: scripted_handle(&conversation),
                    recipient_challenge: [6; 32],
                    contact_signature: fake_signature(&nonce),
                },
            },
        },
    };
    assert_eq!(
        status(&mut owner, &ports, Command::Receive(late)).await,
        Err(ErrorCode::Refused)
    );
}

#[tokio::test]
async fn the_first_wave_to_a_stranger_needs_no_retained_handle_and_carries_its_own() {
    let (mut owner, mut ports) = open().await;
    let own = ports.lineage.binding.clone();
    // Nothing is retained for the peer, so its lineage cannot be read; it is a member.
    ports.readable = false;
    let sent = status(
        &mut owner,
        &ports,
        Command::Send(WaveSend { peer: member(PEER) }),
    )
    .await
    .unwrap();
    assert_eq!((sent.role, sent.stage), (0, Stage::Hello));
    // The signed Hello carries the sender's OWN handle, bound to this wave's conversation.
    let Answer::Outbox(outbox) = owner.waves(Command::Outbox, &ports).await.unwrap() else {
        panic!("an outbox")
    };
    let WaveMessage::Hello { hello, .. } = &outbox.messages[0].envelope.message else {
        panic!("a hello")
    };
    let announcement: cnbx::HandleAnnouncement = serde_json::from_slice(&hello.sender_handle)
        .expect("the hello carries a handle announcement");
    assert_eq!(announcement.binding(), &own);
    assert_eq!(announcement.conversation(), &hello.conversation);
    assert!(!announcement.handle().is_empty());
    // Only roster membership gates the send: a peer that is no member is refused.
    ports.member = false;
    assert_eq!(
        status(
            &mut owner,
            &ports,
            Command::Send(WaveSend { peer: member(PEER) })
        )
        .await,
        Err(ErrorCode::Refused)
    );
    // Every later message needs the peer's lineage, read through the handle retained
    // from the first exchange: unreadable, it is unavailable (retry), never accepted.
    ports.member = true;
    let later = WaveIncoming {
        peer: member(PEER),
        envelope: Envelope {
            version: WAVE_VERSION,
            conversation: hello.conversation,
            sender: member(PEER),
            sequence: 1,
            message: WaveMessage::Welcome {
                nonce: sent.nonce,
                welcome: vec![1],
            },
        },
    };
    assert_eq!(
        status(&mut owner, &ports, Command::Receive(later)).await,
        Err(ErrorCode::Unavailable)
    );
}

#[tokio::test]
async fn a_hello_is_countersigned_only_with_a_handle_bound_to_its_conversation() {
    let (mut owner, mut ports) = open().await;
    let own = ports.lineage.binding.clone();
    ports.readable = false;
    let hello = |handle: Vec<u8>| Hello {
        conversation: [9; 32],
        group: [1; 32],
        contact_policy: [2; 32],
        history: [3; 32],
        opened_at: 1,
        expires_at: u64::MAX,
        sender_authority: [4; 32],
        sender_challenge: [7; 32],
        sender_handle: handle,
    };
    let incoming = |nonce: u8, hello: Hello| WaveIncoming {
        peer: member(PEER),
        envelope: Envelope {
            version: WAVE_VERSION,
            conversation: hello.conversation,
            sender: member(PEER),
            sequence: 0,
            message: WaveMessage::Hello {
                nonce: [nonce; 32],
                hello,
            },
        },
    };
    // No handle, or one bound to another conversation (a substituted handle), is refused
    // before anything is countersigned, and no wave is created.
    for bad in [
        vec![],
        scripted_handle(&[8; 32]),
        b"scripted handle:".to_vec(),
    ] {
        assert_eq!(
            status(
                &mut owner,
                &ports,
                Command::Receive(incoming(1, hello(bad)))
            )
            .await,
            Err(ErrorCode::Refused)
        );
    }
    let Answer::List(list) = owner.waves(Command::List, &ports).await.unwrap() else {
        panic!("a list")
    };
    assert!(list.waves.is_empty());
    // A peer that is no member of the roster is refused before its handle is looked at.
    ports.member = false;
    assert_eq!(
        status(
            &mut owner,
            &ports,
            Command::Receive(incoming(1, hello(scripted_handle(&[9; 32]))))
        )
        .await,
        Err(ErrorCode::Refused)
    );
    // The bound handle is accepted without any retained handle; the countersign carries
    // the recipient's OWN handle for the same conversation.
    ports.member = true;
    let accepted = status(
        &mut owner,
        &ports,
        Command::Receive(incoming(1, hello(scripted_handle(&[9; 32])))),
    )
    .await
    .unwrap();
    assert_eq!((accepted.role, accepted.stage), (1, Stage::Hello));
    let Answer::Outbox(outbox) = owner.waves(Command::Outbox, &ports).await.unwrap() else {
        panic!("an outbox")
    };
    let WaveMessage::Terms { terms, .. } = &outbox.messages[0].envelope.message else {
        panic!("terms")
    };
    let announcement: cnbx::HandleAnnouncement = serde_json::from_slice(&terms.recipient_handle)
        .expect("the countersign carries a handle announcement");
    assert_eq!(announcement.binding(), &own);
    assert_eq!(announcement.conversation(), &[9; 32]);
    assert!(!announcement.handle().is_empty());
}
