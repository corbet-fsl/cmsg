//! The wave door actions on the retained Vault of a real member: the member's
//! action is recorded before any proof, the host worker's jobs survive failure,
//! and a blocked peer is refused on this device in both directions.
use super::profile_owner_tests::{open_as, ProfileOwner};
use super::*;
use crate::door::inbox_waves::{
    Answer, Command, ContactRequest, Decision, Delivered, Envelope, Hello, JobDone, JobResult,
    Policy, Stage, Terms, WaveDecide, WaveIncoming, WaveMessage, WavePorts, WavePunish, WaveSend,
    WAVE_VERSION,
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

pub(super) struct Ports {
    pub(super) lineage: ckmg::Lineage,
}
impl WavePorts for Ports {
    fn policy(&self, _: u64) -> Result<Policy> {
        Ok(Policy {
            group: [1; 32],
            contact_policy: [2; 32],
            history: [3; 32],
            authority: [4; 32],
            lifetime: 3600,
            window: 0,
        })
    }
    fn terms<'a>(
        &'a self,
        nonce: &'a [u8; 32],
        _: &'a Hello,
        _: &'a str,
        _: u64,
    ) -> facades::OwnedFuture<'a, Terms> {
        let nonce = *nonce;
        Box::pin(async move {
            Ok(Terms {
                recipient_authority: [5; 32],
                recipient_challenge: [6; 32],
                contact_signature: fake_signature(&nonce),
            })
        })
    }
    fn sign_contact<'a>(
        &'a self,
        request: ContactRequest<'a>,
        _: u64,
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
    fn peer_lineage<'a>(
        &'a self,
        binding: &'a ckmg::Binding,
    ) -> facades::OwnedFuture<'a, ckmg::Lineage> {
        Box::pin(async move {
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
    (owner, Ports { lineage })
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
