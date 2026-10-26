//! Device pairing over the member mesh: the link and the sealed exchange.
//!
//! The existing device shows a `cvpr1.` link (QR or text) holding a one-time
//! 256-bit secret, an offer id, a one-time HPKE public key and its mesh address.
//! The new device runs FOUR rounds, each one sealed message to that address and one
//! sealed reply: (1) hello, answered with the current lineage anchor; (2) the pairing
//! request, answered with the community's challenge of the first stamped step (after the
//! member's one wallet confirmation); (3) the new key's signature over that challenge,
//! answered with the grant and the challenge of the second step; (4) the new key's
//! signature over the second challenge, answered with the activation. Every message is HPKE PSK mode (RFC 9180)
//! with the link secret as the pre-shared key and the offer id as its identifier, so only
//! the holder of the link can produce or read any of them. The round number is part of
//! the HPKE `info`, so a message cannot be replayed into another round. A repeated
//! identical message gets the identical reply again (a lost answer costs the person
//! nothing), and nothing else is accepted out of order. Nothing passes through our servers, and the
//! link is the only secret: no command or reply of the Door carries it.
//!
//! The payloads are opaque bytes here (the public `PairingRequest` and the
//! `PairingGrant` with the root sealed to the new device); the callers verify them
//! with Keys. The link grants no authority by itself: the existing device still
//! needs the member's explicit approval, a step-up assertion and Keys' own check.
use super::*;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable};

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

/// Versioned prefix of the text form.
pub const PREFIX: &str = "cvpr1.";
/// Longest accepted link text, bounding work before any decoding.
pub const MAX_LINK_CHARS: usize = 768;
/// Largest sealed message in either direction (a grant carries a lineage).
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Seconds an offer stays open (the pairing request itself lives five minutes).
pub const OFFER_SECONDS: u64 = 300;

const VERSION: u8 = 1;
const ENC: usize = 32;
const INFO_REQUEST: &[u8] = b"cvpr.pairing.request.v2";
const INFO_REPLY: &[u8] = b"cvpr.pairing.reply.v2";
/// Number of request/reply rounds of one pairing.
pub const ROUNDS: u8 = 4;

fn info(base: &[u8], round: u8) -> Vec<u8> {
    let mut info = base.to_vec();
    info.push(round);
    info
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Unavailable",
            ErrorCode::Unavailable,
            &__cause,
        )
    })?;
    Ok(bytes)
}

/// Bytes a sealed message adds to its padded plaintext: the encapsulated key and the AEAD tag.
const SEAL_OVERHEAD: usize = ENC + 16;
/// Smallest sealed message; larger ones double up to [`MAX_MESSAGE_BYTES`].
const MIN_BUCKET: usize = 4096;

/// Size class of a sealed message carrying `plaintext` bytes: 4 KiB, then powers of two up to
/// the cap. Every message of a class has exactly this length, so an observer of the carrier
/// learns only the class, never how many scopes (communities) a pairing brings along.
fn bucket(plaintext: usize) -> Option<usize> {
    let needed = plaintext.checked_add(1 + SEAL_OVERHEAD)?;
    let mut size = MIN_BUCKET;
    while size < needed {
        size = size.checked_mul(2)?;
    }
    (size <= MAX_MESSAGE_BYTES).then_some(size)
}

/// ISO 7816-4 padding: 0x80, then zeros, up to the bucket.
fn pad(plaintext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let total = bucket(plaintext.len())? - SEAL_OVERHEAD;
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(total, 0);
    Some(out)
}

fn unpad(mut padded: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    while padded.last() == Some(&0) {
        padded.pop();
    }
    if padded.pop() != Some(0x80) {
        return Err(ErrorCode::Refused);
    }
    Ok(padded)
}

fn seal(
    pk: &[u8; 32],
    secret: &[u8; 32],
    id: &[u8; 16],
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let plaintext = pad(plaintext).ok_or(ErrorCode::InvalidRequest)?;
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(pk).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    let bundle = PskBundle::new(secret, id).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    let (enc, ciphertext) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Psk(bundle), &pk, info, &plaintext, id)
            .map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::Unavailable",
                    ErrorCode::Unavailable,
                    &__cause,
                )
            })?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn open(
    sk: &<Kem as KemTrait>::PrivateKey,
    secret: &[u8; 32],
    id: &[u8; 16],
    info: &[u8],
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if message.len() <= ENC || message.len() > MAX_MESSAGE_BYTES + ENC + 16 {
        return Err(ErrorCode::InvalidRequest);
    }
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&message[..ENC]).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    let bundle = PskBundle::new(secret, id).map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::InvalidRequest",
            ErrorCode::InvalidRequest,
            &__cause,
        )
    })?;
    // Every failure to open is the same refusal: a wrong secret, a forged or an
    // altered message are indistinguishable.
    hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Psk(bundle),
        sk,
        &enc,
        info,
        &message[ENC..],
        id,
    )
    .map(Zeroizing::new)
    .map_err(|__cause| {
        crate::door::cause::emit(
            file!(),
            line!(),
            "ErrorCode::Refused",
            ErrorCode::Refused,
            &__cause,
        )
    })
    .and_then(unpad)
}

/// What the new device learns from the link.
pub struct Link {
    secret: Zeroizing<[u8; 32]>,
    id: [u8; 16],
    recipient: [u8; 32],
    address: cmsh::Address,
}

impl Link {
    /// Strictly decode the text form: one spelling per link, no padding,
    /// whitespace, other alphabets or trailing bytes.
    pub fn parse(text: &str) -> Result<Self> {
        let body = text
            .strip_prefix(PREFIX)
            .filter(|_| text.len() <= MAX_LINK_CHARS)
            .ok_or(ErrorCode::InvalidRequest)?;
        let bytes = BASE64URL_NOPAD.decode(body.as_bytes()).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        if BASE64URL_NOPAD.encode(&bytes) != body {
            return Err(ErrorCode::InvalidRequest);
        }
        let mut at = 0usize;
        let mut take = |n: usize| -> Result<&[u8]> {
            let part = bytes.get(at..at + n).ok_or(ErrorCode::InvalidRequest)?;
            at += n;
            Ok(part)
        };
        if take(1)?[0] != VERSION {
            return Err(ErrorCode::UnsupportedVersion);
        }
        let secret = Zeroizing::new(take(32)?.try_into().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?);
        let id = take(16)?.try_into().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let recipient = take(32)?.try_into().map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let scheme_len = usize::from(take(1)?[0]);
        let scheme = std::str::from_utf8(take(scheme_len)?).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let scheme = cmsh::Scheme::new(scheme).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let address_len = usize::from(u16::from_be_bytes(take(2)?.try_into().map_err(
            |__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::InvalidRequest",
                    ErrorCode::InvalidRequest,
                    &__cause,
                )
            },
        )?));
        let address =
            cmsh::Address::new(scheme, take(address_len)?.to_vec()).map_err(|__cause| {
                crate::door::cause::emit(
                    file!(),
                    line!(),
                    "ErrorCode::InvalidRequest",
                    ErrorCode::InvalidRequest,
                    &__cause,
                )
            })?;
        if at != bytes.len() {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self {
            secret,
            id,
            recipient,
            address,
        })
    }

    /// Where the existing device listens.
    pub fn address(&self) -> &cmsh::Address {
        &self.address
    }

    /// Seal the new device's message of `round` (1..=ROUNDS) under a fresh reply key. The
    /// returned [`Awaiting`] opens the reply, which only the holder of this link can have
    /// produced. A retry of the same round must resend the SAME sealed bytes, not seal
    /// again; a caller that must survive a restart keeps `seed` and the message.
    pub fn seal_round(&self, round: u8, payload: &[u8]) -> Result<(Vec<u8>, Awaiting)> {
        self.seal_round_with(&random::<32>()?, round, payload)
    }

    /// As [`Self::seal_round`] with the reply key derived from a caller-kept `seed`, so the
    /// reply of a round can be opened after a restart ([`Self::awaiting`]).
    pub fn seal_round_with(
        &self,
        seed: &[u8; 32],
        round: u8,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Awaiting)> {
        if round == 0 || round > ROUNDS {
            return Err(ErrorCode::InvalidRequest);
        }
        let awaiting = self.awaiting(seed, round)?;
        let pk = <Kem as KemTrait>::sk_to_pk(&awaiting.private);
        let mut plaintext = pk.to_bytes().to_vec();
        plaintext.extend_from_slice(payload);
        let message = seal(
            &self.recipient,
            &self.secret,
            &self.id,
            &info(INFO_REQUEST, round),
            &plaintext,
        )?;
        Ok((message, awaiting))
    }

    /// The reply opener of a round sealed from `seed`.
    pub fn awaiting(&self, seed: &[u8; 32], round: u8) -> Result<Awaiting> {
        if round == 0 || round > ROUNDS {
            return Err(ErrorCode::InvalidRequest);
        }
        let (private, _) = <Kem as KemTrait>::derive_keypair(seed);
        Ok(Awaiting {
            secret: self.secret.clone(),
            id: self.id,
            round,
            private,
        })
    }
}

/// The new device between one request and its reply.
pub struct Awaiting {
    secret: Zeroizing<[u8; 32]>,
    id: [u8; 16],
    round: u8,
    private: <Kem as KemTrait>::PrivateKey,
}

impl Awaiting {
    /// Open the sealed reply bytes. Anything not sealed under the link for this round
    /// is Refused.
    pub fn open_reply(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open(
            &self.private,
            &self.secret,
            &self.id,
            &info(INFO_REPLY, self.round),
            message,
        )
    }
}

/// The existing device's open offer: the one-time secret and key behind a link, and
/// how far the rounds have come.
pub struct Offer {
    secret: Zeroizing<[u8; 32]>,
    id: [u8; 16],
    private: <Kem as KemTrait>::PrivateKey,
    expires: u64,
    /// Rounds answered so far; the next accepted round is `done + 1`.
    done: u8,
    /// Digest of the accepted message and its sealed reply, per answered round.
    answered: Vec<([u8; 32], Vec<u8>)>,
}

/// Where a request came from, kept to seal the reply.
pub struct ReplyTo([u8; 32]);

/// One accepted message of the new device.
pub enum Received {
    /// A new message for the next round.
    Round {
        /// 1..=ROUNDS.
        round: u8,
        /// The opaque payload.
        payload: Zeroizing<Vec<u8>>,
        /// To seal the reply.
        reply_to: ReplyTo,
    },
    /// The exact message of an answered round again (the answer was lost): the identical
    /// sealed reply, to be resent without any new effect.
    Repeat(Vec<u8>),
}

impl Offer {
    /// Open an offer for `address` until `now + OFFER_SECONDS`; returns it with
    /// the link text to show locally.
    pub fn new(address: &cmsh::Address, now: u64) -> Result<(Self, String)> {
        let secret = Zeroizing::new(random::<32>()?);
        let id = random::<16>()?;
        let (private, public) = <Kem as KemTrait>::derive_keypair(&random::<32>()?);
        let scheme = address.scheme().as_str().as_bytes();
        let address_bytes = address.bytes();
        let address_len = u16::try_from(address_bytes.len()).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?;
        let mut bytes = vec![VERSION];
        bytes.extend_from_slice(&*secret);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&public.to_bytes());
        bytes.push(u8::try_from(scheme.len()).map_err(|__cause| {
            crate::door::cause::emit(
                file!(),
                line!(),
                "ErrorCode::InvalidRequest",
                ErrorCode::InvalidRequest,
                &__cause,
            )
        })?);
        bytes.extend_from_slice(scheme);
        bytes.extend_from_slice(&address_len.to_be_bytes());
        bytes.extend_from_slice(address_bytes);
        let link = format!("{PREFIX}{}", BASE64URL_NOPAD.encode(&bytes));
        if link.len() > MAX_LINK_CHARS {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok((
            Self {
                secret,
                id,
                private,
                expires: now.checked_add(OFFER_SECONDS).ok_or(ErrorCode::Clock)?,
                done: 0,
                answered: Vec::new(),
            },
            link,
        ))
    }

    /// Exclusive deadline of this offer in unix seconds.
    pub fn expires(&self) -> u64 {
        self.expires
    }

    /// Rounds answered so far.
    pub fn rounds_done(&self) -> u8 {
        self.done
    }

    /// All rounds are answered: this offer serves nothing more.
    pub fn finished(&self) -> bool {
        self.done == ROUNDS
    }

    /// Open the new device's next sealed message. A message not sealed under this
    /// offer's link, or for a round other than the next one, is Refused (the two are
    /// indistinguishable); after the deadline everything is Unauthorized. The exact
    /// message of an answered round yields its stored reply again.
    pub fn open_round(&self, message: &[u8], now: u64) -> Result<Received> {
        if now >= self.expires {
            return Err(ErrorCode::Unauthorized);
        }
        let digest: [u8; 32] = Sha256::digest(message).into();
        if let Some((_, reply)) = self.answered.iter().find(|(seen, _)| *seen == digest) {
            return Ok(Received::Repeat(reply.clone()));
        }
        if self.done >= ROUNDS {
            return Err(ErrorCode::Refused);
        }
        let round = self.done + 1;
        let plaintext = open(
            &self.private,
            &self.secret,
            &self.id,
            &info(INFO_REQUEST, round),
            message,
        )?;
        let reply: [u8; 32] = plaintext
            .get(..32)
            .and_then(|key| key.try_into().ok())
            .ok_or(ErrorCode::InvalidRequest)?;
        Ok(Received::Round {
            round,
            payload: Zeroizing::new(plaintext[32..].to_vec()),
            reply_to: ReplyTo(reply),
        })
    }

    /// Seal the reply of the round just received and record it, so the next round is
    /// accepted and a repeated message gets this very reply again. `message` is the
    /// request it answers.
    pub fn answer(&mut self, message: &[u8], to: &ReplyTo, reply: &[u8]) -> Result<Vec<u8>> {
        if self.done >= ROUNDS {
            return Err(ErrorCode::Refused);
        }
        let round = self.done + 1;
        let sealed = seal(
            &to.0,
            &self.secret,
            &self.id,
            &info(INFO_REPLY, round),
            reply,
        )?;
        self.answered
            .push((Sha256::digest(message).into(), sealed.clone()));
        self.done = round;
        Ok(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> cmsh::Address {
        cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![7; 35]).unwrap()
    }

    fn round(offer: &Offer, message: &[u8], now: u64) -> (u8, Vec<u8>, ReplyTo) {
        match offer.open_round(message, now).unwrap() {
            Received::Round {
                round,
                payload,
                reply_to,
            } => (round, payload.to_vec(), reply_to),
            Received::Repeat(_) => panic!("fresh message"),
        }
    }

    #[test]
    fn a_link_carries_its_rounds_in_order_and_nothing_else() {
        let (mut offer, text) = Offer::new(&address(), 1_000).unwrap();
        assert!(text.starts_with(PREFIX) && text.len() <= MAX_LINK_CHARS);
        let link = Link::parse(&text).unwrap();
        assert_eq!(link.address(), &address());
        for n in 1..=ROUNDS {
            let (message, awaiting) = link.seal_round(n, &[n; 5]).unwrap();
            let (got, payload, to) = round(&offer, &message, 1_100);
            assert_eq!((got, payload), (n, vec![n; 5]));
            assert!(!offer.finished());
            let sealed = offer.answer(&message, &to, &[n + 10; 3]).unwrap();
            assert_eq!(&awaiting.open_reply(&sealed).unwrap()[..], &[n + 10; 3]);
        }
        assert!(offer.finished());
        // Nothing new is accepted afterwards.
        let (message, _) = link.seal_round(1, b"again").unwrap();
        assert_eq!(
            offer.open_round(&message, 1_100).err(),
            Some(ErrorCode::Refused)
        );
    }

    #[test]
    fn a_lost_answer_is_repeated_not_redone_and_rounds_cannot_be_skipped() {
        let (mut offer, text) = Offer::new(&address(), 1_000).unwrap();
        let link = Link::parse(&text).unwrap();
        // Round 2 before round 1 is refused without detail.
        let (early, _) = link.seal_round(2, b"x").unwrap();
        assert_eq!(
            offer.open_round(&early, 1_001).err(),
            Some(ErrorCode::Refused)
        );
        let (first, awaiting) = link.seal_round(1, b"hello").unwrap();
        let (_, _, to) = round(&offer, &first, 1_001);
        let sealed = offer.answer(&first, &to, b"options").unwrap();
        // The same message again yields the identical reply bytes and no new round.
        match offer.open_round(&first, 1_002).unwrap() {
            Received::Repeat(again) => assert_eq!(again, sealed),
            Received::Round { .. } => panic!("repeat"),
        }
        assert_eq!(offer.rounds_done(), 1);
        assert_eq!(&awaiting.open_reply(&sealed).unwrap()[..], b"options");
        // A reply of one round is not accepted for another.
        let (second, awaiting2) = link.seal_round(2, b"credential").unwrap();
        assert_eq!(
            awaiting2.open_reply(&sealed).err(),
            Some(ErrorCode::Refused)
        );
        let _ = second;
    }

    #[test]
    fn a_stranger_without_the_link_secret_cannot_make_or_read_a_message() {
        let (offer, text) = Offer::new(&address(), 1_000).unwrap();
        let (_, other_text) = Offer::new(&address(), 1_000).unwrap();
        // Another offer's link cannot talk to this offer.
        let (message, _) = Link::parse(&other_text)
            .unwrap()
            .seal_round(1, b"x")
            .unwrap();
        assert_eq!(
            offer.open_round(&message, 1_001).err(),
            Some(ErrorCode::Refused)
        );
        // A tampered message and a truncated one are refused without detail.
        let (mut message, awaiting) = Link::parse(&text).unwrap().seal_round(1, b"x").unwrap();
        let last = message.len() - 1;
        message[last] ^= 1;
        assert_eq!(
            offer.open_round(&message, 1_001).err(),
            Some(ErrorCode::Refused)
        );
        assert_eq!(
            offer.open_round(&message[..ENC], 1_001).err(),
            Some(ErrorCode::InvalidRequest)
        );
        // A reply not sealed under this link is refused by the requester.
        assert_eq!(
            awaiting.open_reply(&message).err(),
            Some(ErrorCode::Refused)
        );
        assert!(Link::parse(&text).unwrap().seal_round(0, b"x").is_err());
        assert!(Link::parse(&text)
            .unwrap()
            .seal_round(ROUNDS + 1, b"x")
            .is_err());
    }

    #[test]
    fn an_offer_expires() {
        let (offer, text) = Offer::new(&address(), 1_000).unwrap();
        assert_eq!(offer.expires(), 1_000 + OFFER_SECONDS);
        let (message, _) = Link::parse(&text).unwrap().seal_round(1, b"x").unwrap();
        assert_eq!(
            offer.open_round(&message, 1_000 + OFFER_SECONDS).err(),
            Some(ErrorCode::Unauthorized)
        );
    }

    #[test]
    fn the_text_form_has_one_strict_spelling() {
        let (_, text) = Offer::new(&address(), 1).unwrap();
        for bad in [
            String::new(),
            "cvpr1.".into(),
            format!("{text}="),
            format!("{text} "),
            format!(" {text}"),
            text.replacen("cvpr1.", "cvpr2.", 1),
            format!("{text}A"),
            text[..text.len() - 4].to_owned(),
            "x".repeat(MAX_LINK_CHARS + 1),
        ] {
            assert!(Link::parse(&bad).is_err(), "{bad}");
        }
        let mut raw = BASE64URL_NOPAD
            .decode(&text.as_bytes()[PREFIX.len()..])
            .unwrap();
        raw[0] = 2;
        let versioned = format!("{PREFIX}{}", BASE64URL_NOPAD.encode(&raw));
        assert_eq!(
            Link::parse(&versioned).err(),
            Some(ErrorCode::UnsupportedVersion)
        );
    }
}
