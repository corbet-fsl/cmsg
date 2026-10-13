//! Device pairing over the member mesh: the link and the sealed exchange.
//!
//! The existing device shows a `cvpr1.` link (QR or text) holding a one-time
//! 256-bit secret, an offer id, a one-time HPKE public key and its mesh address.
//! The new device sends ONE sealed message to that address and gets ONE sealed
//! reply. Both are HPKE PSK mode (RFC 9180) with the link secret as the pre-shared
//! key and the offer id as its identifier, so only the holder of the link can
//! produce or read either message. Nothing passes through our servers, and the
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
const INFO_REQUEST: &[u8] = b"cvpr.pairing.request.v1";
const INFO_GRANT: &[u8] = b"cvpr.pairing.grant.v1";

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| ErrorCode::Unavailable)?;
    Ok(bytes)
}

fn seal(
    pk: &[u8; 32],
    secret: &[u8; 32],
    id: &[u8; 16],
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > MAX_MESSAGE_BYTES {
        return Err(ErrorCode::InvalidRequest);
    }
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(pk).map_err(|_| ErrorCode::InvalidRequest)?;
    let bundle = PskBundle::new(secret, id).map_err(|_| ErrorCode::InvalidRequest)?;
    let (enc, ciphertext) =
        hpke::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Psk(bundle), &pk, info, plaintext, id)
            .map_err(|_| ErrorCode::Unavailable)?;
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
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&message[..ENC])
        .map_err(|_| ErrorCode::InvalidRequest)?;
    let bundle = PskBundle::new(secret, id).map_err(|_| ErrorCode::InvalidRequest)?;
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
    .map_err(|_| ErrorCode::Refused)
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
        let bytes = BASE64URL_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| ErrorCode::InvalidRequest)?;
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
        let secret = Zeroizing::new(
            take(32)?
                .try_into()
                .map_err(|_| ErrorCode::InvalidRequest)?,
        );
        let id = take(16)?
            .try_into()
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let recipient = take(32)?
            .try_into()
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let scheme_len = usize::from(take(1)?[0]);
        let scheme =
            std::str::from_utf8(take(scheme_len)?).map_err(|_| ErrorCode::InvalidRequest)?;
        let scheme = cmsh::Scheme::new(scheme).map_err(|_| ErrorCode::InvalidRequest)?;
        let address_len = usize::from(u16::from_be_bytes(
            take(2)?.try_into().map_err(|_| ErrorCode::InvalidRequest)?,
        ));
        let address = cmsh::Address::new(scheme, take(address_len)?.to_vec())
            .map_err(|_| ErrorCode::InvalidRequest)?;
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

    /// Seal the new device's public pairing request. The returned [`Awaiting`]
    /// opens the reply, which only the holder of this link can have produced.
    pub fn seal_request(&self, request: &[u8]) -> Result<(Vec<u8>, Awaiting)> {
        let (sk, pk) = <Kem as KemTrait>::derive_keypair(&random::<32>()?);
        let mut plaintext = pk.to_bytes().to_vec();
        plaintext.extend_from_slice(request);
        let message = seal(
            &self.recipient,
            &self.secret,
            &self.id,
            INFO_REQUEST,
            &plaintext,
        )?;
        Ok((
            message,
            Awaiting {
                secret: self.secret.clone(),
                id: self.id,
                private: sk,
            },
        ))
    }
}

/// The new device between its request and the reply.
pub struct Awaiting {
    secret: Zeroizing<[u8; 32]>,
    id: [u8; 16],
    private: <Kem as KemTrait>::PrivateKey,
}

impl Awaiting {
    /// Open the sealed grant bytes. Anything not sealed under the link is Refused.
    pub fn open_grant(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        open(&self.private, &self.secret, &self.id, INFO_GRANT, message)
    }
}

/// The existing device's open offer: the one-time secret and key behind a link.
pub struct Offer {
    secret: Zeroizing<[u8; 32]>,
    id: [u8; 16],
    private: <Kem as KemTrait>::PrivateKey,
    expires: u64,
}

/// Where a request came from, kept to seal the one reply.
pub struct ReplyTo([u8; 32]);

impl Offer {
    /// Open an offer for `address` until `now + OFFER_SECONDS`; returns it with
    /// the link text to show locally.
    pub fn new(address: &cmsh::Address, now: u64) -> Result<(Self, String)> {
        let secret = Zeroizing::new(random::<32>()?);
        let id = random::<16>()?;
        let (private, public) = <Kem as KemTrait>::derive_keypair(&random::<32>()?);
        let scheme = address.scheme().as_str().as_bytes();
        let address_bytes = address.bytes();
        let address_len =
            u16::try_from(address_bytes.len()).map_err(|_| ErrorCode::InvalidRequest)?;
        let mut bytes = vec![VERSION];
        bytes.extend_from_slice(&*secret);
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&public.to_bytes());
        bytes.push(u8::try_from(scheme.len()).map_err(|_| ErrorCode::InvalidRequest)?);
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
            },
            link,
        ))
    }

    /// Exclusive deadline of this offer in unix seconds.
    pub fn expires(&self) -> u64 {
        self.expires
    }

    /// Open the new device's sealed request. A message not sealed under this
    /// offer's link is Refused; a message after the deadline is Unauthorized.
    pub fn open_request(&self, message: &[u8], now: u64) -> Result<(Zeroizing<Vec<u8>>, ReplyTo)> {
        if now >= self.expires {
            return Err(ErrorCode::Unauthorized);
        }
        let plaintext = open(&self.private, &self.secret, &self.id, INFO_REQUEST, message)?;
        let reply: [u8; 32] = plaintext
            .get(..32)
            .and_then(|key| key.try_into().ok())
            .ok_or(ErrorCode::InvalidRequest)?;
        Ok((Zeroizing::new(plaintext[32..].to_vec()), ReplyTo(reply)))
    }

    /// Seal the grant for the requester; consumes the offer, so one link serves
    /// exactly one pairing.
    pub fn seal_grant(self, to: &ReplyTo, grant: &[u8]) -> Result<Vec<u8>> {
        seal(&to.0, &self.secret, &self.id, INFO_GRANT, grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> cmsh::Address {
        cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![7; 35]).unwrap()
    }

    #[test]
    fn a_link_carries_one_exchange_each_way_and_nothing_else() {
        let (offer, text) = Offer::new(&address(), 1_000).unwrap();
        assert!(text.starts_with(PREFIX) && text.len() <= MAX_LINK_CHARS);
        let link = Link::parse(&text).unwrap();
        assert_eq!(link.address(), &address());
        let (message, awaiting) = link.seal_request(b"public pairing request").unwrap();
        let (request, reply_to) = offer.open_request(&message, 1_100).unwrap();
        assert_eq!(&request[..], b"public pairing request");
        let grant = offer
            .seal_grant(&reply_to, b"grant with sealed root")
            .unwrap();
        assert_eq!(
            &awaiting.open_grant(&grant).unwrap()[..],
            b"grant with sealed root"
        );
    }

    #[test]
    fn a_stranger_without_the_link_secret_cannot_make_or_read_a_message() {
        let (offer, text) = Offer::new(&address(), 1_000).unwrap();
        let (_, other_text) = Offer::new(&address(), 1_000).unwrap();
        // Another offer's link cannot talk to this offer.
        let (message, _) = Link::parse(&other_text)
            .unwrap()
            .seal_request(b"x")
            .unwrap();
        assert_eq!(
            offer.open_request(&message, 1_001).err(),
            Some(ErrorCode::Refused)
        );
        // A tampered message and a truncated one are refused without detail.
        let (mut message, awaiting) = Link::parse(&text).unwrap().seal_request(b"x").unwrap();
        let last = message.len() - 1;
        message[last] ^= 1;
        assert_eq!(
            offer.open_request(&message, 1_001).err(),
            Some(ErrorCode::Refused)
        );
        assert_eq!(
            offer.open_request(&message[..ENC], 1_001).err(),
            Some(ErrorCode::InvalidRequest)
        );
        // A reply not sealed under this link is refused by the requester.
        assert_eq!(
            awaiting.open_grant(&message).err(),
            Some(ErrorCode::Refused)
        );
    }

    #[test]
    fn an_offer_expires_and_serves_one_pairing() {
        let (offer, text) = Offer::new(&address(), 1_000).unwrap();
        assert_eq!(offer.expires(), 1_000 + OFFER_SECONDS);
        let (message, _) = Link::parse(&text).unwrap().seal_request(b"x").unwrap();
        assert_eq!(
            offer.open_request(&message, 1_000 + OFFER_SECONDS).err(),
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
            .decode(text[PREFIX.len()..].as_bytes())
            .unwrap();
        raw[0] = 2;
        let versioned = format!("{PREFIX}{}", BASE64URL_NOPAD.encode(&raw));
        assert_eq!(
            Link::parse(&versioned).err(),
            Some(ErrorCode::UnsupportedVersion)
        );
    }
}
