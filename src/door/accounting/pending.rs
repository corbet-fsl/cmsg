//! Upper binding sealed inside the pending genesis companion.
//!
//! The lower owner (CWLT) seals this value as opaque authenticated bytes together
//! with the exact private candidate. Reopen compares it with the freshly
//! authenticated account and never edits it: a changed origin, Lineage, device,
//! credential, Balance payload or outbox refuses and cannot be refreshed in place.
//! The signed outbox itself lives once, in the Store output committed with state
//! A; this binding carries only its SHA-256.
use super::*;

const DOMAIN: &[u8] = b"cmsg.account.pending.v1\0";
const MAX_ORIGIN: usize = 2048;
const MAX_CREDENTIAL: usize = 4096;
/// Leaves room under the lower owner's bound on the opaque upper value.
pub const MAX_OUTBOX: usize = 512 * 1024;

/// Exact origin, Lineage/device/credential digests, pinned Balance payload digest
/// and the SHA-256 of the original signed ApplyExtended outbox of one pending request.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingBinding {
    origin: String,
    lineage: [u8; 32],
    device: [u8; 32],
    credential: Vec<u8>,
    balance_payload: [u8; 32],
    outbox_digest: [u8; 32],
}

fn digest<T: serde::Serialize>(purpose: &[u8], value: &T) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(purpose);
    hash.update(serde_json::to_vec(value).map_err(|_| ErrorCode::Unauthorized)?);
    Ok(hash.finalize().into())
}

/// SHA-256 of a bounded, non-empty outbox.
pub(super) fn outbox_digest(outbox: &[u8]) -> Result<[u8; 32]> {
    if outbox.is_empty() || outbox.len() > MAX_OUTBOX {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(Sha256::digest(outbox).into())
}

fn put(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| ErrorCode::Unauthorized)?
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if input.len() < n {
        return Err(ErrorCode::Unauthorized);
    }
    let (head, tail) = input.split_at(n);
    *input = tail;
    Ok(head)
}

fn var<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8]> {
    let n = u32::from_be_bytes(
        take(input, 4)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)?,
    );
    take(
        input,
        usize::try_from(n).map_err(|_| ErrorCode::Unauthorized)?,
    )
    .and_then(|value| {
        if value.len() > max {
            Err(ErrorCode::Unauthorized)
        } else {
            Ok(value)
        }
    })
}

impl PendingBinding {
    pub(super) fn from_parts(
        origin: String,
        lineage: &ckmg::Lineage,
        device: &ckmg::PublicKey,
        credential: Vec<u8>,
        balance_payload: [u8; 32],
        outbox: &[u8],
    ) -> Result<Self> {
        Self::from_digests(
            origin,
            digest(b"lineage", lineage)?,
            digest(b"device", device)?,
            credential,
            balance_payload,
            outbox_digest(outbox)?,
        )
    }

    fn from_digests(
        origin: String,
        lineage: [u8; 32],
        device: [u8; 32],
        credential: Vec<u8>,
        balance_payload: [u8; 32],
        outbox_digest: [u8; 32],
    ) -> Result<Self> {
        if origin.is_empty()
            || origin.len() > MAX_ORIGIN
            || credential.is_empty()
            || credential.len() > MAX_CREDENTIAL
            || balance_payload == [0; 32]
            || outbox_digest == [0; 32]
        {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(Self {
            origin,
            lineage,
            device,
            credential,
            balance_payload,
            outbox_digest,
        })
    }

    /// SHA-256 of the original signed ApplyExtended outbox, which the Store keeps.
    pub fn outbox_digest(&self) -> [u8; 32] {
        self.outbox_digest
    }

    /// Canonical bytes for the lower owner's opaque authenticated upper value.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = DOMAIN.to_vec();
        put(&mut out, self.origin.as_bytes())?;
        out.extend_from_slice(&self.lineage);
        out.extend_from_slice(&self.device);
        put(&mut out, &self.credential)?;
        out.extend_from_slice(&self.balance_payload);
        out.extend_from_slice(&self.outbox_digest);
        Ok(out)
    }

    /// Exact inverse of `encode`; trailing bytes and any other domain refuse.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = bytes;
        if take(&mut input, DOMAIN.len())? != DOMAIN {
            return Err(ErrorCode::Unauthorized);
        }
        let origin = String::from_utf8(var(&mut input, MAX_ORIGIN)?.to_vec())
            .map_err(|_| ErrorCode::Unauthorized)?;
        let lineage = take(&mut input, 32)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)?;
        let device = take(&mut input, 32)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)?;
        let credential = var(&mut input, MAX_CREDENTIAL)?.to_vec();
        let balance_payload = take(&mut input, 32)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)?;
        let outbox_digest = take(&mut input, 32)?
            .try_into()
            .map_err(|_| ErrorCode::Unauthorized)?;
        if !input.is_empty() {
            return Err(ErrorCode::Unauthorized);
        }
        Self::from_digests(
            origin,
            lineage,
            device,
            credential,
            balance_payload,
            outbox_digest,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> PendingBinding {
        PendingBinding::from_digests(
            "https://member.example".into(),
            [1; 32],
            [2; 32],
            vec![3; 16],
            [4; 32],
            [5; 32],
        )
        .unwrap()
    }

    #[test]
    fn encoding_is_exact_and_every_bound_field_changes_it() {
        let base = binding();
        let bytes = base.encode().unwrap();
        assert!(PendingBinding::decode(&bytes).unwrap() == base);
        assert_eq!(base.outbox_digest(), [5; 32]);
        let mut other = base.clone();
        other.origin.push('x');
        assert_ne!(other.encode().unwrap(), bytes);
        for mutate in [
            (|b: &mut PendingBinding| b.lineage[0] ^= 1) as fn(&mut PendingBinding),
            |b| b.device[0] ^= 1,
            |b| b.credential[0] ^= 1,
            |b| b.balance_payload[0] ^= 1,
            |b| b.outbox_digest[0] ^= 1,
        ] {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_ne!(changed.encode().unwrap(), bytes);
            assert!(changed != base);
        }
    }

    #[test]
    fn decoding_refuses_truncation_trailing_bytes_domain_and_bounds() {
        let bytes = binding().encode().unwrap();
        for cut in 0..bytes.len() {
            assert!(PendingBinding::decode(&bytes[..cut]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PendingBinding::decode(&trailing).is_err());
        let mut domain = bytes.clone();
        domain[0] ^= 1;
        assert!(PendingBinding::decode(&domain).is_err());
        let ok = |origin: &str, credential: Vec<u8>, payload: [u8; 32], digest: [u8; 32]| {
            PendingBinding::from_digests(
                origin.into(),
                [1; 32],
                [2; 32],
                credential,
                payload,
                digest,
            )
        };
        assert!(ok("o", vec![1], [1; 32], [1; 32]).is_ok());
        assert!(ok("", vec![1], [1; 32], [1; 32]).is_err());
        assert!(ok("o", vec![], [1; 32], [1; 32]).is_err());
        assert!(ok("o", vec![1], [0; 32], [1; 32]).is_err());
        assert!(ok("o", vec![1], [1; 32], [0; 32]).is_err());
        assert!(ok(&"o".repeat(MAX_ORIGIN + 1), vec![1], [1; 32], [1; 32]).is_err());
        assert!(ok("o", vec![0; MAX_CREDENTIAL + 1], [1; 32], [1; 32]).is_err());
    }

    #[test]
    fn the_outbox_digest_is_the_sha256_of_a_bounded_non_empty_outbox() {
        assert_eq!(
            outbox_digest(b"abc").unwrap(),
            <[u8; 32]>::from(Sha256::digest(b"abc"))
        );
        assert!(outbox_digest(&[]).is_err());
        assert!(outbox_digest(&vec![0; MAX_OUTBOX]).is_ok());
        assert!(outbox_digest(&vec![0; MAX_OUTBOX + 1]).is_err());
        assert_ne!(outbox_digest(b"a").unwrap(), outbox_digest(b"b").unwrap());
    }
}
