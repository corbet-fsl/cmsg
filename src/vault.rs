use crate::Error;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
const STORE_HEADER: &[u8] = b"cmsg-store-v1\0";
pub(crate) fn seal(
    plaintext: &[u8],
    wrapping_key: &[u8; 32],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad = store_aad(context)?;
    if plaintext.len() > MAX_STORE_BYTES - 128 {
        return Err(Error::InvalidStore);
    }
    let data_key = Zeroizing::new(random::<32>()?);
    let wrap_nonce = random::<24>()?;
    let data_nonce = random::<24>()?;
    let wrapped = XChaCha20Poly1305::new(wrapping_key.into())
        .encrypt(
            XNonce::from_slice(&wrap_nonce),
            Payload {
                msg: data_key.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::InvalidStore)?;
    let encrypted = XChaCha20Poly1305::new((&*data_key).into())
        .encrypt(
            XNonce::from_slice(&data_nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::InvalidStore)?;
    let mut output = STORE_HEADER.to_vec();
    output.extend_from_slice(&wrap_nonce);
    output.extend_from_slice(&wrapped);
    output.extend_from_slice(&data_nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}
pub(crate) fn open(
    sealed: &[u8],
    wrapping_key: &[u8; 32],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let aad = store_aad(context)?;
    let offset = STORE_HEADER.len();
    if sealed.len() < offset + 24 + 48 + 24 + 16
        || sealed.len() > MAX_STORE_BYTES
        || !sealed.starts_with(STORE_HEADER)
    {
        return Err(Error::InvalidStore);
    }
    let key = Zeroizing::new(
        XChaCha20Poly1305::new(wrapping_key.into())
            .decrypt(
                XNonce::from_slice(&sealed[offset..offset + 24]),
                Payload {
                    msg: &sealed[offset + 24..offset + 72],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::InvalidStore)?,
    );
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::InvalidStore)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&sealed[offset + 72..offset + 96]),
                Payload {
                    msg: &sealed[offset + 96..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::InvalidStore)?,
    );

    Ok(plaintext)
}
fn store_aad(context: &[u8]) -> Result<Vec<u8>, Error> {
    if context.is_empty() || context.len() > 128 {
        return Err(Error::InvalidStore);
    }
    let mut aad = STORE_HEADER.to_vec();
    aad.extend_from_slice(context);
    Ok(aad)
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| Error::Randomness)?;
    Ok(value)
}
