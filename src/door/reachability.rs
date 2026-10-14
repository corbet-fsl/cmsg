//! The reachability descriptor a member publishes in the profile: the device's OWN bound Mesh
//! addresses, encoded canonically. It is built here from the live listener, never from request
//! data, and a peer decodes it to learn where the member can be reached.
use super::*;

const VERSION: u8 = 1;

/// `version | count u8 | (scheme_len u8 | scheme | address_len u16 BE | address)*`.
pub fn encode(addresses: &[cmsh::Address]) -> Result<Vec<u8>> {
    let mut out = vec![VERSION, u8::try_from(addresses.len()).map_err(|_| ErrorCode::InvalidRequest)?];
    for address in addresses {
        let scheme = address.scheme().as_str().as_bytes();
        out.push(u8::try_from(scheme.len()).map_err(|_| ErrorCode::InvalidRequest)?);
        out.extend_from_slice(scheme);
        out.extend_from_slice(
            &u16::try_from(address.bytes().len())
                .map_err(|_| ErrorCode::InvalidRequest)?
                .to_be_bytes(),
        );
        out.extend_from_slice(address.bytes());
    }
    if out.len() > cbrd::cpfl::MAX_REACHABILITY_BYTES {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(out)
}

/// Inverse of [`encode`]; any malformed or trailing byte refuses the whole descriptor.
pub fn decode(bytes: &[u8]) -> Result<Vec<cmsh::Address>> {
    let mut at = bytes;
    let mut take = |n: usize| -> Result<&[u8]> {
        if at.len() < n {
            return Err(ErrorCode::InvalidRequest);
        }
        let (head, rest) = at.split_at(n);
        at = rest;
        Ok(head)
    };
    if take(1)?[0] != VERSION {
        return Err(ErrorCode::InvalidRequest);
    }
    let count = usize::from(take(1)?[0]);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let scheme_len = usize::from(take(1)?[0]);
        let scheme = std::str::from_utf8(take(scheme_len)?).map_err(|_| ErrorCode::InvalidRequest)?;
        let scheme = cmsh::Scheme::new(scheme).map_err(|_| ErrorCode::InvalidRequest)?;
        let len = usize::from(u16::from_be_bytes(take(2)?.try_into().map_err(|_| ErrorCode::InvalidRequest)?));
        out.push(cmsh::Address::new(scheme, take(len)?.to_vec()).map_err(|_| ErrorCode::InvalidRequest)?);
    }
    if !at.is_empty() {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(tag: u8) -> cmsh::Address {
        cmsh::Address::new(cmsh::Scheme::new("tor").unwrap(), vec![tag; 35]).unwrap()
    }

    #[test]
    fn round_trips_and_refuses_damage() {
        let all = vec![address(1), address(2)];
        let bytes = encode(&all).unwrap();
        assert_eq!(decode(&bytes).unwrap(), all);
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode(&longer).is_err());
        assert!(decode(&[9, 0]).is_err());
        assert_eq!(decode(&encode(&[]).unwrap()).unwrap(), vec![]);
    }
}
