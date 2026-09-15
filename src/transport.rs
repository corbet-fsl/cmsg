use crate::Error;
use sha3::{Digest, Sha3_256};
#[cfg(not(target_arch = "wasm32"))]
use std::{net::SocketAddr, time::Duration};
#[cfg(not(target_arch = "wasm32"))]
use tokio::net::TcpStream;
#[cfg(not(target_arch = "wasm32"))]
use tokio_socks::tcp::Socks5Stream;

/// A checksum-validated v3 onion service address. No URLs, IPs, DNS names,
/// alternate routing hints or redirects can be represented by this type.
#[derive(Clone)]
pub struct OnionEndpoint {
    host: String,
    port: u16,
}
impl OnionEndpoint {
    pub fn parse(host: &str, port: u16) -> Result<Self, Error> {
        if port == 0 || host.len() != 62 || !host.ends_with(".onion") {
            return Err(Error::InvalidRoute);
        }
        let name = &host[..56];
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(Error::InvalidRoute);
        }
        let bytes = data_encoding::BASE32_NOPAD
            .decode(name.to_uppercase().as_bytes())
            .map_err(|_| Error::InvalidRoute)?;
        if bytes.len() != 35 || bytes[34] != 3 {
            return Err(Error::InvalidRoute);
        }
        let mut checksum = Sha3_256::new();
        checksum.update(b".onion checksum");
        checksum.update(&bytes[..32]);
        checksum.update([3]);
        if checksum.finalize()[..2] != bytes[32..34] {
            return Err(Error::InvalidRoute);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Only talks to a trusted local Tor SOCKS listener. Configure Tor with
/// `IsolateSOCKSAuth`; fresh credentials isolate each connection. A loopback
/// address is a containment check, not cryptographic proof the process is Tor.
/// The application/OS must own and verify that listener; no peer may configure it.
#[cfg(not(target_arch = "wasm32"))]
pub struct OnionTransport {
    proxy: SocketAddr,
}
#[cfg(not(target_arch = "wasm32"))]
impl OnionTransport {
    pub fn new(proxy: SocketAddr) -> Result<Self, Error> {
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err(Error::InvalidRoute);
        }
        Ok(Self { proxy })
    }
    pub async fn connect(&self, endpoint: &OnionEndpoint) -> Result<TcpStream, Error> {
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|_| Error::Randomness)?;
        let isolation = data_encoding::HEXLOWER.encode(&random);
        tokio::time::timeout(
            Duration::from_secs(45),
            Socks5Stream::connect_with_password(
                self.proxy,
                (endpoint.host.as_str(), endpoint.port),
                &isolation,
                &isolation,
            ),
        )
        .await
        .map_err(|_| Error::Transport)?
        .map(Socks5Stream::into_inner)
        .map_err(|_| Error::Transport)
    }
}
