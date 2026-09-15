//! Bounded byte framing, independent of transport routing or anonymity.
use crate::{Error, MAX_WIRE_BYTES};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
#[cfg(not(target_arch = "wasm32"))]
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

/// Incremental uint32 big-endian framing for native and browser byte streams.
/// This codec performs no I/O. The caller owns deadlines and transport closure.
/// Each input chunk is bounded to MAX_WIRE_BYTES + 4 bytes; split larger chunks
/// before submitting them. Any malformed frame or EOF closes the codec.
pub struct FrameCodec {
    max_frame_bytes: usize,
    header: [u8; 4],
    header_len: usize,
    expected: Option<usize>,
    payload: Vec<u8>,
    closed: bool,
}

impl FrameCodec {
    pub fn new(max_frame_bytes: usize) -> Result<Self, Error> {
        if max_frame_bytes == 0 || max_frame_bytes > MAX_WIRE_BYTES {
            return Err(Error::InvalidState);
        }
        Ok(Self {
            max_frame_bytes,
            header: [0; 4],
            header_len: 0,
            expected: None,
            payload: Vec::new(),
            closed: false,
        })
    }

    pub fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.closed {
            return Err(Error::Transport);
        }
        if payload.is_empty() || payload.len() > self.max_frame_bytes {
            self.close();
            return Err(Error::InvalidMessage);
        }
        let mut wire = Vec::with_capacity(payload.len() + 4);
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);
        Ok(wire)
    }

    pub fn push(&mut self, mut chunk: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        if self.closed {
            return Err(Error::Transport);
        }
        if chunk.len() > MAX_WIRE_BYTES + 4 {
            self.close();
            return Err(Error::InvalidMessage);
        }
        let mut frames = Vec::new();
        while !chunk.is_empty() {
            if self.expected.is_none() {
                let count = (4 - self.header_len).min(chunk.len());
                self.header[self.header_len..self.header_len + count]
                    .copy_from_slice(&chunk[..count]);
                self.header_len += count;
                chunk = &chunk[count..];
                if self.header_len != 4 {
                    continue;
                }
                let length = u32::from_be_bytes(self.header) as usize;
                if length == 0 || length > self.max_frame_bytes {
                    self.close();
                    return Err(Error::InvalidMessage);
                }
                self.expected = Some(length);
            }
            let length = self.expected.ok_or(Error::InvalidState)?;
            let count = (length - self.payload.len()).min(chunk.len());
            self.payload.extend_from_slice(&chunk[..count]);
            chunk = &chunk[count..];
            if self.payload.len() == length {
                frames.push(std::mem::take(&mut self.payload));
                self.expected = None;
                self.header_len = 0;
            }
        }
        Ok(frames)
    }

    /// End of stream is valid only between complete frames.
    pub fn finish(&mut self) -> Result<(), Error> {
        let complete = !self.closed && self.header_len == 0 && self.expected.is_none();
        self.close();
        if complete {
            Ok(())
        } else {
            Err(Error::Transport)
        }
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.payload.clear();
        self.header = [0; 4];
        self.header_len = 0;
        self.expected = None;
    }
}

/// An owned byte stream with nonzero uint32 big-endian frames.
///
/// This codec does not authenticate a route. Obtain an anonymous application
/// stream from a trusted onion transport before wrapping it. A raw socket alone
/// is not evidence of Tor, and this type never chooses or changes a destination.
/// Framing failures and cancelled operations must make this wrapper unusable.
#[cfg(not(target_arch = "wasm32"))]
pub struct FramedStream<S> {
    stream: Option<S>,
    max_frame_bytes: usize,
    frame_timeout: Duration,
}

#[cfg(not(target_arch = "wasm32"))]
impl<S: AsyncRead + AsyncWrite + Unpin> FramedStream<S> {
    /// Require 1..=MAX_WIRE_BYTES and a positive deadline of at most 60 seconds.
    /// Each read or write gets one deadline covering its whole frame; a write
    /// includes flushing. Payload bytes remain opaque to this generic codec.
    pub fn new(stream: S, max_frame_bytes: usize, frame_timeout: Duration) -> Result<Self, Error> {
        if max_frame_bytes == 0
            || max_frame_bytes > MAX_WIRE_BYTES
            || frame_timeout.is_zero()
            || frame_timeout > Duration::from_secs(60)
        {
            return Err(Error::InvalidState);
        }
        Ok(Self {
            stream: Some(stream),
            max_frame_bytes,
            frame_timeout,
        })
    }

    pub async fn send_frame(&mut self, payload: &[u8]) -> Result<(), Error> {
        // While an operation is in flight the wrapper owns no reusable stream.
        // An error or a dropped future therefore closes this owned stream,
        // rather than allowing another frame after an unknown partial write.
        let mut stream = self.stream.take().ok_or(Error::Transport)?;
        if payload.is_empty() || payload.len() > self.max_frame_bytes {
            return Err(Error::InvalidMessage);
        }
        let header = (payload.len() as u32).to_be_bytes();
        timeout(self.frame_timeout, async {
            stream.write_all(&header).await?;
            stream.write_all(payload).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| Error::Transport)?
        .map_err(|_| Error::Transport)?;
        self.stream = Some(stream);
        Ok(())
    }

    pub async fn receive_frame(&mut self) -> Result<Vec<u8>, Error> {
        let mut stream = self.stream.take().ok_or(Error::Transport)?;
        let payload = timeout(self.frame_timeout, async {
            let mut header = [0; 4];
            stream
                .read_exact(&mut header)
                .await
                .map_err(|_| Error::Transport)?;
            let length = u32::from_be_bytes(header) as usize;
            if length == 0 || length > self.max_frame_bytes {
                return Err(Error::InvalidMessage);
            }
            let mut payload = vec![0; length];
            stream
                .read_exact(&mut payload)
                .await
                .map_err(|_| Error::Transport)?;
            Ok(payload)
        })
        .await
        .map_err(|_| Error::Transport)??;
        self.stream = Some(stream);
        Ok(payload)
    }
}
