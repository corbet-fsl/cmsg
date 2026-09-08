//! Real stream framing tests. Loopback/duplex streams do not prove anonymity.
use cmsg::{Error, FramedStream, MAX_WIRE_BYTES};
use std::time::Duration;
use tokio::{
    io::{duplex, AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

async fn pair(max: usize, deadline: Duration) -> (FramedStream<TcpStream>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (peer, _) = listener.accept().await.unwrap();
    (FramedStream::new(client, max, deadline).unwrap(), peer)
}

#[tokio::test]
async fn fragmented_and_consecutive_frames_preserve_exact_binary_bytes() {
    let (mut framed, mut peer) = pair(128, Duration::from_secs(1)).await;
    let first = [0, 255, 1, 128];
    let second = b"second frame";
    let writer = tokio::spawn(async move {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(first.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&(second.len() as u32).to_be_bytes());
        bytes.extend_from_slice(second);
        for part in bytes.chunks(3) {
            peer.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    assert_eq!(framed.receive_frame().await.unwrap(), first);
    assert_eq!(framed.receive_frame().await.unwrap(), second);
    writer.await.unwrap();
}

#[tokio::test]
async fn outbound_frame_is_big_endian_and_exactly_bounded() {
    let (stream, mut peer) = duplex(512);
    let mut framed = FramedStream::new(stream, 128, Duration::from_secs(1)).unwrap();
    let payload = [255; 128];
    framed.send_frame(&payload).await.unwrap();
    let mut header = [0; 4];
    peer.read_exact(&mut header).await.unwrap();
    assert_eq!(header, [0, 0, 0, 128]);
    let mut received = [0; 128];
    peer.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn zero_and_oversize_headers_fail_without_waiting_for_a_body() {
    for declared in [0, 65, (MAX_WIRE_BYTES + 1) as u32, u32::MAX] {
        let (mut framed, mut peer) = pair(64, Duration::from_secs(1)).await;
        peer.write_all(&declared.to_be_bytes()).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), framed.receive_frame())
                .await
                .unwrap(),
            Err(Error::InvalidMessage)
        );
        assert_eq!(framed.receive_frame().await, Err(Error::Transport));
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(2), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn truncated_headers_and_bodies_poison_the_stream() {
    for partial in [vec![0, 0], vec![0, 0, 0, 3, 1, 2]] {
        let (mut framed, mut peer) = pair(64, Duration::from_secs(1)).await;
        peer.write_all(&partial).await.unwrap();
        peer.shutdown().await.unwrap();
        assert_eq!(framed.receive_frame().await, Err(Error::Transport));
        assert_eq!(framed.receive_frame().await, Err(Error::Transport));
    }
}

#[tokio::test]
async fn slowloris_cannot_extend_the_whole_frame_deadline() {
    let (mut framed, mut peer) = pair(64, Duration::from_millis(90)).await;
    let trickle = tokio::spawn(async move {
        // Header and body each complete within 90ms; together they exceed it.
        // Neither per-byte nor separate header/body timers satisfy the contract.
        for byte in [0, 0, 0, 4, 1, 2, 3, 4] {
            if peer.write_all(&[byte]).await.is_err() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    });
    assert_eq!(
        timeout(Duration::from_secs(2), framed.receive_frame())
            .await
            .unwrap(),
        Err(Error::Transport)
    );
    trickle.abort();
    let _ = trickle.await;
    assert_eq!(framed.receive_frame().await, Err(Error::Transport));
}

#[tokio::test]
async fn blocked_writes_expire_and_poison_the_stream() {
    let (stream, _unread_peer) = duplex(1);
    let mut framed = FramedStream::new(stream, 32, Duration::from_millis(40)).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), framed.send_frame(&[1; 16]))
            .await
            .unwrap(),
        Err(Error::Transport)
    );
    assert_eq!(framed.send_frame(b"retry").await, Err(Error::Transport));
}

#[tokio::test]
async fn buffered_flush_is_inside_the_whole_write_deadline() {
    let (stream, _unread_peer) = duplex(1);
    // The frame fits the writer buffer, so its writes succeed without waiting;
    // only flushing it to the deliberately unread stream applies backpressure.
    let buffered = BufStream::with_capacity(32, 128, stream);
    let mut framed = FramedStream::new(buffered, 32, Duration::from_millis(40)).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), framed.send_frame(&[1; 16]))
            .await
            .unwrap(),
        Err(Error::Transport)
    );
    assert_eq!(framed.send_frame(b"retry").await, Err(Error::Transport));
}

#[tokio::test]
async fn cancellation_of_partial_reads_or_writes_poison_the_stream() {
    let (mut reader, mut peer) = pair(64, Duration::from_secs(1)).await;
    peer.write_all(&[0, 0]).await.unwrap();
    assert!(timeout(Duration::from_millis(20), reader.receive_frame())
        .await
        .is_err());
    assert_eq!(reader.receive_frame().await, Err(Error::Transport));

    let (stream, _unread_peer) = duplex(1);
    let mut writer = FramedStream::new(stream, 64, Duration::from_secs(1)).unwrap();
    assert!(
        timeout(Duration::from_millis(20), writer.send_frame(b"partial"))
            .await
            .is_err()
    );
    assert_eq!(writer.send_frame(b"retry").await, Err(Error::Transport));
}

#[tokio::test]
async fn invalid_outbound_sizes_never_write_a_header() {
    for size in [0, 129] {
        let (stream, mut peer) = duplex(512);
        let mut framed = FramedStream::new(stream, 128, Duration::from_secs(1)).unwrap();
        assert_eq!(
            framed.send_frame(&vec![1; size]).await,
            Err(Error::InvalidMessage)
        );
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        assert_eq!(framed.send_frame(b"retry").await, Err(Error::Transport));
    }
}

#[tokio::test]
async fn configuration_requires_finite_frame_and_deadline_bounds() {
    let (stream, _peer) = duplex(1);
    assert!(FramedStream::new(stream, MAX_WIRE_BYTES, Duration::from_secs(60)).is_ok());
    for (max, deadline) in [
        (0, Duration::from_secs(1)),
        (MAX_WIRE_BYTES + 1, Duration::from_secs(1)),
        (64, Duration::ZERO),
        (64, Duration::from_secs(61)),
    ] {
        let (stream, _peer) = duplex(1);
        assert!(matches!(
            FramedStream::new(stream, max, deadline),
            Err(Error::InvalidState)
        ));
    }
}
