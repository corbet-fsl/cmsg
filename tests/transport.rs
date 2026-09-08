mod common;
use cmsg::{OnionEndpoint, OnionTransport, Received};
use sha3::{Digest, Sha3_256};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

fn endpoint() -> (String, OnionEndpoint) {
    let key = [42u8; 32];
    let mut checksum = Sha3_256::new();
    checksum.update(b".onion checksum");
    checksum.update(key);
    checksum.update([3]);
    let checksum = checksum.finalize();
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&checksum[..2]);
    bytes.push(3);
    let host = format!(
        "{}.onion",
        data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
    );
    let parsed = OnionEndpoint::parse(&host, 80).unwrap();
    (host, parsed)
}
async fn socks_request(stream: &mut TcpStream) -> (Vec<u8>, String) {
    assert_eq!(stream.read_u8().await.unwrap(), 5);
    let n = stream.read_u8().await.unwrap() as usize;
    let mut methods = vec![0; n];
    stream.read_exact(&mut methods).await.unwrap();
    assert!(methods.contains(&2));
    stream.write_all(&[5, 2]).await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), 1);
    let n = stream.read_u8().await.unwrap() as usize;
    let mut user = vec![0; n];
    stream.read_exact(&mut user).await.unwrap();
    let n = stream.read_u8().await.unwrap() as usize;
    let mut pass = vec![0; n];
    stream.read_exact(&mut pass).await.unwrap();
    assert_eq!(user, pass);
    assert!(user.len() >= 32);
    stream.write_all(&[1, 0]).await.unwrap();
    let mut connect = [0; 4];
    stream.read_exact(&mut connect).await.unwrap();
    assert_eq!(connect, [5, 1, 0, 3]); // Domain name forwarded through Tor, no DNS lookup.
    let n = stream.read_u8().await.unwrap() as usize;
    let mut host = vec![0; n];
    stream.read_exact(&mut host).await.unwrap();
    assert_eq!(stream.read_u16().await.unwrap(), 80);
    (user, String::from_utf8(host).unwrap())
}
#[tokio::test]
async fn proxy_failure_cannot_redirect_to_a_clearnet_trap() {
    let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = trap.local_addr().unwrap().port();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transport = OnionTransport::new(proxy.local_addr().unwrap()).unwrap();
    let (host, peer) = endpoint();
    let fake_proxy = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let (_, requested) = socks_request(&mut stream).await;
        assert_eq!(requested, host);
        let [high, low] = port.to_be_bytes();
        stream
            .write_all(&[5, 4, 0, 1, 127, 0, 0, 1, high, low])
            .await
            .unwrap();
    });
    assert!(transport.connect(&peer).await.is_err());
    fake_proxy.await.unwrap();
    assert!(timeout(Duration::from_millis(150), trap.accept())
        .await
        .is_err());
}
#[tokio::test]
async fn each_connection_requests_new_socks_isolation_and_only_uses_proxy_socket() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let transport = OnionTransport::new(proxy.local_addr().unwrap()).unwrap();
    let (_, peer) = endpoint();
    let fake_proxy = tokio::spawn(async move {
        let mut previous = None;
        for _ in 0..2 {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let (user, _) = socks_request(&mut stream).await;
            assert_ne!(previous.as_ref(), Some(&user));
            previous = Some(user);
            // BND.ADDR is not a redirect instruction; data stays on this socket.
            stream
                .write_all(&[5, 0, 0, 1, 203, 0, 113, 1, 0, 80])
                .await
                .unwrap();
            stream.write_all(b"proxy-stream").await.unwrap();
        }
    });
    for _ in 0..2 {
        let mut stream = transport.connect(&peer).await.unwrap();
        let mut bytes = [0; 12];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"proxy-stream");
    }
    fake_proxy.await.unwrap();
}
#[tokio::test]
async fn received_markup_cannot_trigger_a_tracking_request() {
    let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let text = format!("<img src='http://{}/identify'>", trap.local_addr().unwrap());
    let mut a = common::member();
    let mut b = common::member();
    a.create_group().unwrap();
    b.join(&a.add(&b.key_package().unwrap()).unwrap().welcome)
        .unwrap();
    let received = b.receive(&a.send(text.as_bytes()).unwrap()).unwrap();
    assert_eq!(format!("{received:?}"), "Text([redacted])");
    assert!(matches!(received, Received::Text(value) if value.text == text));
    assert!(timeout(Duration::from_millis(150), trap.accept())
        .await
        .is_err());
}
