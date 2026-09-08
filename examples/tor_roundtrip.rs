#[path = "../tests/common/mod.rs"]
mod synthetic;
// Synthetic live Tor onion experiment; never run a hosted client with real keys.
use cmsg::{OnionEndpoint, OnionTransport, Received};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 && args.len() != 5 {
        return Err("expected SOCKS_ADDR ONION_HOST SERVICE_BIND [ONION_PORT]".into());
    }
    let transport = OnionTransport::new(args[1].parse()?).map_err(|_| "route invalid")?;
    let port = args.get(4).map(|p| p.parse()).transpose()?.unwrap_or(80);
    let endpoint = OnionEndpoint::parse(&args[2], port).map_err(|_| "onion invalid")?;
    let listener = TcpListener::bind(&args[3]).await?;
    let mut sender = synthetic::member();
    let mut receiver = synthetic::member();
    sender.create_group().map_err(|_| "MLS create")?;
    receiver
        .join(
            &sender
                .add(&receiver.key_package().map_err(|_| "key package")?)
                .map_err(|_| "MLS add")?
                .welcome,
        )
        .map_err(|_| "MLS join")?;
    let wire = sender
        .send(b"synthetic onion round trip")
        .map_err(|_| "encrypt")?;
    let receive = tokio::spawn(async move {
        let (mut stream, source) = listener.accept().await.map_err(|_| "accept")?;
        // A Tor hidden-service listener sees the local Tor process, not the caller.
        if !source.ip().is_loopback() {
            return Err("unexpected source address");
        }
        let length = stream.read_u32().await.map_err(|_| "frame")? as usize;
        if length > cmsg::MAX_WIRE_BYTES {
            return Err("oversize frame");
        }
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await.map_err(|_| "read")?;
        match receiver.receive(&payload).map_err(|_| "decrypt")? {
            Received::Text(text) if text.text == "synthetic onion round trip" => (),
            _ => return Err("incorrect plaintext"),
        }
        stream.write_all(b"OK").await.map_err(|_| "ack")?;
        Ok(())
    });
    let mut stream = transport
        .connect(&endpoint)
        .await
        .map_err(|_| "onion connect failed")?;
    stream.write_u32(wire.len() as u32).await?;
    stream.write_all(&wire).await?;
    let mut ack = [0; 2];
    stream.read_exact(&mut ack).await?;
    assert_eq!(&ack, b"OK");
    receive.await??;
    println!("{{\"onion_round_trip\":true,\"plaintext_equal\":true,\"recipient_saw_only_local_tor\":true}}");
    Ok(())
}
