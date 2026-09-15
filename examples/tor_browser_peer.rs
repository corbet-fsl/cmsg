#[path = "../tests/common/mod.rs"]
mod synthetic;

use cmsg::{FramedStream, MemberIdentity, OnionEndpoint, OnionTransport, Received, MAX_WIRE_BYTES};
use std::time::Duration;

fn core<T>(result: Result<T, cmsg::Error>) -> Result<T, &'static str> {
    result.map_err(|_| "cmsg fixture protocol failed")
}

// Disposable test participant. Its synthetic keys must never be reused by an app.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 { return Err("expected SOCKS_ADDR BROWSER_ONION VIRTUAL_PORT".into()); }
    let endpoint = core(OnionEndpoint::parse(&args[2], args[3].parse()?))?;
    let transport = core(OnionTransport::new(args[1].parse()?))?;
    let stream = core(transport.connect(&endpoint).await)?;
    let mut stream = core(FramedStream::new(stream, MAX_WIRE_BYTES, Duration::from_secs(60)))?;
    let identity = core(MemberIdentity::new("synthetic-community"))?;
    let mut member = synthetic::root_device(&identity);
    core(stream.send_frame(&core(member.key_package())?).await)?;
    core(member.join(&core(stream.receive_frame().await)?))?;
    core(stream.send_frame(&core(member.send_bytes(&[0, 255, 128, 7, 0, 9]))?).await)?;
    match core(member.receive(&core(stream.receive_frame().await)?))? {
        Received::Bytes(data) if data.bytes == [254, 0, 129, 4, 0, 3] => (),
        _ => return Err("browser/native ciphertext mismatch".into()),
    }
    core(stream.send_frame(b"cmsg-native-verified").await)?;
    println!("{{\"nativeFramedStream\":true,\"rootAuthorizedMlsBinaryBothDirections\":true}}");
    Ok(())
}
