//! Portable framing contract. These tests prove byte framing, not Tor routing.
use cmsg::{Error, FrameCodec, MAX_WIRE_BYTES};

#[test]
fn fragmented_headers_and_bodies_preserve_binary_frame_boundaries() {
    let mut codec = FrameCodec::new(128).unwrap();
    let first = codec.encode(&[0, 255, 128, 1]).unwrap();
    let second = codec.encode(b"next").unwrap();
    let wire = [first, second].concat();
    let mut decoded = Vec::new();
    for chunk in wire.chunks(3) {
        decoded.extend(codec.push(chunk).unwrap());
    }
    assert_eq!(decoded, vec![vec![0, 255, 128, 1], b"next".to_vec()]);
    codec.finish().unwrap();
    assert_eq!(codec.push(&[0]), Err(Error::Transport));
}

#[test]
fn invalid_frame_header_poisoning_prevents_reusing_partial_state() {
    for length in [0u32, 65, u32::MAX] {
        let mut codec = FrameCodec::new(64).unwrap();
        assert_eq!(
            codec.push(&length.to_be_bytes()),
            Err(Error::InvalidMessage)
        );
        assert_eq!(codec.push(&[0, 0, 0, 1, 42]), Err(Error::Transport));
        assert_eq!(codec.encode(b"retry"), Err(Error::Transport));
    }
}

#[test]
fn truncated_frames_fail_closed_at_eof() {
    for partial in [vec![0], vec![0, 0, 0, 3, 1, 2]] {
        let mut codec = FrameCodec::new(64).unwrap();
        assert!(codec.push(&partial).unwrap().is_empty());
        assert_eq!(codec.finish(), Err(Error::Transport));
        assert_eq!(codec.push(&[]), Err(Error::Transport));
    }
}

#[test]
fn invalid_outbound_sizes_and_oversized_chunks_fail_closed() {
    for payload in [vec![], vec![1; 65]] {
        let mut codec = FrameCodec::new(64).unwrap();
        assert_eq!(codec.encode(&payload), Err(Error::InvalidMessage));
        assert_eq!(codec.encode(b"retry"), Err(Error::Transport));
    }
    let mut codec = FrameCodec::new(64).unwrap();
    assert_eq!(
        codec.push(&vec![0; MAX_WIRE_BYTES + 5]),
        Err(Error::InvalidMessage)
    );
    assert_eq!(codec.push(&[]), Err(Error::Transport));
}

#[test]
fn portable_codec_uses_the_native_uint32_wire_format() {
    let mut codec = FrameCodec::new(256).unwrap();
    let wire = codec.encode(&[255; 256]).unwrap();
    assert_eq!(&wire[..4], &[0, 0, 1, 0]);
    assert_eq!(wire.len(), 260);
    assert_eq!(codec.push(&wire).unwrap(), vec![vec![255; 256]]);
    assert!(FrameCodec::new(0).is_err());
    assert!(FrameCodec::new(MAX_WIRE_BYTES + 1).is_err());
}
