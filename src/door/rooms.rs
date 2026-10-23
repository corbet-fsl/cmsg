//! Room link: the one place where the door's Board learns whether it carries
//! the anonymous room transport. `cbrd::Board<T, R>` has its room calls only
//! for `R = AnonymousRooms<_>`; Rust has no specialization, so the door's
//! generic `BoardBinding<T, R>` reaches them through this trait. The plain
//! `()` link has no rooms and refuses every room call before any traffic.
use cbrd::clnk::{self, cmbl, ErrorCode as LinkError};
use std::{future::Future, pin::Pin};

pub(crate) type RoomFuture<'a, X> = Pin<Box<dyn Future<Output = Result<X, LinkError>> + 'a>>;

pub(crate) type JoinFuture<'a, X> = Pin<Box<dyn Future<Output = Result<X, ctnd::Error>> + 'a>>;

/// Hands out no waiting: a join attempt reads the room's traffic once per
/// attempt and a missed context commit is a restart, never a sleep in the door.
pub(crate) struct NoPause;
impl cbrd::Pause for NoPause {
    fn pause(&mut self) -> ctnd::PortFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

pub trait RoomLink: Sized + 'static {
    /// Whether this link carries the anonymous room transport at all.
    const ROOMS: bool = false;

    fn room_connection<T: clnk::Transport>(
        _board: &cbrd::Board<T, Self>,
        _room: cmbl::Id,
    ) -> Result<cmbl::Id, LinkError> {
        Err(LinkError::Rejected)
    }
    /// Assembly transport only; membership stays with Attend/Threads.
    fn execute_room<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _command: cmbl::Request,
    ) -> RoomFuture<'a, cmbl::Outcome> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    fn close_rooms<T: clnk::Transport>(_board: &mut cbrd::Board<T, Self>) {}
    /// The common room epoch request (signed by the device before it is sent).
    fn prepare_room_epoch<T: clnk::Transport>(
        _board: &cbrd::Board<T, Self>,
        _nonce: cmbl::Id,
    ) -> Result<cbrd::Prepared, LinkError> {
        Err(LinkError::Rejected)
    }
    fn receive_room_epoch<'a, T: clnk::Transport>(
        _board: &'a mut cbrd::Board<T, Self>,
        _prepared: cbrd::Prepared,
        _signature: Vec<u8>,
    ) -> RoomFuture<'a, ()> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// A blind room pass request for `room` (signed by the device).
    fn prepare_room_pass<T: clnk::Transport>(
        _board: &mut cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _operation: cmbl::Id,
        _nonce: cmbl::Id,
    ) -> Result<cbrd::Prepared, LinkError> {
        Err(LinkError::Rejected)
    }
    fn receive_room_pass<'a, T: clnk::Transport>(
        _board: &'a mut cbrd::Board<T, Self>,
        _prepared: cbrd::Prepared,
        _signature: Vec<u8>,
    ) -> RoomFuture<'a, cmbl::Id> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// Join a member room (consent already decided, evidence from a sealed
    /// member answer): see `cbrd::Board::join_room`.
    fn join_room<'a, T, K, B, S, A, C, P>(
        _board: &'a cbrd::Board<T, Self>,
        _input: cbrd::RoomJoinInput<'a, K, B, S, A, C, P>,
    ) -> JoinFuture<'a, cbrd::RoomJoined>
    where
        T: clnk::Transport,
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cbrd::cgrp::PolicySource,
        A: cbrd::cgrp::Authority,
        C: ckmg::Clock,
        P: cbrd::Pause + 'a,
    {
        Box::pin(async { Err(ctnd::Error::Unavailable) })
    }
    /// Admit a newcomer as an existing member; see `cbrd::Board::admit_room`.
    fn admit_room<'a, T, K, B, S, A, C>(
        _board: &'a cbrd::Board<T, Self>,
        _input: cbrd::RoomAdmitInput<'a, K, B, S, A, C>,
    ) -> JoinFuture<'a, cbrd::RoomAdmitted>
    where
        T: clnk::Transport,
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cbrd::cgrp::PolicySource,
        A: cbrd::cgrp::Authority,
        C: ckmg::Clock,
    {
        Box::pin(async { Err(ctnd::Error::Unavailable) })
    }
    /// Remove a member who announced its own leave; see `cbrd::Board::remove_room`.
    fn remove_room<'a, T, K, B, S, A, C>(
        _board: &'a cbrd::Board<T, Self>,
        _input: cbrd::RoomRemoveInput<'a, K, B, S, A, C>,
    ) -> JoinFuture<'a, cbrd::RoomAdmitted>
    where
        T: clnk::Transport,
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cbrd::cgrp::PolicySource,
        A: cbrd::cgrp::Authority,
        C: ckmg::Clock,
    {
        Box::pin(async { Err(ctnd::Error::Unavailable) })
    }
    /// Relay a member's leave notice (its signed Groups `Leave`) to the room.
    fn relay_room_notice<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _key: &'a cbrd::TransportKey,
        _companion: &'a cbrd::RoomCompanion,
    ) -> RoomFuture<'a, ()> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// The newcomers' ordered external commits after relay sequence `after`.
    fn room_joins<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _after: u64,
        _key: &'a cbrd::TransportKey,
    ) -> RoomFuture<'a, cbrd::JoinsRead> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// Every member frame the room still holds (sealed), for a member that
    /// catches up epoch by epoch.
    fn room_frames<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
    ) -> RoomFuture<'a, cbrd::RoomFrames> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// Relay one room secret (an MLS application message) to the room.
    fn relay_room_secret<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _key: &'a cbrd::TransportKey,
        _message: &'a [u8],
    ) -> RoomFuture<'a, ()> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// The room secrets after relay sequence `after` that open under `key`.
    fn room_secrets<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _after: u64,
        _key: &'a cbrd::TransportKey,
    ) -> RoomFuture<'a, cbrd::SecretsRead> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// Post a join request (fresh ephemeral key); returns its relay sequence.
    fn request_room_join<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _public_key: [u8; 32],
    ) -> RoomFuture<'a, u64> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// Live join requests a member can answer: `(request, ephemeral key)`.
    fn room_join_requests<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
    ) -> RoomFuture<'a, Vec<(u64, [u8; 32])>> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// A member answers request `to` with state sealed to the request's key.
    fn answer_room_join<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _to: u64,
        _sealed: Vec<u8>,
    ) -> RoomFuture<'a, ()> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
    /// Sealed answers to request `to`: `(ordering, counter, sealed)`.
    fn room_join_answers<'a, T: clnk::Transport>(
        _board: &'a cbrd::Board<T, Self>,
        _room: cmbl::Id,
        _to: u64,
    ) -> RoomFuture<'a, Vec<(cmbl::Id, u64, Vec<u8>)>> {
        Box::pin(async { Err(LinkError::Rejected) })
    }
}

impl RoomLink for () {}

impl<R: clnk::Transport + 'static> RoomLink for clnk::AnonymousRooms<R> {
    const ROOMS: bool = true;

    fn room_connection<T: clnk::Transport>(
        board: &cbrd::Board<T, Self>,
        room: cmbl::Id,
    ) -> Result<cmbl::Id, LinkError> {
        board.room_connection(room)
    }
    fn execute_room<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        command: cmbl::Request,
    ) -> RoomFuture<'a, cmbl::Outcome> {
        Box::pin(board.execute_room(command))
    }
    fn close_rooms<T: clnk::Transport>(board: &mut cbrd::Board<T, Self>) {
        board.close_rooms();
    }
    fn prepare_room_epoch<T: clnk::Transport>(
        board: &cbrd::Board<T, Self>,
        nonce: cmbl::Id,
    ) -> Result<cbrd::Prepared, LinkError> {
        board.prepare_room_epoch(nonce)
    }
    fn receive_room_epoch<'a, T: clnk::Transport>(
        board: &'a mut cbrd::Board<T, Self>,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> RoomFuture<'a, ()> {
        Box::pin(board.receive_room_epoch(prepared, signature))
    }
    fn prepare_room_pass<T: clnk::Transport>(
        board: &mut cbrd::Board<T, Self>,
        room: cmbl::Id,
        operation: cmbl::Id,
        nonce: cmbl::Id,
    ) -> Result<cbrd::Prepared, LinkError> {
        board.prepare_room_pass(room, operation, nonce)
    }
    fn receive_room_pass<'a, T: clnk::Transport>(
        board: &'a mut cbrd::Board<T, Self>,
        prepared: cbrd::Prepared,
        signature: Vec<u8>,
    ) -> RoomFuture<'a, cmbl::Id> {
        Box::pin(board.receive_room_pass(prepared, signature))
    }
    fn join_room<'a, T, K, B, S, A, C, P>(
        board: &'a cbrd::Board<T, Self>,
        input: cbrd::RoomJoinInput<'a, K, B, S, A, C, P>,
    ) -> JoinFuture<'a, cbrd::RoomJoined>
    where
        T: clnk::Transport,
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cbrd::cgrp::PolicySource,
        A: cbrd::cgrp::Authority,
        C: ckmg::Clock,
        P: cbrd::Pause + 'a,
    {
        Box::pin(board.join_room(input))
    }
    fn admit_room<'a, T, K, B, S, A, C>(
        board: &'a cbrd::Board<T, Self>,
        input: cbrd::RoomAdmitInput<'a, K, B, S, A, C>,
    ) -> JoinFuture<'a, cbrd::RoomAdmitted>
    where
        T: clnk::Transport,
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cbrd::cgrp::PolicySource,
        A: cbrd::cgrp::Authority,
        C: ckmg::Clock,
    {
        Box::pin(board.admit_room(input))
    }
    fn room_joins<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
        after: u64,
        key: &'a cbrd::TransportKey,
    ) -> RoomFuture<'a, cbrd::JoinsRead> {
        Box::pin(board.room_joins(room, after, key))
    }
    fn room_frames<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
    ) -> RoomFuture<'a, cbrd::RoomFrames> {
        Box::pin(board.room_frames(room))
    }
    fn relay_room_secret<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
        key: &'a cbrd::TransportKey,
        message: &'a [u8],
    ) -> RoomFuture<'a, ()> {
        Box::pin(board.relay_room_secret(room, key, message))
    }
    fn remove_room<'a, T, K, B, S, A, C>(
        board: &'a cbrd::Board<T, Self>,
        input: cbrd::RoomRemoveInput<'a, K, B, S, A, C>,
    ) -> JoinFuture<'a, cbrd::RoomAdmitted>
    where
        T: clnk::Transport,
        K: cthr::keys::Custody,
        B: cwst::backend::Backend,
        S: cbrd::cgrp::PolicySource,
        A: cbrd::cgrp::Authority,
        C: ckmg::Clock,
    {
        Box::pin(board.remove_room(input))
    }
    fn relay_room_notice<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
        key: &'a cbrd::TransportKey,
        companion: &'a cbrd::RoomCompanion,
    ) -> RoomFuture<'a, ()> {
        Box::pin(board.relay_room_notice(room, key, companion))
    }
    fn room_secrets<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
        after: u64,
        key: &'a cbrd::TransportKey,
    ) -> RoomFuture<'a, cbrd::SecretsRead> {
        Box::pin(board.room_secrets(room, after, key))
    }
    fn request_room_join<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
        public_key: [u8; 32],
    ) -> RoomFuture<'a, u64> {
        Box::pin(board.request_room_join(room, public_key))
    }
    fn room_join_requests<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
    ) -> RoomFuture<'a, Vec<(u64, [u8; 32])>> {
        Box::pin(board.room_join_requests(room))
    }
    fn answer_room_join<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
        to: u64,
        sealed: Vec<u8>,
    ) -> RoomFuture<'a, ()> {
        Box::pin(board.answer_room_join(room, to, sealed))
    }
    fn room_join_answers<'a, T: clnk::Transport>(
        board: &'a cbrd::Board<T, Self>,
        room: cmbl::Id,
        to: u64,
    ) -> RoomFuture<'a, Vec<(cmbl::Id, u64, Vec<u8>)>> {
        Box::pin(board.room_join_answers(room, to))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_anonymous_room_link_carries_rooms() {
        struct Nowhere;
        impl clnk::Transport for Nowhere {
            async fn post(&self, _: &str, _: Vec<u8>) -> Result<Vec<u8>, LinkError> {
                Err(LinkError::Transport)
            }
        }
        const { assert!(!<() as RoomLink>::ROOMS) };
        const { assert!(<clnk::AnonymousRooms<Nowhere> as RoomLink>::ROOMS) };
    }
}
