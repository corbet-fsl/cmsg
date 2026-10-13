//! Room link: the one place where the door's Board learns whether it carries
//! the anonymous room transport. `cbrd::Board<T, R>` has its room calls only
//! for `R = AnonymousRooms<_>`; Rust has no specialization, so the door's
//! generic `BoardBinding<T, R>` reaches them through this trait. The plain
//! `()` link has no rooms and refuses every room call before any traffic.
use cbrd::clnk::{self, cmbl, ErrorCode as LinkError};
use std::{future::Future, pin::Pin};

pub(crate) type RoomFuture<'a, X> = Pin<Box<dyn Future<Output = Result<X, LinkError>> + 'a>>;

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
        assert!(!<() as RoomLink>::ROOMS);
        assert!(<clnk::AnonymousRooms<Nowhere> as RoomLink>::ROOMS);
    }
}
