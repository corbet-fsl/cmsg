# Native Tor owner

With `native-tor`, trusted construction may call `Door::bind_native_tor` with an
original Keys `NativeTorInitializer`. The Door checks its community and member
origin, consumes the capability directly into original Arti, starts the original
Tor Node, and waits for the original onion listener through Ferry and Mesh.
No raw key, endpoint override or network configuration is an API action.

The retained Mesh owns a stop guard. Failed or cancelled initialization, normal
disconnect, owner drop and drained shutdown all stop the original Node. Original
Keys custody invalidation also stops that same Node. Background receive pumps
cannot keep the network alive after the owner releases it.

This is the message-transport constructor needed by the native test bed. It does
not provide Records, authenticated discovery, Inbox receive dispatch, or completed
custody. It does not set `runtime.status` to ready. `mesh.status` reports only the
existing original Mesh measurements; merely building a transport is insufficient
for the two-member voucher/profile/forum/Wave/chat journey.

Required pending execution: compile the exact Keys/Arti/Mesh closure; run through
the existing private Tor fixture; verify two real onion listeners and messages;
cancel bootstrap and publication; disconnect and drop while pumps hold handles;
lock/rotate Keys and confirm no old service remains; then exercise actual Inbox
and Records with this same Door through cmeet. No local build/test was performed.
