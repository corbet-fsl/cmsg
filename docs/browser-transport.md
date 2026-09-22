# Browser Tor transport reference

[Browser package entrypoint](../browser/README.md).

## Experimental raw onion node

The `/tor-streams` entrypoint uses the separate pinned `service` build described
in [`browser/upstream/`](../browser/upstream/README.md). Its source provides
browser-owned onion publication and raw Arti streams. The
[isolated browser/native Tor contract](../browser/upstream/README.md)
passed at `b23221271f71`, including browser-owned publication and bidirectional
MLS traffic. That historical run uses the explicit private-network build; public-network
deployment was still unvalidated at that revision. Later [public-network
validation](public-tor-validation.md) and [onion renewal](onion-renewal.md) have
separate pinned evidence and limits. The stock npm TorJS package is rejected.

```js
import { createTorJsOnionNode } from '@corbet-labs/cmsg/tor-streams';
const node = await createTorJsOnionNode({
  gateway: configuredGateway,
  bootstrapDeadlineMs: 180000,
  operationDeadlineMs: 45000,
});
const listener = await node.listen({ port: 4242, maximumStreams: 8, deadlineMs: 60000 });
// Sign/publish listener.host and listener.port with this device's live lease.
const stream = await listener.accept();
const incomingWire = await stream.receive();
const incoming = await inbox.receive(incomingWire, wrappingKey, context, persist);
```

`node.connect(peerOnion, peerPort)` returns the same framed stream. Its wire
format matches native `FramedStream` directly; it requires no HTTP payload
server. `send` and `receive` each allow one pending operation, can proceed in
opposite directions concurrently, and close on framing/transport failure.
Closing a node closes its listener and streams. Each node can launch one onion
service; restarting creates fresh onion keys. Permanent member identity and
contact policy remain separately encrypted cmsg state. A terminated or
suspended browser cannot promise continuous reachability.

## HTTP client bridge

The optional `@corbet-labs/cmsg/tor-js` entrypoint requires the pinned onion-enabled
build of `tor-js@0.4.1` described in [`browser/upstream/`](../browser/upstream/README.md). The stock npm artifact omits
Arti's `onion-service-client` feature and is rejected before network bootstrap.
The patch and its generated artifact still require compile and network evidence.
The adapter requires an explicitly configured TorJS gateway and a whole-request
deadline. No gateway, billing account, CDN fallback or direct-IP message route
is supplied. Bundle and serve TorJS' `wasm-file` asset with the application.

```js
import { createTorJsOnionTransport } from '@corbet-labs/cmsg/tor-js';

const transport = await createTorJsOnionTransport({
  gateway: configuredGateway,
  deadlineMs: 45000,
});
const replyWire = await transport.exchange(peerOnion, peerPort, encryptedWire);
const reply = await inbox.receive(replyWire, wrappingKey, context, persist);
```

This adapter performs one request/reply exchange against a peer-owned onion
HTTP listener. It does not publish a browser onion service, provide an inbox
server, queue offline messages, or make a suspended browser reachable.
TorJS 0.4.1 exposes client HTTP fetch, not a public onion-service hosting API.
Transport connectivity and hosting need separate end-to-end evidence; codec
tests and browser crypto tests do not establish either.

The browser constructs Tor circuits. Its gateway forwards encrypted bytes and
can observe client IP, timing, volume, and the entry relay. The gateway is part
of the bandwidth path for the entire session. The adapter suppresses its TorJS
logger, sends a fixed generic User-Agent, accepts only checksum-valid v3 onion
destinations, rejects redirects, and applies strict response bounds. A deadline
closes the dedicated TorJS client and rejects the operation; upstream in-flight
connection cancellation is limited by TorJS' own implementation.

## Peer HTTP wire contract

- Request: `POST /cmsg/v1/exchange`.
- Content-Type and Accept: `application/vnd.cmsg.frame`.
- Body: one nonempty frame, encoded as uint32 big-endian length plus bytes.
- Response: status 200, the same Content-Type, and an exact Content-Length.
- Response body: exactly one frame, at most `MAX_WIRE_BYTES` payload bytes.
- Redirects, compression, chunked responses and multiple response frames fail.

Applications supply MLS ciphertext as frame payloads. This HTTP wrapper does
not identify members, attest a gateway, or enforce first-contact admission.
Do not replace TorJS fetch with browser fetch or a cleartext onion gateway.
