# Manual installed iPhone PWA passkey check

This is a required manual acceptance task, not an automated WebKit passkey claim.
The community UI remains top-level and installed at its own origin. Custody and
cmsg run in the separate matching vault frame. The former inverted layout is
rejected. No one-origin fallback is enabled without an explicit decision.

The check page is `.ci/manual-passkeys.html`. Serve it inside the actual community
PWA with the original generated `browser.js` and public `cmsg-client-config.json`
using the Rust-generated VaultBridgeConfiguration. Use the actual PWA manifest,
service worker, HTTPS configuration and original vault frame deployment; a desktop
tab or test page outside the installed PWA does not establish this result. The
frame must load its own pinned VaultHostConfiguration; the UI never supplies a
service session, credential, PRF or key through its channel.

Current source has only partial runtime construction: `login.start` is unavailable
until original Passkeys, independently verified G3 and durable Vault composition
exist. That refusal is an expected incomplete result, never a passkey success.
The manual page neither substitutes an authenticator nor manufactures completion.

Every browser uses one original cpky top-level vault-origin popup route. Keyhole
keeps its existing crossOrigin refusal; there is no iframe ceremony branch or
server patch. The deployment owner must supply exact frame/popup CSP. The frame
has no get/create delegation. The popup's ordinary top-level WebAuthn must retain
crossOrigin=false and no topOrigin. A reconstructed clientDataJSON, broader RP,
or disabled browser policy is not a test.

1. On an actual iPhone, install the community PWA through Safari and open the check
   page inside that installed application. Confirm the visible/installed origin
   stays the community origin. Record only browser/OS version and coarse outcomes.
2. Connect the original vault frame, then press Start sign-in. A gesture on the
   community page does not activate its cross-origin Vault child; the API channel
   does not transfer activation. Exercise the original cpky integration's explicit
   confirmation inside the visible Vault frame before its popup launch, if required.
   Do not hide this confirmation or use synthetic events/browser policy overrides.
   The original cpky path must open only the matching top-level vault-origin popup,
   transfer its opaque result only to the original same-origin Vault frame, and
   close after the accepted handover.
3. Poll the original login state. Complete is valid only after actual server
   authentication and durable custody acceptance. A popup closing, a returned
   assertion, or Pending is not completion. Confirm required domain operations
   work through the same still-running owner; do not inspect or log secret bytes.
4. Cancel in the authenticator and repeat with popup refusal/blocking. The original
   lifecycle must refuse or expire without a partial grant or stranded successful
   login. Test foreground/background and PWA suspension during the ceremony.
5. Close or navigate the popup early, reopen the PWA, and reject replay of the old
   ceremony. Original cpky window/source/nonce/deadline checks must be exercised
   by its real vectors; the check page must not forge callback data or credentials.
6. Close the runtime through the page and require the actual drain acknowledgement.
   Reload only after recording the result. If the browser destroys a document or
   transport before acknowledgement, record uncertainty and use owner-defined
   reconciliation; never assume an admitted mutation rolled back.
7. Repeat in ordinary Safari, Chromium and Firefox using that same popup route.
   Distinguish installed-PWA behavior from ordinary-tab behavior in the evidence;
   no successful frame ceremony or automated WebKit passkey result is claimed.

If the installed iPhone popup handover fails, retain a coarse failure and the exact
original source/tool configuration. Escalate the explicitly reserved one-origin
fallback decision; do not activate it silently. No account identifiers, tokens,
credential blobs, PRF values, root keys, private profile content, or screenshots of
private account data belong in the report.

The frame activation requirement follows the [HTML activation notification
algorithm](https://html.spec.whatwg.org/multipage/interaction.html#activation-notification).
Its concrete popup prompt/lifetime implementation belongs to original cpky and
must be exercised on the installed phone PWA; the channel tests do not prove it.
