# org-ietf-turn

[![CI](https://github.com/kotoba-lang/org-ietf-turn/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/org-ietf-turn/actions/workflows/ci.yml)

**TURN relay (RFC 8656) protocol core — pure Clojure/EDN (`.cljc`, JVM +
ClojureScript).** Closes the STUN-only NAT-traversal gap for 1:1 real-media
WebRTC calls behind symmetric NAT. This repo is the **message layer +
credential layer + relay state model**: STUN (RFC 8489) parse/encode,
ephemeral-credential mint/verify, MESSAGE-INTEGRITY / FINGERPRINT, the
allocation/permission/channel-binding state machine (RFC 8656 §5-§11),
ChannelData framing (§12.4), and STUN/ChannelData datagram classification.
It intentionally does **not** include a UDP/TCP socket listener — see
`docs/ADR-kotoba-turn-relay.md`.

This supersedes the Rust `kotoba-turn` crate (`kotoba-lang/kotoba`, removed in
PR #259, 2026-07-01 — see `kotoba-lang/kotoba/docs/rust-crate-migration.md`):
new kotoba protocol implementations are CLJC/EDN-first; a native adapter may
be added later but is never the semantic authority.

```clojure
(require '[kotoba.turn.credential :as cred])

(cred/mint-credential "shared-secret" "alice" 600 1700000000)
;; => {:username "1700000600:alice" :credential "..."}  (base64 HMAC-SHA1)

(cred/verify-credential "shared-secret" username credential now)
;; => true / false (checks expiry AND signature)
```

```clojure
(require '[kotoba.turn.stun :as stun]
         '[kotoba.bytes :as bytes])

(def msg (-> (stun/encode-header {:typ stun/binding-request :length 0 :txid (vec (repeat 12 0))})
             (stun/push-attr stun/attr-software (bytes/utf8-encode "kotoba"))
             stun/set-attr-length
             (stun/append-message-integrity key-bytes)
             stun/append-fingerprint))

(stun/verify-message-integrity msg key-bytes) ;=> true
(stun/verify-fingerprint msg)                 ;=> true
```

```clojure
(require '[kotoba.turn.allocation :as alloc]
         '[kotoba.turn.channeldata :as cd]
         '[kotoba.turn.demux :as demux])

;; Everything below is `now`-injected (a caller-supplied ms timestamp) —
;; nothing in these three namespaces reads a clock or touches a socket.
(def a (alloc/allocate now five-tuple relayed-address))
(alloc/expired? a now)                              ;=> false
(def a (alloc/create-permission a peer-address now)) ;; RFC 8656 §9, own 300s expiry
(alloc/permission-active? a peer-address now)        ;=> true
(def a (alloc/channel-bind a 0x4001 peer-address now)) ;; nil if channel-num out of range
(alloc/peer-for-channel a 0x4001 now)                ;=> peer-address

(cd/decode (cd/encode 0x4001 payload-bytes))         ;=> {:channel-number 0x4001 :data payload-bytes}
(demux/classify-datagram raw-datagram)               ;=> :stun | :channel-data | :unknown
```

## Design

- **Byte-vector and SHA-1/HMAC-SHA1 primitives now live in
  [`kotoba-lang/bytes`](https://github.com/kotoba-lang/bytes)**
  (`kotoba.bytes` / `kotoba.bytes.sha1`), not in this repo. They were
  extracted out of `kotoba.turn.bytes` / `kotoba.turn.sha1` (Phase 1 of a
  shared-lib consolidation across kotoba-lang protocol libraries) because
  neither was actually TURN/STUN-specific — both are generic
  `vector<int 0..255>` byte-vector primitives and a pure, portable SHA-1 +
  HMAC-SHA1 implementation (no platform crypto API, identical code on the JVM
  and in ClojureScript). This repo depends on `kotoba-lang/bytes` via a
  `:local/root` sibling checkout (see `deps.edn`).
- **`kotoba.turn.credential`** — ephemeral TURN credential mint/verify, the
  coturn `use-auth-secret` scheme:
  `username = "<expiry-unix-ts>:<user>"`,
  `credential = base64(HMAC-SHA1(shared-secret, username))`. The HMAC
  primitive is reader-conditional (`:clj` → `javax.crypto.Mac`, `:cljs` → the
  pure `kotoba.bytes.sha1` impl from `kotoba-lang/bytes`); `credential_test.clj`
  cross-checks both branches against the *same* RFC 2202 vector and against
  each other directly to pin them to byte-identical output.
- **`kotoba.turn.stun`** — RFC 8489 20-byte header + attribute TLV iteration
  (4-byte padding), XOR-MAPPED-ADDRESS (IPv4), MESSAGE-INTEGRITY
  (HMAC-SHA1 over the message up to but not including the attribute, with the
  header length field patched first), FINGERPRINT (CRC-32, self-implemented,
  XORed with `0x5354554E`).
- **`kotoba.turn.allocation`** — the RFC 8656 §5-§11 allocation / permission /
  channel-binding **state model**: a plain EDN map per allocation
  (`:turn/five-tuple` `:turn/relayed-address` `:turn/expiry`
  `:turn/permissions` `:turn/channel-bindings`), plus pure functions
  (`allocate` `expired?` `refresh` `create-permission` `permission-active?`
  `channel-bind` `refresh-channel-binding` `channel-for-peer`
  `peer-for-channel`). Every function is deterministic and `now`-injected
  (a caller-supplied ms timestamp) — same discipline as `kotoba.turn.stun`
  and the deleted Rust reference implementation's `allocation.rs`. This
  namespace owns nothing: callers store/index allocations themselves and
  garbage-collect anything `expired?` reports true for. It does **not**
  relay any data — there is no socket I/O anywhere in this repo.
- **`kotoba.turn.channeldata`** — RFC 8656 §12.4 ChannelData framing
  (`encode`/`decode`): the lightweight binary format TURN uses once a
  channel is bound, distinct from a full STUN message. 4-byte header
  (channel number + length, big-endian) + payload, padded to a 4-byte
  boundary the same way `kotoba.turn.stun/push-attr` pads STUN attribute
  values. `decode` returns `nil` (never throws) on malformed/too-short
  input.
- **`kotoba.turn.demux`** — RFC 8656 §12.4's datagram classification
  (`classify-datagram`): a listener multiplexes STUN and ChannelData on one
  port and must tell which is which before parsing either. Implements the
  real bit-level check (RFC 8489 §5: STUN's leading 2 bits are always `00`;
  a valid channel number's leading 2 bits are `01`), not a length guess or
  try/parse/fallback — see the namespace docstring for the exact reasoning.

## Scope

In scope: STUN message codec, ephemeral-credential mint/verify,
MESSAGE-INTEGRITY / FINGERPRINT, the allocation/permission/channel-binding
state machine (RFC 8656 §5-§11), ChannelData framing (§12.4), and
STUN/ChannelData datagram classification. **Out of scope (still deferred,
per `docs/ADR-kotoba-turn-relay.md`):** the actual UDP/TCP/TLS socket
listener I/O that would drive this state machine with real packets, the
long-term-credential mechanism (RFC 8489 §9.2), IPv6 XOR-addresses, and the
`REQUESTED-TRANSPORT`/`DONT-FRAGMENT`/`EVEN-PORT`/`RESERVATION-TOKEN`
request-validation logic around allocation creation. **This repo is still
not a runnable TURN relay server** — it is the pure protocol + state
contract a future listener phase must implement against.

## Correctness

`clojure -M:test` (cognitect test-runner), 41 tests / 94 assertions: STUN
header round-trip + attribute TLV parse/padding/overrun + XOR-MAPPED-ADDRESS
(RFC 5769 §2.2) + MESSAGE-INTEGRITY round-trip/tamper-detect (survives a
trailing FINGERPRINT) + FINGERPRINT round-trip/corruption-detect (CRC-32/IEEE
check value `0xCBF43926`) + credential mint/verify round-trip, tamper/
wrong-secret/malformed-username rejection, expiry-boundary (`>=` inclusive),
and the `:clj`/`:cljs` HMAC-SHA1 branches cross-checked against each other
and against an RFC 2202 §3 vector (SHA-1/HMAC-SHA1's own FIPS 180-1 + RFC
2202 vector suite lives in `kotoba-lang/bytes`); allocation lifetime/expiry/
refresh (including refresh-with-lifetime-0 deleting via `nil`), permission
independent-expiry, channel-bind range validation and both-direction
expiry-aware lookup; ChannelData encode/decode round-trip (including a
non-4-aligned payload and a zero-length payload) and malformed/truncated/
invalid-channel-number rejection; datagram classification of a real
`kotoba.turn.stun`-encoded message, a real `kotoba.turn.channeldata`-encoded
message, and garbage/short/wrong-leading-bits input.

## License

Apache-2.0.
