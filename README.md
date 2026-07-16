# kotoba-turn

[![CI](https://github.com/kotoba-lang/kotoba-turn/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/kotoba-turn/actions/workflows/ci.yml)

**TURN relay (RFC 8656) protocol core — pure Clojure/EDN (`.cljc`, JVM +
ClojureScript).** Closes the STUN-only NAT-traversal gap for 1:1 real-media
WebRTC calls behind symmetric NAT. This repo is the **message-layer +
credential-layer contract**: STUN (RFC 8489) parse/encode, ephemeral-credential
mint/verify, MESSAGE-INTEGRITY / FINGERPRINT. It intentionally does **not**
include a UDP/TCP socket listener or the allocation/permission/channel state
machine yet — see `docs/ADR-kotoba-turn-relay.md`.

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

## Scope

In scope: STUN message codec, ephemeral-credential mint/verify,
MESSAGE-INTEGRITY / FINGERPRINT. **Out of scope (follow-up):** the
5-tuple allocation / permission / channel-binding state machine, ChannelData
framing (§12.4), and the actual UDP/TCP/TLS listener I/O — see
`docs/ADR-kotoba-turn-relay.md` for what's deliberately deferred and why.

## Correctness

`clojure -M:test` (cognitect test-runner): STUN header round-trip + attribute
TLV parse/padding/overrun + XOR-MAPPED-ADDRESS (RFC 5769 §2.2) +
MESSAGE-INTEGRITY round-trip/tamper-detect (survives a trailing FINGERPRINT) +
FINGERPRINT round-trip/corruption-detect (CRC-32/IEEE check value
`0xCBF43926`) + credential mint/verify round-trip, tamper/wrong-secret/
malformed-username rejection, expiry-boundary (`>=` inclusive), and the
`:clj`/`:cljs` HMAC-SHA1 branches cross-checked against each other and against
an RFC 2202 §3 vector. (SHA-1/HMAC-SHA1's own FIPS 180-1 + RFC 2202 vector
suite now lives in `kotoba-lang/bytes`.)

## License

Apache-2.0.
