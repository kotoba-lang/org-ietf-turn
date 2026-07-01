(ns kotoba.turn.credential-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.turn.bytes :as b]
            [kotoba.turn.credential :as cred]
            [kotoba.turn.sha1 :as sha1]))

(deftest platform-hmac-matches-pure-impl
  (testing "the :clj (javax.crypto.Mac) branch and the pure kotoba.turn.sha1
            branch (what :cljs calls) produce byte-identical HMAC-SHA1 output
            — this is the correctness guarantee the reader-conditional split
            depends on"
    (doseq [[secret msg] [["Jefe" "what do ya want for nothing?"]
                          ["k" "1700000600:alice"]
                          ["" ""]
                          ["a shared turn secret" "1735689600:bob@example.com"]]]
      (is (= (cred/hmac-sha1-bytes (b/utf8-encode secret) (b/utf8-encode msg))
             (sha1/hmac-sha1 (b/utf8-encode secret) (b/utf8-encode msg)))
          (str "diverged for secret=" secret " msg=" msg)))))

(deftest rfc2202-vector-via-credential-ns
  ;; RFC 2202 §3 case 2 — also pins the JS SDK's `mintTurnCredential`-style
  ;; wire format (base64 HMAC-SHA1), see docs/ADR-kotoba-turn-relay.md.
  (is (= "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
         (apply str (map #(format "%02x" (bit-and % 0xff))
                          (cred/hmac-sha1 "Jefe" "what do ya want for nothing?"))))))

(deftest mint-then-verify-roundtrip
  (let [now 1700000000
        {:keys [username credential]} (cred/mint-credential "shh-its-a-secret" "alice" 600 now)]
    (is (= username "1700000600:alice"))
    (is (true? (cred/verify-credential "shh-its-a-secret" username credential now)))
    (is (true? (cred/verify-credential "shh-its-a-secret" username credential 1700000600)))))

(deftest verify-rejects-expired
  (let [now 1700000000
        {:keys [username credential]} (cred/mint-credential "s" "bob" 60 now)]
    (is (false? (cred/verify-credential "s" username credential 1700000061)))))

(deftest verify-rejects-tampered-credential
  (let [now 1700000000
        {:keys [username credential]} (cred/mint-credential "s" "carol" 600 now)]
    (is (false? (cred/verify-credential "s" username (str credential "AA") now)))))

(deftest verify-rejects-wrong-secret
  (let [now 1700000000
        {:keys [username credential]} (cred/mint-credential "right-secret" "dave" 600 now)]
    (is (false? (cred/verify-credential "wrong-secret" username credential now)))))

(deftest verify-rejects-malformed-username
  (is (false? (cred/verify-credential "s" "no-colon-here" "x" 0)))
  (is (false? (cred/verify-credential "s" "not-a-number:alice" "x" 0))))

(deftest verify-boundary-exact-expiry-is-still-valid
  ;; expires_at == now is inclusive (>=), matching the reference Rust impl.
  (let [now 1700000000
        {:keys [username credential]} (cred/mint-credential "s" "erin" 0 now)]
    (is (= username (str now ":erin")))
    (is (true? (cred/verify-credential "s" username credential now)))
    (is (false? (cred/verify-credential "s" username credential (inc now))))))
