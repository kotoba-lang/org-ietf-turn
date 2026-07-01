;; kotoba.turn.sha1 — pure SHA-1 (FIPS 180-4) + HMAC-SHA1 (RFC 2104), portable
;; across JVM Clojure and ClojureScript. No platform crypto API is used here —
;; this is the reference implementation the ClojureScript side of
;; `kotoba.turn.credential` calls directly, and the one the JVM side is
;; cross-checked against (see `sha1_test.clj` / `credential_test.clj`).
;;
;; Bytes in and bytes out are `kotoba.turn.bytes` byte-vectors (vector<int 0..255>).
(ns kotoba.turn.sha1
  (:require [kotoba.turn.bytes :as b]))

(def ^:private mask32 0xffffffff)

(defn- m32 [x] (bit-and x mask32))

(defn- rotl32 [x n]
  (m32 (bit-or (bit-shift-left x n) (unsigned-bit-shift-right x (- 32 n)))))

(defn- add32 [& xs] (m32 (reduce + 0 xs)))

(def ^:private h-init [0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476 0xC3D2E1F0])

(defn- pad-message
  "FIPS 180-4 §5.1.1 padding: append 0x80, zero-pad to 56 mod 64, then the
   original bit-length as a big-endian 64-bit integer (split across two
   32-bit big-endian words, since a single 64-bit shift is not cljs-safe)."
  [msg]
  (let [byte-len (count msg)
        bit-len (* byte-len 8)
        with-marker (conj (vec msg) 0x80)
        rem64 (mod (count with-marker) 64)
        zero-pad (mod (- 56 rem64) 64)
        hi (m32 (unsigned-bit-shift-right bit-len 32))
        lo (m32 bit-len)]
    (-> with-marker
        (into (repeat zero-pad 0))
        (into (b/u32->bytes hi))
        (into (b/u32->bytes lo)))))

(defn- words-from-chunk
  "16 big-endian 32-bit words from a 64-byte chunk."
  [chunk]
  (mapv b/bytes->u32 (partition 4 chunk)))

(defn- extend-schedule
  "Extend 16 words to the full 80-word message schedule (§6.1.2 step (b))."
  [w16]
  (loop [w (vec w16) i 16]
    (if (= i 80)
      w
      (recur (conj w (rotl32 (bit-xor (nth w (- i 3)) (nth w (- i 8))
                                       (nth w (- i 14)) (nth w (- i 16)))
                              1))
             (inc i)))))

(defn- round-fk [i b c d]
  (cond
    (<= 0 i 19)  [(bit-or (bit-and b c) (bit-and (m32 (bit-not b)) d)) 0x5A827999]
    (<= 20 i 39) [(bit-xor b c d) 0x6ED9EBA1]
    (<= 40 i 59) [(bit-or (bit-and b c) (bit-and b d) (bit-and c d)) 0x8F1BBCDC]
    :else        [(bit-xor b c d) 0xCA62C1D6]))

(defn- process-chunk [[h0 h1 h2 h3 h4] chunk]
  (let [w (extend-schedule (words-from-chunk chunk))]
    (loop [i 0 a h0 b h1 c h2 d h3 e h4]
      (if (= i 80)
        [(add32 h0 a) (add32 h1 b) (add32 h2 c) (add32 h3 d) (add32 h4 e)]
        (let [[f k] (round-fk i b c d)
              temp (add32 (rotl32 a 5) f e k (nth w i))]
          (recur (inc i) temp a (rotl32 b 30) c d))))))

(defn sha1-bytes
  "SHA-1 digest of a byte vector; returns a 20-byte vector."
  [msg]
  (let [padded (pad-message msg)
        chunks (partition 64 padded)
        [h0 h1 h2 h3 h4] (reduce process-chunk h-init chunks)]
    (vec (mapcat b/u32->bytes [h0 h1 h2 h3 h4]))))

(def ^:const block-size 64)

(defn hmac-sha1
  "HMAC-SHA1 (RFC 2104) of byte-vector `msg` under byte-vector `key`. Returns a
   20-byte vector. Pure — usable directly, and it's what the ClojureScript
   branch of `kotoba.turn.credential/hmac-sha1` calls."
  [key msg]
  (let [key' (if (> (count key) block-size) (sha1-bytes key) (vec key))
        key-padded (b/pad-right key' (- block-size (count key')))
        opad (mapv (fn [k] (bit-xor k 0x5c)) key-padded)
        ipad (mapv (fn [k] (bit-xor k 0x36)) key-padded)]
    (sha1-bytes (into opad (sha1-bytes (into ipad msg))))))
