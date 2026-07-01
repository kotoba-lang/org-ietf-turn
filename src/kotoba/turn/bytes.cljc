;; kotoba.turn.bytes — portable byte-vector primitives shared by the TURN/STUN
;; codec and the credential HMAC-SHA1 path. Every "bytes" value in this library
;; is a plain Clojure vector of ints in [0,255] (NOT a platform byte-array),
;; so the exact same code runs unmodified on the JVM and in ClojureScript —
;; there is nothing to reader-conditional here and nothing to diverge.
(ns kotoba.turn.bytes)

(defn u8 [n] (bit-and n 0xff))

(defn u16->bytes
  "Big-endian 2-byte encoding of a 16-bit unsigned int."
  [n]
  [(u8 (bit-shift-right n 8)) (u8 n)])

(defn bytes->u16
  "Decode 2 big-endian bytes (a 2-element byte vector) to an unsigned int."
  [[hi lo]]
  (bit-or (bit-shift-left (bit-and hi 0xff) 8) (bit-and lo 0xff)))

(defn u32->bytes
  "Big-endian 4-byte encoding of a 32-bit unsigned int."
  [n]
  [(u8 (bit-shift-right n 24)) (u8 (bit-shift-right n 16)) (u8 (bit-shift-right n 8)) (u8 n)])

(defn bytes->u32
  "Decode 4 big-endian bytes to an unsigned int (0..2^32-1)."
  [[b0 b1 b2 b3]]
  (bit-or (bit-shift-left (bit-and b0 0xff) 24)
          (bit-shift-left (bit-and b1 0xff) 16)
          (bit-shift-left (bit-and b2 0xff) 8)
          (bit-and b3 0xff)))

(defn xor-bytes
  "XOR two equal-length byte vectors elementwise."
  [a b]
  (mapv #(bit-xor %1 %2) a b))

(defn pad-right
  "Pad `bs` with `n` zero bytes on the right."
  [bs n]
  (into (vec bs) (repeat n 0)))

(defn utf8-encode
  "Encode a string to a UTF-8 byte vector. Pure/portable: handles the BMP plus
   surrogate-pair codepoints (>0xFFFF) without relying on any platform string
   API, so :clj and :cljs produce byte-identical output."
  [^String s]
  (let [len (count s)]
    (loop [i 0 out (transient [])]
      (if (>= i len)
        (persistent! out)
        (let [c1 (int (nth s i))]
          (cond
            ;; surrogate pair -> single codepoint > 0xFFFF
            (and (<= 0xD800 c1 0xDBFF) (< (inc i) len))
            (let [c2 (int (nth s (inc i)))]
              (if (<= 0xDC00 c2 0xDFFF)
                (let [cp (+ 0x10000
                            (bit-shift-left (- c1 0xD800) 10)
                            (- c2 0xDC00))]
                  (recur (+ i 2)
                         (conj! out
                                (u8 (bit-or 0xF0 (bit-shift-right cp 18)))
                                (u8 (bit-or 0x80 (bit-and (bit-shift-right cp 12) 0x3F)))
                                (u8 (bit-or 0x80 (bit-and (bit-shift-right cp 6) 0x3F)))
                                (u8 (bit-or 0x80 (bit-and cp 0x3F))))))
                (recur (inc i) out))) ; lone high surrogate: skip (malformed input)

            (< c1 0x80)
            (recur (inc i) (conj! out c1))

            (< c1 0x800)
            (recur (inc i)
                   (conj! out
                          (u8 (bit-or 0xC0 (bit-shift-right c1 6)))
                          (u8 (bit-or 0x80 (bit-and c1 0x3F)))))

            :else
            (recur (inc i)
                   (conj! out
                          (u8 (bit-or 0xE0 (bit-shift-right c1 12)))
                          (u8 (bit-or 0x80 (bit-and (bit-shift-right c1 6) 0x3F)))
                          (u8 (bit-or 0x80 (bit-and c1 0x3F)))))))))))

(def ^:private b64-alphabet
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defn base64-encode
  "Standard (RFC 4648) base64 encode of a byte vector, padded with `=`."
  [bs]
  (let [n (count bs)]
    (apply str
           (loop [i 0 out []]
             (if (>= i n)
               out
               (let [b0 (nth bs i)
                     b1 (when (< (inc i) n) (nth bs (inc i)))
                     b2 (when (< (+ i 2) n) (nth bs (+ i 2)))
                     triple (bit-or (bit-shift-left b0 16)
                                    (bit-shift-left (or b1 0) 8)
                                    (or b2 0))
                     c0 (bit-and (bit-shift-right triple 18) 0x3F)
                     c1 (bit-and (bit-shift-right triple 12) 0x3F)
                     c2 (bit-and (bit-shift-right triple 6) 0x3F)
                     c3 (bit-and triple 0x3F)]
                 (recur (+ i 3)
                        (conj out
                              (nth b64-alphabet c0)
                              (nth b64-alphabet c1)
                              (if b1 (nth b64-alphabet c2) \=)
                              (if b2 (nth b64-alphabet c3) \=)))))))))

(def ^:private b64-index
  (into {} (map-indexed (fn [i c] [c i]) b64-alphabet)))

(defn base64-decode
  "Standard (RFC 4648) base64 decode to a byte vector. Ignores a trailing `=`
   pad. Returns nil on malformed input (non-alphabet character)."
  [^String s]
  (let [chars (remove #(= % \=) (seq s))]
    (when (every? #(contains? b64-index %) chars)
      (let [vals (mapv b64-index chars)
            n (count vals)]
        (loop [i 0 out (transient [])]
          (if (>= i n)
            (persistent! out)
            (let [v0 (nth vals i)
                  v1 (when (< (inc i) n) (nth vals (inc i)))
                  v2 (when (< (+ i 2) n) (nth vals (+ i 2)))
                  v3 (when (< (+ i 3) n) (nth vals (+ i 3)))
                  triple (bit-or (bit-shift-left v0 18)
                                 (bit-shift-left (or v1 0) 12)
                                 (bit-shift-left (or v2 0) 6)
                                 (or v3 0))]
              (recur (+ i 4)
                     (cond-> out
                       true (conj! (u8 (bit-shift-right triple 16)))
                       v2   (conj! (u8 (bit-shift-right triple 8)))
                       v3   (conj! (u8 triple)))))))))))

(defn constant-time-eq
  "Constant-time equality for two byte vectors (or two strings). Always scans
   the full length of the longer input and folds every mismatch into a single
   accumulator, instead of short-circuiting on the first differing element —
   this avoids leaking a length/content-dependent timing signal, which is the
   whole point when comparing a caller-presented MESSAGE-INTEGRITY digest or
   TURN credential against the locally-computed value (a plain `=` here would
   be a timing side-channel on secret-derived data)."
  [a b]
  (let [a (if (string? a) (utf8-encode a) a)
        b (if (string? b) (utf8-encode b) b)
        n (max (count a) (count b))]
    (loop [i 0 diff (bit-xor (count a) (count b))]
      (if (>= i n)
        (zero? diff)
        (recur (inc i)
               (bit-or diff (bit-xor (int (get a i 0)) (int (get b i 0)))))))))
