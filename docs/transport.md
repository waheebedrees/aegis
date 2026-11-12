
# Transport — v4 stack

The transport is three layers, each fail-closed against its own attack
surface. They compose: `tls.py` establishes an authenticated, exporter-separated
connection; `frame.py` encodes/decodes bounded length-prefixed frames over it;
`stream_session.py` multiplexes authenticated streams with flow control,
keepalive, and per-stream cancellation.

```
┌─────────────────────────────────────────────────────────────────┐
│  Application                                                    │
│    Transport.open_stream / accept; Stream.send / recv / aclose │
├─────────────────────────────────────────────────────────────────┤
│  stream_session.py — multiplexing, flow control, keepalive      │
│    Transport.establish → _reader_loop + _ping_loop + _control_loop │
├─────────────────────────────────────────────────────────────────┤
│  frame.py — bounded wire format, per-type FrameSpec validation  │
│    FrameReader.read_frame / FrameWriter.write_frame             │
├─────────────────────────────────────────────────────────────────┤
│  tls.py — TLS 1.3 peer identity + exporter split                │
│    TlsConnection.wrap / awrap → peer_id + SessionSecrets       │
├─────────────────────────────────────────────────────────────────┤
│  asyncio.StreamReader / StreamWriter (TLS socket underneath)   │
└─────────────────────────────────────────────────────────────────┘
```

Every layer *assumes its caller is compliant* and *rejects non-compliant peers
before the next layer sees the input*. The frame layer never trusts a length
it hasn't bounded; the session layer never trusts a `seq` it hasn't checked;
the TLS layer never trusts a `peer_id` it hasn't extracted from a verified
cert.

---

## 1. Threat model

### 1.1 Assets

| Asset | Where it lives | Loss mode |
|---|---|---|
| Peer identity | Peer's X.509 cert (SPIFFE URI SAN) | Impersonation; every authentication layer above falls |
| TLS exporter | Kernel TLS stack; consumed once at handshake | Channel-binding forgery; stream MAC forgery |
| Stream MAC key | Derived from exporter via HKDF split | All chunk authentication lost |
| Frame stream | TCP buffer, bounded by `FrameReader` | Connection desync; protocol confusion |
| Per-stream flow-control window | `Stream._peer_window`, `Stream._window` | Buffer exhaustion; stalled peers |
| Process memory | `_buf` per stream + `_streams` | DoS via stream flood or chunk flood |

### 1.2 Adversary classes

| Adversary | Capabilities | Defeated by |
|---|---|---|
| **A1 — Passive network** | Reads wire traffic | TLS 1.3. Nothing cleartext. |
| **A2 — Active MITM** | Modifies TLS records | TLS 1.3 AEAD; any tamper fails the handshake. |
| **A3 — Unauthenticated peer** | Completes TLS without a valid SPIFFE cert | `TlsConnection._verify` step 6: `getpeercert()` must be non-empty (proves chain verification succeeded). |
| **A4 — Authenticated but unauthorized** | Valid cert, wrong trust domain or wrong target | `SpiffeAdapter.verify_peer`: trust domain, self-loop, target pin, `authorize` callback. |
| **A5 — Certificate replay** | Replays a captured server certificate | TLS 1.3 handshake binding — the peer signature covers the current client key share. Cert expiry tracked via `_expiry_loop` (transport shuts down at `not_after - skew`). |
| **A6 — Reflected chunks** | Echoes our own STREAM_DATA back | HKDF-split `send_ikm` ≠ `recv_ikm`; `HmacStreamSigner` uses distinct keys per direction. |
| **A7 — Framing desync** | Sends a body length that lies about what follows | `FrameReader.read_frame` consumes exactly `payload_len` bytes; a mismatch raises `LENGTH_MISMATCH` and **permanently closes** the reader. |
| **A8 — Flow-control abuse** | Sends more than our advertised window | `_on_stream_data`: `_recv_buffered + len(data) > _window` → fatal `FLOW_CONTROL`. |
| **A9 — Credit theft** | Sends `WINDOW_UPDATE` for bytes never sent | `_on_window_update`: `_send_granted + credits > _send_sent` → fatal `CREDIT_OVERRUN`. |
| **A10 — Stream-ID collision** | Client sends duplicate or decreasing sids | `_on_open`: odd + strictly increasing (`> _last_peer_sid`). |
| **A11 — Chunk replay within a stream** | Re-sends a captured (seq, data, mac) | `_on_stream_data`: `chunk.seq == st._recv_seq` — exactly sequential. |
| **A12 — Chunk relocation** | Moves a chunk from stream A to stream B | `HmacStreamSigner` binds `stream_id` into the MAC input. |
| **A13 — Ping flood** | Sends PINGs to keep the connection alive without answering ours | `_ping_loop` fails after `MAX_OUTSTANDING_PINGS=3` unanswered. |
| **A14 — Stale-frame flood** | After a stream is retired, keeps sending frames for its sid | `_stale_bytes` is bounded at `MAX_STALE_BYTES=8MB`, then fatal `STALE_FLOOD`. |
| **A15 — TLS-terminating sidecar** | A mesh sidecar terminates TLS | **Not defended.** See §12.4; identity and channel binding both degrade. |
| **A16 — Compromised peer process** | Full control of one authenticated peer | Out of scope; peer's key is peer's responsibility. |

### 1.3 Out of scope

- Control of the TLS library, OpenSSL, or the kernel TLS stack.
- Physical access to host memory, CPU caches, or swap.
- Side-channel attacks on `hmac.compare_digest` (already constant-time in the
  standard library) or `cryptography.x509` parsing.
- Traffic analysis / metadata leakage (frame sizes and timings are visible).
- Post-quantum adversaries against the TLS handshake.

---

## 2. Layer 1 — TLS (`tls.py`)

### 2.1 What this layer guarantees

`TlsConnection.wrap(...)` succeeds **only** if all of the following hold, in
this order:

| # | Check | Failure mode |
|---|---|---|
| 1 | A cipher negotiated | `no cipher negotiated` |
| 2 | Cipher not on the forbidden list (`NULL`, `ANON`, `EXPORT`, `RC4`, `3DES`, `DES`, `MD5`, `CBC`) | `forbidden cipher: <name>` |
| 3 | `ssl.SSLObject.version()` ∈ `TlsPolicy.allowed_versions` (TLS 1.3 only) | `TLS version ...` |
| 4 | ALPN negotiated ∈ `TlsPolicy.allowed_alpns` (default `("aegis/v1",)`) | `ALPN mismatch` |
| 5 | `SSLSocket.context` inspectable AND `verify_mode == ssl.CERT_REQUIRED` | `TLS context is not inspectable` / `must be CERT_REQUIRED` |
| 6 | `check_hostname == False` | `check_hostname must be False for SPIFFE mTLS` |
| 7 | `getpeercert()` non-empty (proves chain verification) AND DER parses | `peer certificate not verified` / `DER parse failed` |
| 8 | `not_before ≤ now ± clock_skew ≤ not_after` | `not yet valid` / `expired` |
| 9 | `adapter.verify_peer(cert)` returns a valid SPIFFE ID | adapter-specific |
| 10 | Exporter extracted and split | `exporter must return exactly 32 raw bytes` |

**The fail-closed rule for #5 and #6 is the load-bearing one.** `getpeercert()`
returns an *attacker-supplied* certificate when `verify_mode != CERT_REQUIRED`.
A missing `context` attribute is a hard error, not a "skip the check" — the
comment in the source says this explicitly and it's correct.

### 2.2 The three-secret split

The raw 32-byte RFC 9266 exporter is a single value. It's used three times:

```
raw_exporter  = SSLSocket.export_keying_material(
                    b"EXPORTER-Channel-Binding", None, 32)
prk           = HMAC-SHA256(b"aegis-exporter-root-v4:" + alpn, raw_exporter)
channel_binding = HMAC-SHA256(prk, b"aegis-cb-v4\x01")
stream_ikm_c2s  = HMAC-SHA256(prk, b"aegis-stream-c2s-v4\x02")
stream_ikm_s2c  = HMAC-SHA256(prk, b"aegis-stream-s2c-v4\x03")
```

This is a simplified HKDF: Extract once, Expand three times with distinct
labels. The properties:

1. **`channel_binding` is one-way from the stream keys.** Disclosing the
   channel binding (it appears in PoPs, evidence records, audit logs) leaks
   nothing about either stream key. This matters because capchain uses the
   channel binding as a *public* value.
2. **Send and receive stream keys are independent.** A peer that somehow
   obtained our `send_ikm` still can't verify our received chunks (they're
   keyed by `recv_ikm = peer's send_ikm`), and can't reflect our own chunks
   back at us (`HmacStreamSigner` uses distinct keys per direction).
3. **Versioned labels.** The `-v4` suffix means a wire version bump
   (`WIRE_VERSION = 4` → `5`) changes all four labels simultaneously. A peer
   speaking v4 cannot verify any v5 chunk, even with the same exporter.

`_derive_session_secrets` copies the raw exporter into a `bytearray`,
computes the three secrets, then zeroes the `bytearray` in `finally`. The
`prk` is `bytes` and cannot be scrubbed; the docstring flags this. For a
strict zeroization posture, change `native_exporter` to write into a
caller-supplied `bytearray` (§14, D5).

### 2.3 The SPIFFE adapter

`SpiffeAdapter.verify_peer` runs, in order:

1. `extract_spiffe_id(cert)` — exactly one `spiffe://` URI SAN.
2. `_parse_spiffe_uri` — lowercase trust domain, no userinfo / query / fragment
   / percent-escape, path segments not empty / `.` / `..`.
3. `spiffe_id != self.peer_id` — self-loop rejected.
4. `spiffe_id == self.target_node_id` — pin, if set.
5. `self.authorize(spiffe_id) is True` — the caller's ACL.

**The pin (step 4) is before the authorize (step 5).** If the caller knows the
one peer they want, a wrong identity never reaches the callback — which matters
because `authorize` may have side effects (logging, rate limiting, billing).

**The constructor validates `peer_id`, `trust_domain`, and `target_node_id` as
full SPIFFE IDs.** A typo in `peer_id` used to surface as "peer identity
mismatch" at handshake time; it's now a `ValueError` at adapter construction.
This is the right place for it — the failure is local misconfiguration, not a
remote protocol failure.

### 2.4 Certificate expiry

`TlsConnection.not_before` / `not_after` are POSIX UTC seconds, parsed from the
DER. The session layer's `_expiry_loop` shuts down at `not_after - skew`, not
at `not_after` — so a peer that started a handshake just before expiry is not
yanked mid-frame at the exact instant the certificate dies. The 30-second
sleep between checks bounds the "how stale is the clock check" question.

**Note: this only checks the *peer's* certificate.** The local certificate
might expire concurrently; that failure surfaces as an `SSL_ERROR_EOF` on the
next write, which `FrameWriter` translates into `StreamClosed` and the session
layer escalates to `_request_stop("write:...")`. Acceptable — the peer will
typically send a TLS alert first.

---

## 3. Layer 2 — Framing (`frame.py`)

### 3.1 Wire format

Every frame on the wire:

```
offset   size  field
0        4     payload_len   (u32 BE; excludes these 4 bytes)
4        1     type          (u8)
5        2     flags         (u16 BE)
7        4     stream_id     (u32 BE, 0..0x7FFFFFFF; 0 = session-scoped)
11       4     token_len     (u32 BE)
15       N     token
15+N     4     pop_len       (u32 BE)
19+N     M     pop
19+N+M   K     body
```

`PROLOGUE_LEN = 11` (everything from `type` to `token_len`).
`FIXED_OVERHEAD = 15` (prologue + `pop_len`).
`payload_len = FIXED_OVERHEAD + N + M + K`.

### 3.2 The `FrameRegistry` invariant

Frame types come from `FrameRegistry`, an immutable table of `FrameSpec`
entries. **Unknown types are rejected after the 15-byte header, before any
payload is read.** This is what makes the decoder safe against a peer that
announces a `payload_len` of 8 MB for a type it isn't registered for: we never
read those 8 MB.

Per-type limits (`flags`, `stream_id`, `token_len`, `pop_len`, `body_len`) are
enforced **after the header and before the payload tail**. The largest
pre-validation allocation is 15 bytes.

```python
# Registered types (DEFAULT_REGISTRY):
#   SESSION_INIT   body 1..64, stream_id=0
#   DATA           body 0..4K, token 0..4K, pop 0..1K, stream_id=0
#   OPEN_STREAM    body 3..4K, token 0..4K, pop 0..1K, stream_id>0
#   STREAM_DATA    body 8..(8+256K), pop=32, stream_id>0, flags∈{0,FIN}
#   WINDOW_UPDATE  body=4, stream_id>0
#   CANCEL         body 0..128, stream_id>0
#   PING           body=8
#   PONG           body=8
#   CLOSE          body 0..128
#   ERROR          body 0..256
```

### 3.3 The reader never resynchronizes

Once `FrameReader.read_frame` consumes the 4-byte length prefix, **any**
error or cancellation marks the reader permanently closed. There is no
resynchronization. The docstring's phrasing is precise: *"Once the 4-byte
length prefix is consumed, ANY error or cancellation marks the FrameReader
permanently closed. There is no resynchronization."*

This matters because a stream desync after a partial frame is unrecoverable on
the wire — the peer might have written a prefix that announced one length and
a body that announced another, and the only correct response is to close the
connection and let the peer reconnect.

### 3.4 Two deadlines

`FrameReader.read_frame` takes both `idle_timeout` and `frame_timeout`:

- **`idle_timeout`** bounds the wait for the first byte of a frame. It's the
  "nobody is talking" timeout.
- **`frame_timeout`** bounds the remainder once the prefix is consumed. It's
  the "somebody started a frame and stopped" timeout.

Both default to `None` (no timeout), so a caller that forgets to set one gets
a reader that waits forever. `stream_session.py` sets both
(`TransportConfig.idle_timeout`, `.frame_timeout`).

The `_exact` helper's exception ordering matters:

```python
except asyncio.TimeoutError:           # must precede OSError on 3.11+
    ...
except asyncio.IncompleteReadError as exc:
    if frame_boundary and not exc.partial:
        return self._end("eof")        # clean EOF at a frame boundary
    ...
except asyncio.CancelledError:
    self.close("cancelled")            # bytes may be partly consumed
    raise
except (ConnectionError, OSError):
    return self._end("connection")
except Exception as exc:
    self.close("read_error")
    raise FrameError("READ_ERROR", ...)
```

On Python 3.11+, `asyncio.TimeoutError` is `OSError`, so it *must* be caught
first. The comment says so and the order is correct.

### 3.5 The `FrameWriter` has no queue

`FrameWriter.write_frame` acquires the lock, encodes, writes, drains,
returns. There is no writer-side buffer to overflow — the OS socket buffer is
the only queue. If `write` fails or `drain` times out, the writer is closed,
which closes the stream, which the session layer translates into a fatal
`TransportError`.

**Cancelling `write_frame` does not withdraw the frame.** The comment is
precise: *"The complete frame is queued; cancelling drain() leaves the byte
stream frame-aligned, so no resync is needed."* A caller that catches
`CancelledError` from `write_frame` cannot assume the frame wasn't sent. They
must assume it was.

### 3.6 The `DATA` frame

`DATA` is the session-scoped authenticated message. Its `FrameSpec` sets no
constraint on `token`/`pop`/`body` sizes beyond the global caps — *whether*
`DATA` must carry a token is a session-layer policy. The constructor comment
says this explicitly: *"Whether a DATA frame must carry a token is a
session-layer policy — the frame spec does not enforce it, because the session
layer is what defines 'authenticated DATA'."*

This is the correct split. The frame layer shouldn't decide that capchain
tokens must appear on every DATA frame, because a different application over
the same transport might use DATA for something else.

---

## 4. Layer 3 — Stream session (`stream_session.py`)

### 4.1 Role model

- **Client** opens streams. Stream IDs are **odd** and **strictly increasing**.
- **Server** accepts streams. Server never opens a stream, so there is no
  collision space to resolve.

The strict increase (`sid > _last_peer_sid`) plus the odd rule (`sid % 2 == 1`)
means `_last_peer_sid` monotonically increases and every accepted sid is
unique. A client that accidentally reuses an id after a transport restart is
caught by the retirement ring (§4.6), not by `_last_peer_sid` — which is why
the retirement ring exists.

### 4.2 The handshake

`Transport.establish` does:

1. Both sides send `SESSION_INIT` **before** reading. No role ordering
   dependency: the client doesn't wait for the server's `SESSION_INIT`, and
   vice versa. This eliminates a class of deadlocks (both sides waiting) at
   the cost of one extra frame in the buffer if the peer fails immediately.
2. Both sides read the other's `SESSION_INIT` and validate:
   - `version == PROTOCOL_VERSION` (4)
   - `features == FEATURES` (exact; unknown bits rejected)
   - `MIN_MAX_FRAME ≤ max_frame ≤ MAX_FRAME_BYTES`
   - `MIN_STREAM_WINDOW ≤ stream_window ≤ MAX_STREAM_WINDOW`
   - `1 ≤ max_streams ≤ MAX_STREAMS`
3. Both sides set `_peer_max_frame`, `_peer_window`, `_peer_max_streams`
   from the peer's advertised values.
4. Both sides spawn the four worker tasks.

The handshake timeout is `config.handshake_timeout` (default 10s). Any failure
triggers `_shutdown(..., notify=False)` — no CLOSE is sent, because a peer
that failed the handshake is not owed a graceful shutdown.

### 4.3 Worker tasks

Four tasks run concurrently per transport:

| Task | What it does | Termination |
|---|---|---|
| `_reader_loop` | `FrameStream.recv` → `_on_frame` (synchronous) | `_stopping` or `StreamClosed` |
| `_ping_loop` | Send PING every `ping_interval`; fail after 3 unanswered | `_stop_ev` or PING_TIMEOUT |
| `_control_loop` | Send PONG / CANCEL / WINDOW_UPDATE; single-shot on `_ctl_ev` | `_stopping` |
| `_expiry_loop` | Wait until `not_after - skew`, then `_request_stop("CERT_EXPIRED")` | Certificate expiry |

`_supervise` blocks on `_stop_ev` and calls `_shutdown`. If any of the four
tasks calls `_request_stop`, `_supervise` observes the stop and initiates
shutdown.

`_on_frame` is **synchronous** — no `await` between the frame arriving and the
state mutation. This is what makes ordering well-defined: `_on_open`
immediately adds to `_pending`, `_on_stream_data` immediately appends to
`_buf`, `_on_window_update` immediately bumps `_send_granted`. A peer cannot
get a `STREAM_DATA` dispatched before the matching `OPEN_STREAM` because
`_on_open` ran synchronously as part of the same reader task.

### 4.4 Flow control

Per stream, there are two windows:

- **`_peer_window`** — the peer's advertised receive window. This is our
  **send budget**. `Stream.send` blocks until
  `_send_sent - _send_granted + len(data) ≤ _peer_window`.
- **`_window`** — our advertised receive window. This is our **receive
  budget**. `_on_stream_data` rejects when
  `_recv_buffered + len(data) > _window`.

Credit returns to the peer via `WINDOW_UPDATE` when the application **dequeues**
a chunk (`Stream.recv` → `_grant(st, len(data))`). It does **not** return on
arrival. This is deliberate: returning credit on arrival lets a peer that
never reads from `recv` fill the buffer up to `stream_window` and then we have
to fail closed on the next chunk, which is worse for the peer than backpressure
on their own `send`.

`_on_window_update` rejects `WINDOW_UPDATE` for more credit than has been sent:

```python
if st._send_granted + credits > st._send_sent:
    raise TransportError("CREDIT_OVERRUN", str(f.stream_id))
```

Without this, a peer could grant itself unlimited credit and defeat flow
control entirely.

### 4.5 Chunk authentication

Every `STREAM_DATA` frame carries a 32-byte MAC in `pop`. `HmacStreamSigner`:

```
mac = HMAC-SHA256(
    key,
    b"aegis/stream-chunk/v4"                # domain separation
    || u32be(stream_id) || u64be(seq)
    || u8(fin) || u32be(len(data))
    || data
)
```

The key is `send_ikm` or `recv_ikm` depending on direction, taken from
`TlsConnection.secrets.for_role(is_client)`. Because `send_ikm ≠ recv_ikm`
(the HKDF split is one-way and the two directions are independent), a peer
cannot reflect our own chunks back at us: the MAC we compute for a chunk we
sent uses `send_ikm`, and the MAC we expect from the peer uses `recv_ikm`.
They are different keys over different inputs.

**Bound into the MAC:** `stream_id`, `seq`, `fin`, `len(data)`, `data`. A
chunk cannot be replayed on a different stream, cannot be replayed out of
order, cannot be flipped to `fin=True` by a MITM, and cannot have its length
or content altered.

**Not bound into the MAC:** the `open_payload`, `open_token`, `open_pop`. Those
are covered by the TLS exporter itself — the whole stream is inside the TLS
record layer, and the exporter derives from the same handshake. A peer that
tampers with `OPEN_STREAM` bytes would have to break the TLS AEAD first. If
you want a *forward-secret* per-stream secret distinct from the connection
exporter (so a leaked TLS session key doesn't compromise past streams),
that's a different design (§14, L5).

### 4.6 Retirement ring

When a stream is fully closed (`send_fin and remote_fin and not _buf and not_reset`), `_forget(st)` removes it from `_streams` and appends its sid to
`_retired`. The ring holds up to `8 * max_streams` sids.

If a `STREAM_DATA`, `WINDOW_UPDATE`, or `CANCEL` arrives for a sid in
`_retired`, `_lookup` returns `None` and the frame is dropped — a compliant
peer can legitimately send one more frame after we retire, because the retire
is our local decision. `_stale_bytes` accumulates the dropped frames' payload
sizes and is fatal at `MAX_STALE_BYTES = 8 MB`. Without the cap, a peer could
flood with retired-sid frames forever; without the tolerance, a race in the
retire/cancel path would fail a correct peer.

### 4.7 Fatality model

`TransportError` is connection-fatal. `StreamError` is stream-scoped. The
distinction is enforced by the code, and the docstring is precise:

> *A fatal `TransportError` is reserved for behaviour a compliant peer can
> never produce. Races that two correct peers can legitimately hit (data
> crossing a `CANCEL`, credit for a just-retired stream) are tolerated.*

The tolerated races:

| Race | What happens |
|---|---|
| `DATA` arrives after we retired the stream | `_lookup` → `None` → drop, count against `_stale_bytes` |
| `CANCEL` arrives for a stream we already reset | Same |
| `WINDOW_UPDATE` for a retired stream | Same |
| Peer's `CLOSE` arrives while we're shutting down | `_on_close` raises `PEER_CLOSE` (fatal, but `_shutdown` is idempotent) |

The fatal ones (a compliant peer *cannot* produce these):

| Frame | Failure mode |
|---|---|
| `DATA` for an unknown, non-retired sid | `UNKNOWN_STREAM` |
| Duplicate `SESSION_INIT` | `DUPLICATE_HELLO` |
| `OPEN_STREAM` from the server (client receives) | `UNEXPECTED_OPEN` |
| `OPEN_STREAM` with even sid | `BAD_STREAM_ID` |
| `OPEN_STREAM` with sid ≤ last accepted | `BAD_STREAM_ID` |
| `OPEN_STREAM` when `len(_streams) ≥ max_streams` | `STREAM_LIMIT` |
| `DATA` after `FIN` on that stream | `DATA_AFTER_FIN` |
| `seq` not exactly `_recv_seq` | `SEQ` |
| Payload exceeds `_window` | `FLOW_CONTROL` |
| `WINDOW_UPDATE` credits > sent bytes | `CREDIT_OVERRUN` |
| `PONG` for a nonce we never sent | `UNSOLICITED_PONG` |
| Malformed `OPEN_STREAM` / `STREAM_DATA` / `WINDOW_UPDATE` / `CANCEL` / `CLOSE` | `BAD_*` |

---

## 5. Memory and liveness bounds

Every peer-influenced structure is bounded. The table is from the module
docstring:

| Structure | Bound | Enforced by |
|---|---|---|
| live streams | `max_streams` (covers pending accepts) | `_on_open`: `len(_streams) >= config.max_streams` |
| buffered per stream | `stream_window` | `_on_stream_data`: `_recv_buffered + len(data) > _window` |
| retained per stream (OPEN metadata) | `OPEN_MAX_TOKEN + OPEN_MAX_POP + OPEN_MAX_BODY` | `FrameSpec.OPEN_STREAM` |
| retired tombstones | `8 * max_streams` | `_mark_retired`'s `while len(_retired) > _retired_cap` |
| pending control frames | one pong slot + one entry per live stream | `_pong: Optional[bytes]`; `_cancels` / `_credits` keyed by sid |
| tolerated stale bytes | `MAX_STALE_BYTES = 8 MB` | `_tolerate_stale` |
| outstanding pings | `MAX_OUTSTANDING_PINGS = 3` | `_ping_loop`: `len(_outstanding_pings) >= MAX_OUTSTANDING_PINGS` |

`TransportConfig.__post_init__` cross-checks:

```python
max_streams * stream_window <= MAX_BUFFERED (32 MB)
max_streams * PER_STREAM_OVERHEAD <= MAX_STREAM_OVERHEAD (4 MB)
FIXED_OVERHEAD + MAC_LEN + 8 + min(stream_window, MAX_CHUNK_BYTES) <= max_frame
```

The third check means a maximal chunk advertised by the peer's window must
actually fit in our own frame size. Without it, a peer could advertise a
`stream_window` larger than our `max_frame` allows — we'd accept the window
and then never be able to send anything. The check makes the configuration
self-consistent.

The liveness checks:

```python
idle_timeout >= 2 * ping_interval
frame_timeout <= idle_timeout
```

If `idle_timeout < 2 * ping_interval`, the peer's PING could arrive just
before our idle timeout and we'd fail spuriously. Two intervals gives one full
round trip of slack.

---

## 6. End-to-end flow — one successful stream

```
client                                                  server
  │                                                        │
  │──── TLS handshake (out of scope; handled by asyncio) ──│
  │                                                        │
  │  TlsConnection.wrap() → peer_id, SessionSecrets        │
  │  Transport.establish():                                │
  │──── SESSION_INIT (v4, features, limits) ──────────────▶│
  │◀─── SESSION_INIT (v4, features, limits) ───────────────│
  │  both: set peer_max_frame, peer_window, peer_max_streams
  │  both: spawn reader + ping + control + expiry + supervise
  │                                                        │
  │  open_stream(kind="chat", token=..., pop=...)          │
  │──── OPEN_STREAM (sid=1, kind, token, pop, body) ──────▶│
  │                                                        │  _on_open: validate sid, add to _pending
  │                                                        │  accept() returns Stream
  │                                                        │
  │  send(b"hello")                                        │
  │──── STREAM_DATA (sid=1, seq=0, mac, "hello") ─────────▶│
  │                                                        │  _on_stream_data: seq, window check, buffer
  │                                                        │  recv() → verify mac → yield "hello"
  │                                                        │  _grant(st, 5) → queue WINDOW_UPDATE
  │◀─── WINDOW_UPDATE (sid=1, credits=5) ──────────────────│
  │  _on_window_update: bump _send_granted                 │
  │                                                        │
  │  send(b"", fin=True)                                   │
  │──── STREAM_DATA (sid=1, seq=1, mac, "") ──────────────▶│
  │                                                        │  recv() → b"" → remote_fin = True
  │                                                        │
  │  aclose()                                              │
  │──── (nothing; send_fin already set) ──────────────────│
  │                                                        │  recv() → None (drained + remote_fin)
  │                                                        │  aclose() → may send empty FIN if not sent
  │◀─── STREAM_DATA (sid=1, seq=0, mac, "", fin) ──────────│
  │  _on_stream_data: remote_fin = True                    │
  │  retire_if_done → _forget → _mark_retired(sid=1)       │
  │                                                        │
  │  transport.close("done")                               │
  │──── CLOSE (reason="done") ────────────────────────────▶│
  │                                                        │  _on_close → PEER_CLOSE (fatal)
  │                                                        │  _shutdown: close, no reply
  │  _supervise → _shutdown → _closed.set()                │
  │                                                        │
```

Note: **there is no per-stream close handshake other than FIN.** A `CANCEL`
frame aborts a stream (equivalent to TCP RST); a FIN (empty `STREAM_DATA` with
`fin=True`) half-closes it. Both halves of a stream must reach FIN before the
stream is retired. If both sides send `CANCEL`, the stream is retired immediately.

---

## 7. Properties

What the stack guarantees when §1.2 is respected and the caller doesn't
misuse the API:

**P1 — Identity is verified, not claimed.** `TlsConnection.peer_id` comes only
from a `x509.Certificate` whose DER was produced by a TLS stack in
`CERT_REQUIRED` mode after a successful chain verification. A caller that
needs the peer identity asks `tls.peer_id`; it cannot be anything else.

**P2 — Send and receive directions are independent.** No bit of a frame
authenticated with `send_ikm` can be verified with `send_ikm`. This means a
peer cannot reflect our own chunks at us and cannot replay them as its own.

**P3 — Chunks are bound to their stream.** The MAC input includes
`stream_id`, so a captured chunk cannot be relocated from one stream to
another.

**P4 — Chunks are bound to their position.** The MAC input includes `seq`,
and `_on_stream_data` checks `chunk.seq == st._recv_seq`, so a captured
chunk cannot be replayed later in the stream.

**P5 — Framing is bounded and fail-closed.** Every frame is validated against
its `FrameSpec` before any payload tail is read. Once the 4-byte length
prefix is consumed, any error is permanent. There is no resynchronization.

**P6 — Flow control is two-sided.** A peer cannot exceed our advertised
receive window (`FLOW_CONTROL`), and we cannot exceed the peer's advertised
receive window (`_await_credit` blocks until we have credit). Credit returns
on dequeue, not on arrival, so a peer that never reads is not rewarded.

**P7 — Memory is bounded.** The `_streams` / `_buf` / `_retired` / `_stale_bytes`
structures are all capped. The worst-case memory per side is bounded by
`MAX_BUFFERED + MAX_STREAM_OVERHEAD + MAX_STALE_BYTES`.

**P8 — Fatal errors are rare and justified.** A `TransportError` implies
non-compliant peer behavior. Races that two correct peers can hit are
tolerated (drop the frame, don't fail).

What is **not** guaranteed:

- **P1 does not survive a compromised `PeerVerifier`.** If `SpiffeAdapter`'s
  `authorize` callback always returns `True`, A4 is defended but A4's caller
  is not. The stack assumes the callback is honest.
- **P1–P8 do not survive a TLS-terminating sidecar.** See §12.4.
- **P1–P8 do not survive a compromised `_derive_session_secrets`.** A peer
  that learns the exporter can forge every subsequent frame. The exporter is
  scrubbed on derivation failure, but if it leaks elsewhere, all bets are off.

---

## 8. Failure modes — fail-open or fail-closed?

Every check either admits or raises. **There are no fail-open paths** once the
TLS layer has returned a `TlsConnection`.

| Failure | Behavior |
|---|---|
| Peer cert chain invalid | `TlsConnection.wrap` raises; connection closed |
| Peer cert expired | Same |
| Peer trust domain wrong | `SpiffeAdapter.verify_peer` raises; connection closed |
| Peer identity wrong (target pin) | Same |
| Peer not authorized by callback | Same |
| Forbidden cipher | `TlsConnection._verify` raises; connection closed |
| ALPN mismatch | Same |
| Malformed frame in `FrameReader` | Reader permanently closed; `_reader_loop` stops transport |
| Unknown frame type | `FrameReader.read_frame` raises `UNKNOWN_TYPE`; reader closed |
| Frame exceeds `payload_len` limit | Reader closed |
| Frame body exceeds type's `FrameSpec` | Reader closed |
| Handshake `version != 4` | `Transport.establish` raises `TransportError` |
| Handshake `features != FEATURES` | Same |
| `OPEN_STREAM` from server, wrong sid parity, non-increasing sid | `TransportError` |
| `STREAM_DATA` seq mismatch | `TransportError` |
| `STREAM_DATA` exceeds window | `TransportError` |
| `WINDOW_UPDATE` credit overrun | `TransportError` |
| `PONG` for unsolicited nonce | `TransportError` |
| Stale bytes > `MAX_STALE_BYTES` | `TransportError("STALE_FLOOD")` |
| PING timeout (3 unanswered) | `TransportError("PING_TIMEOUT")` |
| Certificate expiry | `_request_stop("CERT_EXPIRED")` |
| Peer sends `CLOSE` | `TransportError("PEER_CLOSE")` |
| Peer sends `ERROR` | `TransportError("PEER_ERROR")` |
| Local `Stream.send` on reset/closed stream | `StreamError("RESET" / "SEND_CLOSED" / "CONN_CLOSED")` |
| Local `Stream.recv` on reset/closed stream | Same |
| Local `Stream.send` chunk too large | `StreamError("CHUNK_TOO_LARGE" / "CHUNK_EXCEEDS_WINDOW")` |

`StreamError` is stream-scoped: the connection stays up, the caller can retry
on a different stream. `TransportError` is connection-fatal: the connection is
torn down.

---

## 9. Design decisions worth knowing

### 9.1 Why TLS 1.3 only

RFC 9266 channel binding is only sound on TLS 1.2 with extended master secret.
Python's `ssl` module doesn't expose "was extended master secret negotiated,"
so a TLS 1.2 connection cannot be proven to be RFC 9266-compliant from
Python. The `TlsPolicy.__post_init__` enforces `allowed_versions <= {"TLSv1.3"}`
because there is no way to enforce the weaker check at runtime.

### 9.2 Why three secrets from one exporter

Covered in §2.2. The short version: `channel_binding` is *public* (it appears
in PoPs and evidence records), so it must be one-way from the stream keys. And
the two directions must be independent, or reflection attacks work.

### 9.3 Why "verify before interpret" in framing

Every `FrameReader.read_frame` validates the `FrameSpec` before reading the
payload. A peer that sends a 4 MB `payload_len` for a `PING` (which has
`body=8`) is rejected at byte 15, not byte 4 MB. Without this, a hostile peer
could allocate 4 MB per frame and exhaust memory before any size check fires.

### 9.4 Why two timeouts

`idle_timeout` (nobody is talking) and `frame_timeout` (somebody started a
frame and stopped) are different failure modes and deserve different
durations. A production deployment typically sets `idle_timeout=60s` (long
enough for a chatty client to be quiet between requests) and
`frame_timeout=30s` (a peer that can't finish a frame in 30s is broken).

### 9.5 Why HMAC vs AEAD for chunks

TLS already provides AEAD over the whole record. Adding a second AEAD over
each chunk would be redundant. HMAC over the chunk header + data is cheaper,
and it extends the integrity guarantee to the chunk boundaries — a MITM that
*can't* break TLS but *can* reorder TCP segments (e.g. an on-path attacker
controlling a router) cannot reorder or drop individual chunks undetected.

If you need per-chunk AEAD (e.g. to allow selective disclosure of chunks to a
third party), that's a different design and probably a different transport.

### 9.6 Why the retirement ring

Races between "we decided to retire this stream" and "the peer sent one more
frame for it" are real. Without tolerance, a correct peer would occasionally
fail because of a benign race. Without a cap, a hostile peer could flood
retired sids forever. The ring bounds the tolerance window, and `_stale_bytes`
bounds the volume.

### 9.7 Why no writer queue

A writer queue would decouple the application's `send()` from the socket's
drain. That's useful for a chatty app but adds a memory bound the transport
must manage. The current design says: if the socket is slow, `send()` blocks.
The application can `asyncio.wait_for` around it if it wants to skip a slow
write. This is simpler and has no queue to overflow.

---

## 10. Integration patterns

### 10.1 Client

```python
from libs.transport.tls import (
    SpiffeAdapter, TlsConnection, TlsPolicy, DEFAULT_TLS_POLICY,
)
from libs.transport.stream.frame import FrameStream
from libs.transport.stream.stream_session import Transport, TransportConfig

adapter = SpiffeAdapter(
    peer_id="spiffe://aegis/client/my-client",
    authorize=lambda peer: peer == "spiffe://aegis/server/my-server",
    target_node_id="spiffe://aegis/server/my-server",
    trust_domain="aegis",
)

reader, writer = await asyncio.open_connection(
    host, port, ssl=ssl_ctx, server_hostname=None,  # SPIFFE uses URI SAN
)
tls = await TlsConnection.awrap(
    reader, writer, adapter=adapter, policy=DEFAULT_TLS_POLICY,
)
transport = await Transport.establish(
    tls, TransportConfig(max_streams=32), is_client=True,
)

try:
    stream = await transport.open_stream(
        kind="chat",
        token=capchain_token,
        pop=pop_envelope,
    )
    await stream.send(b"hello")
    reply = await stream.recv()
    await stream.aclose()
finally:
    await transport.close("done")
```

### 10.2 Server

```python
async def handle(reader, writer):
    tls = await TlsConnection.awrap(
        reader, writer, adapter=server_adapter, policy=DEFAULT_TLS_POLICY,
    )
    transport = await Transport.establish(
        tls, TransportConfig(max_streams=256), is_client=False,
    )
    try:
        while not transport.closed:
            stream = await transport.accept(timeout=60)
            asyncio.create_task(handle_stream(stream))
    except StreamError as exc:
        # ACCEPT_TIMEOUT or CONN_CLOSED; either is fine
        pass
    finally:
        await transport.close("done")
```

### 10.3 Replacing the signer

`Stream.set_signer` overrides the default HMAC signer for a specific stream.
It must be called before the first `send` or `recv`:

```python
stream = await transport.open_stream(kind="chat", ...)
stream.set_signer(MyFancySigner(...))   # must be before send/recv
await stream.send(b"hello")
```

The signer contract: `sign(stream_id, seq, fin, data) -> 32 bytes`;
`verify(stream_id, seq, fin, data, mac) -> None or raise`. Implementations
must be pure functions of the arguments (no per-call state, no clock).

---

## 11. Deployment checklist

**TLS**

- [ ] `ssl.SSLContext.verify_mode == ssl.CERT_REQUIRED`
- [ ] `ssl.SSLContext.check_hostname == False` (SPIFFE identity is URI-SAN based)
- [ ] `ssl.SSLContext.minimum_version == ssl.TLSVersion.TLSv1_3`
- [ ] `ssl.SSLContext.set_alpn_protocols(["aegis/v1"])`
- [ ] `TlsPolicy.allowed_alpns` matches what the listener advertises
- [ ] `peer_id` extractor reads `getpeercert()["subjectAltName"]` for `spiffe://` URIs, **not** a header or query param

**SPIFFE adapter**

- [ ] `SpiffeAdapter.target_node_id` set if you know the exact peer you want
- [ ] `authorize` callback is honest (not `lambda _: True` in production)
- [ ] `trust_domain` matches the peer cert's trust domain
- [ ] `peer_id` is the caller's own full SPIFFE ID (used for self-loop rejection)

**Session**

- [ ] `TransportConfig.idle_timeout >= 2 * ping_interval`
- [ ] `TransportConfig.frame_timeout <= idle_timeout`
- [ ] `TransportConfig.max_streams * stream_window <= MAX_BUFFERED`
- [ ] `TransportConfig.max_frame` is the same on both sides (or the smaller of the two wins — but they must be compatible)

**Service mesh**

- [ ] TLS is **end-to-end** for these ports; no terminating sidecar
- [ ] If a sidecar must terminate TLS, accept that A4 and A3 are both partially defeated — see §12.4

**Observability**

- [ ] Log `TlsConnection.peer_id` on connect (not the cert subject)
- [ ] Log `Transport.close_reason` on close (it's the most useful signal)
- [ ] Log `Stream.reset_reason` on stream close (distinguishes local vs. peer reset)
- [ ] Metrics: `_stale_bytes` growth, `_outstanding_pings` depth, `active_streams`, `busy` on the writer

---

## 12. Cross-cutting concerns

### 12.1 The `peer_id` value is a `str`, not `bytes`

`TlsConnection.peer_id` is the SPIFFE ID string, verbatim from the SAN. It is
**not** the certificate subject DN, **not** the CN, **not** the thumbprint.
Downstream code (capchain's `Verdict.holder`, the `ServerContext.session_id`
matching, evidence records) compares it against configured identities. A
mismatch here is a downstream `WRONG_HOLDER`, not a transport error.

### 12.2 `channel_binding` is a `bytes` object

`TlsConnection.channel_binding` is the 32-byte `channel_binding` field of
`SessionSecrets`. It is the *public* value. It is safe to log, safe to embed
in PoPs, safe to write to evidence records. It is **not** `stream_ikm_c2s` or
`stream_ikm_s2c` — those never leave `SessionSecrets` (and `SessionSecrets`
never leaves `TlsConnection`).

### 12.3 Two transports on the same socket are not supported

`FrameStream` takes a single `ByteReader` / `ByteWriter` pair. If you open
multiple `FrameStream`s on the same socket, they will interleave frames and
desynchronize. The session layer is the multiplexing point; use
`Transport.open_stream` instead of creating multiple transports.

### 12.4 Service mesh — the one deployment that silently breaks

If a sidecar (Istio, Linkerd, Cilium) terminates TLS:

- `getpeercert()` returns the **sidecar's** certificate, not the peer's.
  `SpiffeAdapter.verify_peer` sees one identity for every peer. A4 is defeated.
- `export_keying_material` returns the **app↔sidecar** binding, not the
  end-to-end binding. `HmacStreamSigner` derives from a binding that both the
  sidecar and the peer's sidecar can also derive. A6 (reflection) is defeated.

There is no way to make channel binding work through a TLS-terminating sidecar.
The exporter is bound to the end-to-end handshake by construction.

Fixes, in order of preference:

1. **Passthrough TLS** for these ports (Istio:
   `traffic.sidecar.istio.io/excludeInboundPorts`).
2. **Don't terminate TLS in the mesh** for these connections.
3. **Accept the risk** and use SPIFFE IDs from mesh-supplied attributes — but
   this reintroduces the "attacker controls the attribute" risk.

---

## 13. Code path audit

Where a security engineer should look, in order:

| File | What to audit |
|---|---|
| `tls.py:TlsConnection._verify` | Steps 1–10 in §2.1; the `getpeercert()` non-empty check is the load-bearing one for A3 |
| `tls.py:_derive_session_secrets` | The `try/finally` around the `bytearray` scrub; the `del raw` before computing `prk` |
| `tls.py:split_exporter` | The HKDF Extract/Expand pattern — verify no expansion can collide with another by prefix |
| `tls.py:SpiffeAdapter.verify_peer` | Order: `extract_spiffe_id` → trust domain → self-loop → target pin → `authorize` |
| `frame.py:FrameReader.read_frame` | Order of checks: prefix under idle, then `_to_limit`, then prologue under frame timeout, then tail. `_to_limit` callable re-evaluated after the prefix |
| `frame.py:FrameReader._exact` | Exception order: `TimeoutError` before `OSError` (3.11+); `IncompleteReadError` distinguished by `exc.partial` |
| `frame.py:FrameSpec.validate_header` | Bounds checks before any `len()` on `payload_len` |
| `frame.py:decode_frame` | Memoryview cast; `_U32.unpack_from(raw, 0)` before length checks |
| `stream_session.py:_on_stream_data` | `DATA_AFTER_FIN`, `seq == _recv_seq`, `_recv_buffered + len(data) <= _window` — all before mutation |
| `stream_session.py:_on_window_update` | `_send_granted + credits <= _send_sent` — credit overrun check |
| `stream_session.py:Stream.send` | Commit order: sign → construct frame → bump `_send_seq` / `_send_sent` → `_write`. `_write` failure tears down the transport |
| `stream_session.py:Stream.recv` | No `await` between `self._buf[0]` and `popleft`; MAC verified before dequeue |
| `stream_session.py:_shutdown` | `_down` guard; worker cancellation order; best-effort CLOSE only if writer not busy |

Every function above has a corresponding test in `selftest.py` (or should).

---

## 14. Known limitations and defects

### 14.1 Design limitations

- **L1 — TLS 1.3 only.** §9.1. No path to TLS 1.2 with extended master
  secret, because Python's `ssl` module cannot report it.
- **L2 — No compression.** Compression over authenticated ciphers is a CRIME
  vector; the transport does not attempt it.
- **L3 — No certificate rotation.** The `_expiry_loop` checks `not_after` but
  does not honor a cert swap on the same connection. A rotation requires a
  new transport.
- **L4 — No application-level graceful shutdown.** `CLOSE` is connection-fatal.
  There is no "I'm done, let me drain in-flight streams first" mode. The
  application must drain streams itself before `close()`.
- **L5 — No forward secrecy for past streams if the TLS session key leaks.**
  The exporter-derived stream keys are forward-secret only insofar as the TLS
  exporter is. If an attacker obtains the session's `export_keying_material`
  output, they can derive every stream key. For forward secrecy, add per-stream
  ephemeral ECDH keyed from `stream_ikm`; that is not currently done.


### 14.2 Informational

- **I1 — `FrameType.name` uses `DEFAULT_REGISTRY`, not the caller's registry.**
  Error messages from custom-registry callers will show `UNKNOWN(0x0A)` for
  their custom types.
- **I2 — MAC verification is at `recv`, not at receive.** A peer can fill
  `stream_window` with bad-MAC chunks before the first `recv` fails. Bounded
  DoS, not a bypass.
- **I3 — `_on_pong` assumes TCP ordering.** If PONG(N) arrives before PONG(M)
  for M < N, all older nonces are dropped. Unobservable on TCP; a real bug on
  a reordering substrate.
- **I4 — Cancelling `write_frame` does not withdraw the frame.** Documented;
  callers that retry after `CancelledError` will send the frame twice.
- **I5 — `prk` in `_derive_session_secrets` is `bytes` and cannot be
  scrubbed.** The `scratch` buffer is scrubbed, but the `bytes` returned by
  `hmac.new(...).digest()` survives until GC. Flagged in the docstring.

---

## 15. Quick start

```python
"""Minimum viable client + server over the v4 transport."""
import asyncio
import ssl

from libs.transport.tls import (
    SpiffeAdapter, TlsConnection, DEFAULT_TLS_POLICY,
)
from libs.transport.stream.frame import FrameStream
from libs.transport.stream.stream_session import (
    Stream, StreamError, Transport, TransportConfig,
)


async def serve(reader, writer):
    # The adapter is caller-supplied; it decides who is allowed.
    adapter = SpiffeAdapter(
        peer_id="spiffe://aegis/server/my-server",
        authorize=lambda peer: peer.startswith("spiffe://aegis/client/"),
        trust_domain="aegis",
    )
    try:
        tls = await TlsConnection.awrap(reader, writer, adapter=adapter)
    except Exception as exc:
        print("TLS rejected:", exc)
        return
    transport = await Transport.establish(
        tls, TransportConfig(max_streams=64), is_client=False,
    )
    try:
        while not transport.closed:
            stream = await transport.accept(timeout=60)
            asyncio.create_task(handle_stream(stream))
    except StreamError:
        pass
    finally:
        await transport.close("done")


async def handle_stream(stream: Stream):
    async with stream:
        async for chunk in recv_all(stream):
            # chunk is b"..." (or b"" for a zero-length FIN)
            ...
        await stream.send(b"ack", fin=True)


async def recv_all(stream: Stream):
    while True:
        data = await stream.recv()
        if data is None:
            return
        yield data


async def connect():
    adapter = SpiffeAdapter(
        peer_id="spiffe://aegis/client/my-client",
        authorize=lambda peer: peer == "spiffe://aegis/server/my-server",
        target_node_id="spiffe://aegis/server/my-server",
        trust_domain="aegis",
    )
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations("ca.pem")
    ctx.load_cert_chain("client.pem", "client-key.pem")
    ctx.set_alpn_protocols(["aegis/v1"])

    reader, writer = await asyncio.open_connection(
        "server.example.com", 8443, ssl=ctx, server_hostname=None,
    )
    tls = await TlsConnection.awrap(reader, writer, adapter=adapter)
    transport = await Transport.establish(
        tls, TransportConfig(max_streams=32), is_client=True,
    )
    try:
        stream = await transport.open_stream(kind="chat")
        await stream.send(b"hello", fin=True)
        async for chunk in recv_all(stream):
            ...
    finally:
        await transport.close("done")
```

Notes:

- `TlsConnection.awrap` closes the writer on any failure. `awrap` is the async
  version; the sync `wrap` closes the writer but does not await
  `writer.wait_closed()`. Prefer `awrap` in asyncio code.
- `Transport.establish` is a classmethod. Do not construct `Transport(...)`
  directly.
- `stream.send(b"", fin=True)` sends a zero-length FIN. `recv()` returns
  `b""` for a zero-length chunk and `None` for "peer sent FIN and buffer is
  drained."
- `stream.aclose()` attempts a FIN; on failure it cancels the stream. If you
  need to guarantee the FIN was delivered, call `send(b"", fin=True)` directly
  and handle the `StreamError`.
- The transport handles `CancelledError` correctly: cancelling an in-flight
  `recv` closes the reader (permanent), and the transport escalates to a
  connection stop. Do not expect to retry after a cancellation.
