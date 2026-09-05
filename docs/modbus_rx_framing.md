# Modbus receive framing

The Pi reads a Linux TTY byte stream; read boundaries and read timestamps are
not wire-level RTU boundaries. Normal buffering can combine requests, foreign
responses and broadcasts. `ogm_pi/rtu_framing.py` extracts CRC-valid prefixes
using known shapes. This is best-effort framing, not recovered UART timing.

The policy follows the buffered recovery in Cybergrany/ModbusRTUSlave branch
`agent/ogm-fix-crc-parse-7c2a`, reviewed at `4f88a46`. The Pi keeps its existing
20 ms **host-observed** idle recovery window. It does not add a T3.5 wait to a
successfully extracted request or change master timeouts/inter-frame gaps.

## Shape coverage and extensions

The standard layer knows request and response lengths for FC1–8, FC11–12,
FC15–17, FC20–24 and FC43/MEI14, plus foreign exception responses. FC8 only
has a deterministic length for diagnostic subfunctions 1–4, 10–18 and 20.
Return Query Data (subfunction 0), reserved diagnostics, other MEI types and
unregistered functions are unknown. There is no guessed eight-byte default.

Shapes define framing only. They do not advertise implemented functions;
libmodbus still decides how to handle accepted standard requests. CRC-valid
requests with invalid quantities/values can now reach its exception handling
instead of being rejected by the old framing routine's semantic checks.

Custom request/response hooks are injected into `RtuFramer` as callables:

```python
def length(data: bytes) -> int | Shape:
    # data starts with unit address and function code, and has at most 256 bytes.
    # Return the total ADU length INCLUDING address, function and CRC, or:
    # Shape.NEED_MORE: relevant header is incomplete
    # Shape.UNKNOWN: function/subfunction is not described here
    # Shape.INVALID: header describes an impossible frame
    ...
```

Hooks must be bounded, side-effect-free and perform no I/O. They are consulted
only when the standard layer returns UNKNOWN; they cannot replace a recognized
standard shape. Register separate hooks for custom responses if needed. A
hook returning a length outside 4–256 bytes is rejected.

`ogm_pi/ogm_rtu_shapes.py` describes FC69 with inner FC5/6/15/16. The backend
registers this request hook. FC69 is **framing-only**, including when its target
is this Pi: recognizing it does not enable execution. Its complete ADU is
consumed and ignored. No register layout, pin definition or dependency changes
are required. Future custom shapes can be added to this module without changing
the standard layer, but deployed receivers still need that definition to recover
those shapes from batched traffic.

## Recovery and dispatch

- Only foreign unit IDs use response candidates. Local/broadcast frames use
  request shapes, preventing a variable FC16 request from being split at an
  accidentally CRC-valid eight-byte response prefix.
- Foreign ADUs are consumed as whole frames. Rejected alternate candidate CRCs
  do not count as errors if a valid request or response candidate is found.
- An earlier local unicast with trailing bytes is discarded before register
  mutation, IPC publication or reply. The trailing bytes remain available. The
  reader also checks one bounded chunk of already-readable TTY data before
  returning an otherwise final local request.
- A trailing partial frame/noise is sufficient for conservative stale-unicast
  suppression; it does not prove that the earlier request timed out. The final
  request may itself already be late without observable evidence. RTU has no
  transaction ID, so this policy cannot guarantee freshness.
- Normal broadcast suppression is preserved: the adapter does not call
  `modbus_reply()` for broadcasts. This change does not add broadcast mutation
  support to the Pi mapping or IPC path.
- Unknown/invalid frames and CRC failures enter discard-until-idle recovery.
  Their payload is never scanned for an embedded actionable request. This can
  deliberately lose subsequent legitimate traffic before idle is observed.
- A partial header/candidate is discarded on the existing 20 ms host-idle
  timeout. Further incoming bytes keep the reader out of idle. On a continuously
  busy bus, discard recovery can persist until such an idle period occurs.
- Pending input is bounded to 4096 bytes, candidates to 256 bytes. Overflow
  discards the backlog and subsequent input until idle, rather than treating an
  arbitrary suffix as a new request. One OS read requests at most 4096 bytes.

CRC and shape checks are still heuristic where foreign request/response
interpretations overlap; a valid CRC is not a unique frame delimiter. This
implementation does not claim arbitrary unknown-stream recovery.

## Diagnostics

Counters are local to the daemon process and reset on restart. A
`Modbus RX recovery address=...` warning reports cumulative counters when loss
counters change, at most once every five seconds (first loss reports promptly).
Healthy traffic does not generate periodic warnings. Detailed frame logging
and recoverable libmodbus-error logging retain their existing opt-in settings.

Counters distinguish delivered requests (`rx_ok`), foreign frames, suppressed
broadcasts, framing-only custom frames, CRC failures, invalid lengths/addresses,
unknown shapes, stale local drops, partial timeouts, buffer overflows and discarded
bytes. `rx_crc_bad` counts failed head candidates, not proven electrical corruption.
Counters may include frames that never passed semantic validation by libmodbus.

Pi `BOARD_STATS` error/overflow registers remain unchanged and currently contain
placeholder zeros. Use the local recovery summaries and same-board master
failures for validation; zero BOARD_STATS errors are not parser-health evidence.

## Validation and rollout

From the repository root:

```bash
python -B -m unittest discover -s tests -p 'test_*.py'
```

The framing tests cover standard requests/foreign responses/exceptions and FC69
at every single split, misleading CRC-valid prefixes, maximum frames, malformed
headers, noise, unknown functions, overflow, custom-hook precedence and bounded
backlogs. Receive tests exercise the production adapter with scripted serial
delivery and verify stale suppression before mapping/store/IPC side effects.
An additional pseudoterminal check uses real OS read/readiness calls. These
software checks do not validate a physical UART, RS485, libmodbus C runtime,
or actual playback.

Before deployment, record the installed Pi revision/configuration. Update one
Pi at a time outside a game: restarting `ogm_pi` also stops supervised apps and
forces safe outputs. Keep the previous installation available for rollback.
Exercise 41/42 under representative audio load, including stop/preempt/play and
retry sequences. Compare same-board master timeouts, subsequent frame/address
errors, local drop reasons and actual playback/order. Keep master timing fixed
for this comparison. The legacy audio path's individual polls/writes and Linux
scheduling delays remain separate potential sources of load and latency.
