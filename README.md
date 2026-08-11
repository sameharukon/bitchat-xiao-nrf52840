# XIAO nRF52840 Bitchat BLE Peer Prototype

An experimental, unofficial Bitchat BLE interoperability project for the
Seeed Studio XIAO nRF52840.

The firmware discovers an official Bitchat peer, connects as a BLE central,
subscribes to its GATT characteristic, reconstructs fragmented packets,
validates peer announcements, and advertises the XIAO back to the app as
`xiao52840`.

The official iPhone app has displayed the XIAO as a peer, included its sender
ID in a direct-neighbor announcement, and sent it authenticated
`REQUEST_SYNC` packets. Signed, GCS-aware RSR announcement responses have also
been transmitted successfully from the XIAO.

> [!WARNING]
> This is protocol research firmware, not a production Bitchat client. It does
> not yet implement Noise sessions or private messaging. Do not rely on it for
> confidential or safety-critical communication.

## Current Status

| Capability | Status |
| --- | --- |
| Bitchat advertisement discovery | Verified on hardware |
| GATT connection and notification subscription | Verified on hardware |
| ATT MTU 247 negotiation | Verified on hardware |
| Version 1 packet parsing | Implemented for the currently observed fields |
| Fragment reassembly | Verified for one active assembly |
| Announcement TLV decoding | Verified on hardware |
| Sender ID derivation from the X25519 key | Verified on hardware |
| Ed25519 announcement verification | Verified on hardware |
| Persistent local X25519/Ed25519 identity | Implemented; reboot test pending |
| Signed local announcement transmission | Accepted by the official iPhone app |
| Directed `REQUEST_SYNC` authentication and GCS decoding | Verified on hardware |
| TTL-zero RSR announcement response | Verified with a 168-byte GATT write |
| Public `MESSAGE` receive and display | Next milestone |
| Noise XX and private messaging | Not implemented |

See [the protocol and implementation status](docs/BITCHAT_PROTOCOL_STATUS.md)
for byte layouts, captured examples, design decisions, test evidence, and the
current roadmap.

## Hardware and Software

- Seeed Studio XIAO nRF52840
- A nearby device running the official Bitchat app
- Arduino IDE
- Seeed nRF52 Boards package
  - Tested with version `1.1.13`
- USB serial monitor at `115200` baud

The board package supplies the libraries used by the sketch:

- Bluefruit52Lib
- Adafruit nRFCrypto
- Adafruit LittleFS
- Seeed internal filesystem support

Cryptographic operations use the nRF52840 CryptoCell CC310 backend.

## Quick Start

1. Install the Seeed nRF52 Boards package in Arduino IDE.
2. Select **Seeed XIAO nRF52840** as the target board.
3. Open [`sketch_bitchat.ino`](sketch_bitchat.ino).
4. Build and upload the sketch.
5. Open the serial monitor at `115200` baud. The sketch waits for the serial
   connection during startup.
6. Open Bitchat on a nearby iPhone and keep Bluetooth enabled.
7. Watch the serial output for discovery, connection, verification, and local
   announcement transmission.

A successful first startup should include output similar to:

```text
Identity filesystem: READY
Local identity storage: CREATED
Local Bitchat identity: READY (persistent)
Ed25519 verifier: READY
Scanning for Bitchat...
```

On later starts, the identity record should load instead:

```text
Local identity storage: LOADED
```

After a peer is found and authenticated:

```text
MTU after exchange: 247
Sender ID verification: VALID
Signature verification: VALID (signed data: 256 bytes)
Local ANNOUNCE signature self-check: VALID
GATT write: OK (168 bytes)
```

## What the Firmware Does

```text
BLE scan
  -> Bitchat service UUID filter
  -> GATT connection and notifications
  -> MTU 247 negotiation
  -> packet parsing
  -> fragment reassembly
  -> announcement identity and signature verification
  -> persistent local identity
  -> signed local announcement
  -> authenticated REQUEST_SYNC and RSR handling
```

Packet storage uses static buffers rather than heap allocation. Inbound and
outbound CryptoCell operations share a FreeRTOS mutex, and GATT writes queued
from notification handling are performed by the Arduino loop.

## Immediate Development Goal

The next milestone is secure public-message reception and serial display:

1. Capture a live public `MESSAGE` (`0x02`) from the iPhone.
2. Authenticate it with the signing key from the peer's verified announcement.
3. Validate the payload as UTF-8.
4. Display the sender, timestamp, and text.
5. Add bounded duplicate suppression and the upstream six-hour freshness
   policy.
6. Verify ASCII, Japanese, emoji, invalid-signature, duplicate, and fragmented
   long-message cases on hardware.

Noise, private messages, public-message transmission, and the BLE peripheral
role are intentionally deferred until public receive passes this test matrix.

## Configuration

The local display name and timing constants are near the top of the sketch:

```cpp
static const char LOCAL_NICKNAME[] = "xiao52840";
static const uint32_t ANNOUNCE_INTERVAL_MS = 20000;
```

The forced REQUEST_SYNC missing-member test is disabled in normal builds:

```cpp
#define FORCE_REQUEST_SYNC_MISSING_TEST 0
```

Set it to `1` only for a one-shot RSR response-path test, then return it to
`0` before normal use.

## Known Limitations

- The XIAO currently operates as a BLE central only.
- Only one fragment assembly and one active-link verified peer are retained.
- Version 2 parsing is partial and has not been fully exercised.
- Compressed payloads are not decoded.
- Noise XX, encrypted private messages, group sessions, files, and media are
  not implemented.
- Local identity seeds are stored in plaintext internal flash. The record hash
  detects accidental corruption but does not encrypt or authenticate the
  secrets.
- The Seeed internal filesystem wrapper may format its area after a mount
  failure, which can erase the identity and cause a new sender ID to be
  generated.
- Serial logs expose nicknames, sender IDs, public keys, packet contents, and
  message traffic. Review logs before sharing them publicly.

## Repository Layout

```text
sketch_bitchat.ino                 Main Arduino firmware
docs/BITCHAT_PROTOCOL_STATUS.md    Protocol notes, status, evidence, roadmap
```

## Upstream Compatibility

Protocol behavior was compared with official Bitchat commit
[`9b84b361225facd8e623f25d76f889d3dc54a879`](https://github.com/permissionlesstech/bitchat/commit/9b84b361225facd8e623f25d76f889d3dc54a879).
Bitchat is active software, so wire assumptions should be rechecked before
future protocol changes.

This repository is not affiliated with or endorsed by the official Bitchat
project.

## Contributing

Hardware captures and focused interoperability fixes are welcome. Keep code
identifiers, comments, commit messages, and documentation in English. For
protocol changes, include the upstream source reference and serial evidence
used to validate the behavior.

Do not commit private identity records, raw secret seeds, or logs that reveal
information you do not intend to publish.

## License

No license has been selected for this repository yet. Add an explicit license
before inviting reuse or redistribution.
