# Matter Decode

Wireshark Lua dissector for decrypting and analyzing Matter protocol traffic.

## Overview

Matter encrypts all session traffic with AES-128-CCM, making packet analysis impossible without session keys. This dissector decrypts Matter packets live inside Wireshark given the I2R/R2I session keys.

## Quick Start

### 1. Get session keys

Build chip-tool with `CHIP_DETAIL_LOGGING=1` (or `CHIP_CONFIG_SECURITY_TEST_MODE=1` for fixed test keys). It will print keys during session establishment:

```
[SC] Session Keys Derived (Role: Initiator):
[SC] I2R Key (Initiator to Responder):
[SC] 0x5e, 0xde, 0xd2, 0x44, 0xe5, 0x53, 0x2b, 0x3c,
[SC] 0xdc, 0x23, 0x40, 0x9d, 0xba, 0xd0, 0x52, 0xd2,
[SC] R2I Key (Responder to Initiator):
[SC] 0xa9, 0xe0, 0x11, 0xb1, 0x73, 0x7c, 0x6d, 0x4b,
[SC] 0x70, 0xe4, 0xc0, 0xa2, 0xfe, 0x66, 0x04, 0x76,
```

With `CHIP_CONFIG_SECURITY_TEST_MODE=1`, the keys are always the same (derived from a fixed shared secret with NodeID=0 in the nonce):

| Key | Value |
|-----|-------|
| I2R | `5eded244e5532b3cdc23409dbad052d2` |
| R2I | `a9e011b1737c6d4b70e4c0a2fe660476` |

### 2. Install the dissector

Copy `matter_dissector.lua` to your Wireshark plugins directory:
- **macOS:** `~/Library/Application Support/Wireshark/plugins/`
- **Linux:** `~/.local/lib/wireshark/plugins/`

### 3. Configure keys in Wireshark

Go to **Edit > Preferences > Protocols > MATTER_DECRYPT** and enter:

| Field | Description | Example (test mode) |
|-------|-------------|---------------------|
| I2R Key | 32 hex chars, initiator to responder | `5eded244e5532b3cdc23409dbad052d2` |
| R2I Key | 32 hex chars, responder to initiator | `a9e011b1737c6d4b70e4c0a2fe660476` |
| I2R sender node ID | Initiator's node ID for nonce | `0` |
| R2I sender node ID | Responder's node ID for nonce | `0` |

For non-test-mode sessions, use the actual operational node IDs (e.g. `0x1b669`, `0x6e`).

### 4. Open pcap

Matter packets on UDP port 5540 will be decrypted automatically. The dissector shows:
- Message header (flags, session ID, message counter, node IDs)
- Protocol header (exchange flags, opcode, protocol ID)
- Decoded TLV payload structure

## Building chip-tool with Key Logging

The key logging patch is in `CryptoContext.cpp` — the `#if CHIP_DETAIL_LOGGING` block in `InitFromSecret()` calls `ChipLogByteSpan` to print I2R, R2I, and attestation challenge bytes.

```bash
./scripts/build/build_examples.py \
  --target linux-arm64-chip-tool \
  build -- chip_detail_logging=true
```

## Matter Encryption Details

**Message format:**

```
[ Message Header (8-24 bytes) ] [ Encrypted Payload ] [ 16-byte MIC ]
```

**Message header fields (bits [1:0]=DSIZ, bit 2=S, bits [7:4]=Version):**
- Message Flags (1B), Session ID (2B LE), Security Flags (1B), Message Counter (4B LE)
- Source Node ID (8B LE, optional), Destination Node/Group ID (optional)

**AES-CCM parameters:**
- Key: 128-bit (I2R or R2I depending on sender)
- Nonce (13 bytes): `security_flags(1) || msg_counter(4, LE) || source_node_id(8, LE)`
- AAD: the unencrypted message header
- Tag: 16 bytes (MIC)

**Session keys:**
- **I2R (Initiator to Responder):** encrypts messages from session initiator
- **R2I (Responder to Initiator):** encrypts messages from responder

## Prerequisites

Wireshark 3.6+ (Lua 5.2/5.4 — no external dependencies)

## Files

| File | Description |
|------|-------------|
| `matter_dissector.lua` | Wireshark Lua dissector with AES-CCM decryption |
| `CryptoContext.cpp` | Reference: patched Matter crypto context with key logging |
| `PASESession.cpp` | Reference: PASE session establishment code |

Obsolete Python scripts (key extraction, CLI decryption, CASE derivation) are on the `obsolete` branch.
