# Matter Decode

Tools for decrypting and analyzing Matter protocol traffic using session keys extracted from a modified chip-tool.

## Overview

Matter encrypts all session traffic with AES-128-CCM, making packet analysis impossible without the session keys. This repo provides:

1. **Wireshark Lua dissector** (`matter_dissector.lua`) — live decryption of Matter packets inside Wireshark using session keys from a keylog file
2. **Key extraction script** (`matter_keylog_extract.py`) — parses chip-tool logs to produce the keylog file
3. **CLI decryption tools** (`matter_decrypt.py`, `matter_decrypt_simple.py`) — offline decryption of individual hex payloads
4. **TLV message decoder** (`matter_decode_message.py`) — decodes cleartext Matter TLV payloads into human-readable structure
5. **Modified chip-tool** (`linux-arm64-chip-tool-logsesskeys`) — pre-built ARM64 Linux binary that logs session keys via `CHIP_DETAIL_LOGGING`

## Quick Start

### 1. Get session keys from chip-tool

Run the modified chip-tool (or any chip-tool built with `CHIP_DETAIL_LOGGING=1`). It will print keys during session establishment:

```
[SC] Session Keys Derived (Role: Initiator):
[SC] I2R Key (Initiator to Responder):
[SC] 0x02, 0x9f, 0xc7, 0xad, 0x1f, 0xd1, 0xa2, 0xc6,
[SC] 0x47, 0x23, 0xfd, 0xa0, 0xa3, 0x63, 0x2c, 0x92,
[SC] R2I Key (Responder to Initiator):
[SC] 0xef, 0x98, 0xda, 0x86, 0xce, 0x61, 0x1f, 0xf8,
[SC] 0x44, 0x29, 0x23, 0xd1, 0xc3, 0x38, 0x64, 0x77,
```

### 2. Extract keys to keylog file

```bash
python3 matter_keylog_extract.py chip-tool.log -o matter_keys.log
```

Or pipe directly:

```bash
./chip-tool pairing onnetwork 1 20202021 2>&1 | tee chip-tool.log
python3 matter_keylog_extract.py chip-tool.log -o matter_keys.log
```

### 3. Decrypt in Wireshark

1. Copy `matter_dissector.lua` to your Wireshark plugins directory:
   - **macOS:** `~/Library/Application Support/Wireshark/plugins/`
   - **Linux:** `~/.local/lib/wireshark/plugins/`
2. Open Wireshark, go to **Edit > Preferences > Protocols > MATTER_DECRYPT**
3. Set **Key Log File** to the path of your `matter_keys.log`
4. Open your pcap — Matter packets on UDP port 5540 will be decrypted automatically

The dissector shows in the packet detail pane:
- Message header fields (flags, session ID, message counter, node IDs)
- Protocol header (exchange flags, opcode, protocol ID)
- Decoded TLV payload structure

### 4. Offline CLI decryption (alternative)

```bash
# Full-featured (parses keys from log file)
python3 matter_decrypt.py \
  --payload <hex_of_full_matter_packet> \
  --keys keys.txt \
  --direction auto

# Simple (provide key and parameters directly)
python3 matter_decrypt_simple.py \
  <encrypted_hex> <key_hex> [security_flags] [msg_counter] [node_id]
```

### 5. Decode cleartext TLV

After decryption, decode the TLV payload:

```bash
python3 matter_decode_message.py 152800360115350137002400012401062402021835012400001818181824ff0b18
```

## Keylog File Format

The keylog file is a simple text format consumed by the Wireshark dissector:

```
# Comment lines start with #
# Format: SESSION_ID  I2R_KEY  R2I_KEY
# Use * for SESSION_ID to try on all sessions
*  029fc7ad1fd1a2c64723fda0a3632c92  ef98da86ce611ff8442923d1c3386477
```

Keys are 32-character hex strings (128-bit AES). The dissector tries both I2R and R2I keys for each packet and uses whichever passes AES-CCM authentication.

## Building chip-tool with Key Logging

The key logging is controlled by `CHIP_DETAIL_LOGGING`. The relevant patch is in `CryptoContext.cpp` — the `#if CHIP_DETAIL_LOGGING` block in `InitFromSecret()` calls `ChipLogByteSpan` to print I2R, R2I, and attestation challenge bytes.

```bash
# Build chip-tool with detail logging
./scripts/build/build_examples.py \
  --target linux-arm64-chip-tool \
  build -- chip_detail_logging=true
```

## Matter Encryption Details

**Message format:**

```
[ Message Header (8-24 bytes) ] [ Encrypted Payload ] [ 16-byte MIC ]
```

**Message header fields:**
- Message Flags (1B): version, source node ID present, destination ID size
- Session ID (2B LE): 0 = unencrypted session establishment
- Security Flags (1B): privacy, control, session type
- Message Counter (4B LE)
- Source Node ID (8B LE, optional)
- Destination Node/Group ID (8B or 2B LE, optional)

**AES-CCM parameters:**
- Key: 128-bit (I2R or R2I depending on sender)
- Nonce (13 bytes): `security_flags(1) || msg_counter(4, LE) || source_node_id(8, LE)`
- AAD: the unencrypted message header
- Tag: 16 bytes (MIC)

**Session keys:**
- **I2R (Initiator to Responder):** encrypts messages from session initiator
- **R2I (Responder to Initiator):** encrypts messages from responder
- **Attestation Challenge:** used during commissioning attestation, not for message encryption

## Prerequisites

- **Wireshark dissector:** Wireshark 3.6+ (Lua 5.2/5.4 — no external dependencies)
- **Python scripts:** Python 3, `cryptography` package (`pip install cryptography`)

## Files

| File | Description |
|------|-------------|
| `matter_dissector.lua` | Wireshark Lua dissector with AES-CCM decryption |
| `matter_keylog_extract.py` | Extracts session keys from chip-tool logs |
| `matter_decrypt.py` | CLI decryption with log file key parsing |
| `matter_decrypt_simple.py` | Simple CLI decryption |
| `matter_decode_message.py` | TLV message structure decoder |
| `CryptoContext.cpp` | Reference: patched Matter crypto context with key logging |
| `PASESession.cpp` | Reference: PASE session establishment code |
| `linux-arm64-chip-tool-logsesskeys` | Pre-built ARM64 Linux chip-tool with key logging |
