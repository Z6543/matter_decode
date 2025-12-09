# Matter Session Decryption Tools

This directory contains Python scripts to decrypt Matter encrypted session payloads using session keys logged by chip-tool.

## Prerequisites

Install the cryptography library:

```bash
pip3 install cryptography
```

## Scripts

### 1. `matter_decrypt.py` - Full-featured decryption tool

Complete tool with automatic key parsing from log files and header parsing.

**Usage:**

```bash
# Using a log file containing session keys
python3 scripts/matter_decrypt.py \
  --payload <encrypted_hex> \
  --keys session_keys.txt

# Using keys directly
python3 scripts/matter_decrypt.py \
  --payload <encrypted_hex> \
  --i2r 7058e73e8ebb9804ad3c964a3da48f4d \
  --r2i 74d3ff18412ce672a89914c9ff397050

# Auto-detect which key to use
python3 scripts/matter_decrypt.py \
  --payload <encrypted_hex> \
  --keys session_keys.txt \
  --direction auto
```

### 2. `matter_decrypt_simple.py` - Quick decryption

Simplified script for quick testing.

**Usage:**

```bash
# Command line
python3 scripts/matter_decrypt_simple.py \
  <encrypted_hex> \
  <key_hex> \
  [security_flags] \
  [msg_counter] \
  [node_id]

# Example
python3 scripts/matter_decrypt_simple.py \
  'aabbccdd...' \
  '7058e73e8ebb9804ad3c964a3da48f4d' \
  0 \
  1 \
  0
```

## Getting Session Keys

1. Build chip-tool with detail logging enabled:

```bash
./scripts/build/build_examples.py \
  --target darwin-x64-chip-tool-no-ble \
  build -- chip_detail_logging=true
```

2. Run chip-tool and capture the output:

```bash
./out/darwin-x64-chip-tool-no-ble/chip-tool pairing <...> 2>&1 | tee session.log
```

3. Extract the session keys from the log:

```
[SC] Session Keys Derived (Role: Initiator):
[SC] I2R Key (Initiator to Responder):
[SC] 0x70, 0x58, 0xe7, 0x3e, 0x8e, 0xbb, 0x98, 0x04,
[SC] 0xad, 0x3c, 0x96, 0x4a, 0x3d, 0xa4, 0x8f, 0x4d,
[SC] R2I Key (Responder to Initiator):
[SC] 0x74, 0xd3, 0xff, 0x18, 0x41, 0x2c, 0xe6, 0x72,
[SC] 0xa8, 0x99, 0x14, 0xc9, 0xff, 0x39, 0x70, 0x50,
```

## Example Workflow

1. **Capture session establishment:**
   ```bash
   ./out/darwin-x64-chip-tool-no-ble/chip-tool pairing ble-wifi \
     1 MySSID MyPassword 20202021 3840 2>&1 | tee session.log
   ```

2. **Extract keys to a file:**
   ```bash
   grep -A 10 "Session Keys Derived" session.log > keys.txt
   ```

3. **Capture encrypted payload** (from Wireshark, sniffer, etc.)
   - The encrypted payload should include the Matter header and encrypted data with MIC tag

4. **Decrypt the payload:**
   ```bash
   python3 scripts/matter_decrypt.py \
     --payload 00ab12cd34ef... \
     --keys keys.txt \
     --direction auto
   ```

## Understanding the Keys

- **I2R Key (Initiator to Responder)**: Used to encrypt messages sent FROM the session initiator TO the responder
- **R2I Key (Responder to Initiator)**: Used to encrypt messages sent FROM the responder TO the initiator
- **Role**: Determines which key is used for encryption vs decryption
  - If you're the Initiator: use I2R to encrypt outgoing, R2I to decrypt incoming
  - If you're the Responder: use R2I to encrypt outgoing, I2R to decrypt incoming

## Matter Message Format

Typical encrypted Matter message structure:
```
[ Unencrypted Header ] [ Encrypted Payload ] [ 16-byte MIC Tag ]
```

The nonce for AES-CCM is constructed as (13 bytes):
```
[ Security Flags (1) ] [ Message Counter (4, LE) ] [ Node ID (8, LE) ]
```

Note: In test mode (`CHIP_CONFIG_SECURITY_TEST_MODE`), Node ID is set to 0.

## Troubleshooting

**Decryption fails:**
- Verify you're using the correct key (I2R vs R2I) based on message direction
- Check if the message counter and security flags are correct
- Ensure the encrypted payload includes the 16-byte authentication tag
- Verify the Node ID (often 0 in test mode)

**Key parsing fails:**
- Ensure the log file contains the complete key output
- Check that detail logging was enabled when capturing keys

**Import errors:**
- Install cryptography: `pip3 install cryptography`

## Security Warning

⚠️ These tools are for **debugging and testing purposes only**. Session keys should be kept secure and never shared in production environments. Only use these tools on test networks with devices you control.
