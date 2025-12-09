#!/usr/bin/env python3
"""
Simple Matter Message Decryption Tool

This is a simplified version for quick decryption of Matter messages.
Just paste your keys and payload directly into this script or provide as arguments.
"""

import sys
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def parse_key_from_log(log_lines):
    """Extract hex bytes from log format like '0x70, 0x58, 0xe7, ...'"""
    key_bytes = []
    for line in log_lines:
        # Find all 0xNN patterns
        import re
        hex_values = re.findall(r'0x([0-9a-fA-F]{2})', line)
        key_bytes.extend([int(h, 16) for h in hex_values])
    return bytes(key_bytes)


def decrypt_simple(encrypted_hex, key_hex, security_flags=0x00, msg_counter=0, node_id=0):
    """
    Simple decryption assuming standard Matter AES-CCM with 13-byte nonce.
    
    Args:
        encrypted_hex: Full encrypted message as hex string
        key_hex: 16-byte key as hex string
        security_flags: Security flags byte (default 0x00)
        msg_counter: Message counter (default 0)
        node_id: Node ID (default 0 for test mode)
    """
    # Parse inputs
    encrypted = bytes.fromhex(encrypted_hex.replace(' ', '').replace('0x', ''))
    key = bytes.fromhex(key_hex.replace(' ', '').replace('0x', ''))
    
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    
    # Build 13-byte nonce: [sec_flags(1)] [msg_counter(4)] [node_id(8)]
    nonce = bytearray(13)
    nonce[0] = security_flags
    nonce[1:5] = struct.pack('<I', msg_counter)  # Little endian uint32
    nonce[5:13] = struct.pack('<Q', node_id)     # Little endian uint64
    
    print(f"Key: {key.hex()}")
    print(f"Nonce: {bytes(nonce).hex()}")
    print(f"Encrypted (with tag): {encrypted.hex()}")
    
    # Decrypt with AES-CCM (tag is appended at the end of encrypted data)
    cipher = AESCCM(key, tag_length=16)
    
    # For Matter, AAD is typically the unencrypted header
    # You may need to adjust this based on your specific message format
    aad = b''  # Empty AAD for simple case
    
    try:
        plaintext = cipher.decrypt(bytes(nonce), encrypted, aad)
        print(f"\n✓ Decryption successful!")
        print(f"Plaintext (hex): {plaintext.hex()}")
        print(f"Plaintext (raw): {plaintext}")
        try:
            print(f"Plaintext (ASCII): {plaintext.decode('ascii', errors='replace')}")
        except:
            pass
        return plaintext
    except Exception as e:
        print(f"\n✗ Decryption failed: {e}")
        print("\nTips:")
        print("- Check if you're using the correct key (I2R vs R2I)")
        print("- Verify security flags, message counter, and node ID")
        print("- Ensure the encrypted payload includes the 16-byte tag")
        return None


def example_usage():
    """Example showing how to use this script"""
    
    print("="*70)
    print("EXAMPLE: Decrypt with keys from your log")
    print("="*70)
    
    # Example keys from your log format
    i2r_log = """
    [SC] 0x70, 0x58, 0xe7, 0x3e, 0x8e, 0xbb, 0x98, 0x04, 
    [SC] 0xad, 0x3c, 0x96, 0x4a, 0x3d, 0xa4, 0x8f, 0x4d,
    """
    
    r2i_log = """
    [SC] 0x74, 0xd3, 0xff, 0x18, 0x41, 0x2c, 0xe6, 0x72, 
    [SC] 0xa8, 0x99, 0x14, 0xc9, 0xff, 0x39, 0x70, 0x50,
    """
    
    i2r_key = parse_key_from_log(i2r_log.split('\n'))
    r2i_key = parse_key_from_log(r2i_log.split('\n'))
    
    print(f"Parsed I2R Key: {i2r_key.hex()}")
    print(f"Parsed R2I Key: {r2i_key.hex()}")
    print()
    
    # Example encrypted payload (replace with your actual encrypted data)
    encrypted_payload = "PASTE_YOUR_ENCRYPTED_HEX_HERE"
    
    print("Replace 'PASTE_YOUR_ENCRYPTED_HEX_HERE' with your actual encrypted payload")
    print("\nTo decrypt, call:")
    print("  decrypt_simple(encrypted_payload, i2r_key.hex(), security_flags=0x00, msg_counter=1, node_id=0)")


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Command line usage
        if len(sys.argv) < 3:
            print("Usage: python3 matter_decrypt_simple.py <encrypted_hex> <key_hex> [security_flags] [msg_counter] [node_id]")
            print("Example: python3 matter_decrypt_simple.py 'aabbccdd...' '7058e73e8ebb9804ad3c964a3da48f4d' 0 1 0")
            sys.exit(1)
        
        encrypted = sys.argv[1]
        key = sys.argv[2]
        sec_flags = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x00
        msg_ctr = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        node = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0
        
        decrypt_simple(encrypted, key, sec_flags, msg_ctr, node)
    else:
        # Interactive usage - show example
        example_usage()
