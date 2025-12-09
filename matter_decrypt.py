#!/usr/bin/env python3
"""
Matter Session Payload Decryption Tool

This script decrypts Matter encrypted session payloads using the I2R and R2I keys
derived from PASE/CASE session establishment.

Usage:
    python3 matter_decrypt.py --payload <hex_payload> --keys <keys_file>
    python3 matter_decrypt.py --payload <hex_payload> --i2r <hex_key> --r2i <hex_key>

Example:
    python3 matter_decrypt.py --payload 001234abcd... --keys session_keys.txt
"""

import argparse
import struct
import re
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend


def parse_hex_bytes(hex_string):
    """
    Parse hex bytes from log format like:
    '0x70, 0x58, 0xe7, 0x3e, 0x8e, 0xbb, 0x98, 0x04,'
    
    Returns bytes object.
    """
    # Remove '0x' prefixes and commas, extract just the hex digits
    hex_clean = re.sub(r'0x|,|\s', '', hex_string)
    return bytes.fromhex(hex_clean)


def parse_keys_from_log(log_text):
    """
    Parse I2R, R2I keys and Attestation Challenge from Matter log output.
    
    Expected format:
    [timestamp] [SC] Session Keys Derived (Role: Initiator):
    [timestamp] [SC] I2R Key (Initiator to Responder):
    [timestamp] [SC] 0x70, 0x58, 0xe7, 0x3e, 0x8e, 0xbb, 0x98, 0x04,
    [timestamp] [SC] 0xad, 0x3c, 0x96, 0x4a, 0x3d, 0xa4, 0x8f, 0x4d,
    [timestamp] [SC] R2I Key (Responder to Initiator):
    [timestamp] [SC] 0x74, 0xd3, 0xff, 0x18, 0x41, 0x2c, 0xe6, 0x72,
    [timestamp] [SC] 0xa8, 0x99, 0x14, 0xc9, 0xff, 0x39, 0x70, 0x50,
    [timestamp] [SC] Attestation Challenge:
    [timestamp] [SC] 0x0c, 0x21, 0x68, 0x39, 0x78, 0xd9, 0x58, 0x54,
    [timestamp] [SC] 0xc8, 0x25, 0x94, 0x33, 0xfb, 0xab, 0x05, 0x77,
    
    Returns dict with 'i2r', 'r2i', 'attestation_challenge', and 'role'
    """
    keys = {
        'i2r': None,
        'r2i': None,
        'attestation_challenge': None,
        'role': None
    }
    
    # Determine role
    if 'Role: Initiator' in log_text:
        keys['role'] = 'initiator'
    elif 'Role: Responder' in log_text:
        keys['role'] = 'responder'
    
    # Extract I2R key
    i2r_match = re.search(r'I2R Key.*?:\s*((?:0x[0-9a-fA-F]{2}[,\s]*)+)', log_text, re.DOTALL)
    if i2r_match:
        # Get the next line(s) with hex bytes after "I2R Key"
        i2r_section = re.search(
            r'I2R Key[^\n]*\n((?:\s*(?:\[[^\]]+\]\s*)?(?:\[[^\]]+\]\s*)?(?:\[SC\]\s*)?0x[0-9a-fA-F]{2}[,\s]*)+)',
            log_text,
            re.MULTILINE
        )
        if i2r_section:
            keys['i2r'] = parse_hex_bytes(i2r_section.group(1))
    
    # Extract R2I key
    r2i_section = re.search(
        r'R2I Key[^\n]*\n((?:\s*(?:\[[^\]]+\]\s*)?(?:\[[^\]]+\]\s*)?(?:\[SC\]\s*)?0x[0-9a-fA-F]{2}[,\s]*)+)',
        log_text,
        re.MULTILINE
    )
    if r2i_section:
        keys['r2i'] = parse_hex_bytes(r2i_section.group(1))
    
    # Extract Attestation Challenge
    att_section = re.search(
        r'Attestation Challenge[^\n]*\n((?:\s*(?:\[[^\]]+\]\s*)?(?:\[[^\]]+\]\s*)?(?:\[SC\]\s*)?0x[0-9a-fA-F]{2}[,\s]*)+)',
        log_text,
        re.MULTILINE
    )
    if att_section:
        keys['attestation_challenge'] = parse_hex_bytes(att_section.group(1))
    
    return keys


def build_nonce(security_flags, message_counter, node_id):
    """
    Build Matter message nonce.
    
    Format (13 bytes):
    - 1 byte: security flags
    - 4 bytes: message counter (little endian)
    - 8 bytes: node ID (little endian)
    """
    nonce = bytearray(13)
    nonce[0] = security_flags
    nonce[1:5] = struct.pack('<I', message_counter)
    nonce[5:13] = struct.pack('<Q', node_id)
    return bytes(nonce)


def parse_matter_header(payload):
    """
    Parse Matter message header to extract fields needed for decryption.
    
    Returns dict with header fields and positions.
    """
    if len(payload) < 8:
        raise ValueError("Payload too short to contain Matter header")
    
    # Simple header parsing - you may need to adjust based on your message format
    # This is a basic implementation
    header = {
        'flags': payload[0],
        'session_id': struct.unpack('<H', payload[1:3])[0],
        'security_flags': payload[3],
        'message_counter': struct.unpack('<I', payload[4:8])[0],
        'header_length': 8,  # Minimum header length
    }
    
    # Check for extended fields based on flags
    # You may need to adjust this based on the actual Matter packet format
    
    return header


def decrypt_matter_payload(encrypted_payload, key, nonce, aad, tag_length=16):
    """
    Decrypt Matter payload using AES-CCM.
    
    Args:
        encrypted_payload: bytes - encrypted payload (without tag)
        key: bytes - 16-byte AES key
        nonce: bytes - 13-byte nonce
        aad: bytes - Additional Authenticated Data (unencrypted header)
        tag_length: int - MIC tag length (default 16 bytes)
    
    Returns:
        bytes - decrypted payload
    """
    if len(key) != 16:
        raise ValueError(f"Key must be 16 bytes, got {len(key)}")
    
    if len(nonce) != 13:
        raise ValueError(f"Nonce must be 13 bytes, got {len(nonce)}")
    
    # Create AES-CCM cipher
    cipher = AESCCM(key, tag_length=tag_length)
    
    # Decrypt (the encrypted payload should include the tag at the end)
    try:
        plaintext = cipher.decrypt(nonce, encrypted_payload, aad)
        return plaintext
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")


def decrypt_matter_message(payload_hex, i2r_key, r2i_key, direction='i2r', node_id=0):
    """
    Decrypt a complete Matter message.
    
    Args:
        payload_hex: str - hex string of the complete encrypted message
        i2r_key: bytes - Initiator to Responder key
        r2i_key: bytes - Responder to Initiator key
        direction: str - 'i2r' or 'r2i' to select which key to use
        node_id: int - Node ID for nonce construction
    
    Returns:
        dict with decrypted data and metadata
    """
    payload = bytes.fromhex(payload_hex.replace(' ', '').replace('0x', ''))
    
    # Parse header
    header = parse_matter_header(payload)
    
    # Select appropriate key based on direction
    key = i2r_key if direction == 'i2r' else r2i_key
    
    # Build nonce
    nonce = build_nonce(
        header['security_flags'],
        header['message_counter'],
        node_id
    )
    
    # Extract AAD (unencrypted header)
    aad = payload[:header['header_length']]
    
    # Extract encrypted payload + tag
    encrypted_with_tag = payload[header['header_length']:]
    
    # Decrypt
    plaintext = decrypt_matter_payload(encrypted_with_tag, key, nonce, aad)
    
    return {
        'header': header,
        'nonce': nonce.hex(),
        'aad': aad.hex(),
        'plaintext': plaintext,
        'plaintext_hex': plaintext.hex(),
        'key_used': 'I2R' if direction == 'i2r' else 'R2I'
    }


def main():
    parser = argparse.ArgumentParser(
        description='Decrypt Matter session payloads',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--payload',
        required=True,
        help='Hex string of encrypted Matter payload'
    )
    
    parser.add_argument(
        '--keys',
        help='File containing session keys in log format'
    )
    
    parser.add_argument(
        '--i2r',
        help='I2R key as hex string (alternative to --keys)'
    )
    
    parser.add_argument(
        '--r2i',
        help='R2I key as hex string (alternative to --keys)'
    )
    
    parser.add_argument(
        '--direction',
        choices=['i2r', 'r2i', 'auto'],
        default='auto',
        help='Message direction (auto tries both)'
    )
    
    parser.add_argument(
        '--node-id',
        type=lambda x: int(x, 0),
        default=0,
        help='Node ID for nonce construction (default: 0 for test mode)'
    )
    
    parser.add_argument(
        '--output',
        choices=['hex', 'ascii', 'both'],
        default='both',
        help='Output format for decrypted payload'
    )
    
    args = parser.parse_args()
    
    # Parse keys
    if args.keys:
        with open(args.keys, 'r') as f:
            log_text = f.read()
        keys = parse_keys_from_log(log_text)
        i2r_key = keys['i2r']
        r2i_key = keys['r2i']
        print(f"Parsed keys from log (Role: {keys['role']})")
        print(f"I2R Key: {i2r_key.hex() if i2r_key else 'NOT FOUND'}")
        print(f"R2I Key: {r2i_key.hex() if r2i_key else 'NOT FOUND'}")
        if keys['attestation_challenge']:
            print(f"Attestation Challenge: {keys['attestation_challenge'].hex()}")
        print()
    elif args.i2r and args.r2i:
        i2r_key = bytes.fromhex(args.i2r.replace(' ', '').replace('0x', ''))
        r2i_key = bytes.fromhex(args.r2i.replace(' ', '').replace('0x', ''))
        print("Using provided keys")
    else:
        parser.error("Either --keys or both --i2r and --r2i must be provided")
    
    if not i2r_key or not r2i_key:
        print("ERROR: Could not parse keys")
        return 1
    
    # Try decryption
    directions = ['i2r', 'r2i'] if args.direction == 'auto' else [args.direction]
    
    for direction in directions:
        try:
            print(f"\n{'='*70}")
            print(f"Attempting decryption with {direction.upper()} key...")
            print(f"{'='*70}")
            
            result = decrypt_matter_message(
                args.payload,
                i2r_key,
                r2i_key,
                direction,
                args.node_id
            )
            
            print(f"✓ Decryption successful using {result['key_used']} key!")
            print(f"\nHeader Information:")
            print(f"  Session ID: 0x{result['header']['session_id']:04x}")
            print(f"  Message Counter: {result['header']['message_counter']}")
            print(f"  Security Flags: 0x{result['header']['security_flags']:02x}")
            print(f"\nNonce: {result['nonce']}")
            print(f"AAD (Header): {result['aad']}")
            
            if args.output in ['hex', 'both']:
                print(f"\nDecrypted Payload (hex):")
                print(f"  {result['plaintext_hex']}")
            
            if args.output in ['ascii', 'both']:
                print(f"\nDecrypted Payload (ASCII/UTF-8 attempt):")
                try:
                    ascii_text = result['plaintext'].decode('utf-8', errors='replace')
                    print(f"  {ascii_text}")
                except:
                    print(f"  (not valid UTF-8)")
            
            if args.output in ['both']:
                print(f"\nDecrypted Payload (bytes):")
                print(f"  {result['plaintext']}")
            
            # If auto mode and successful, don't try other direction
            if args.direction == 'auto':
                break
                
        except Exception as e:
            print(f"✗ Decryption failed with {direction.upper()} key: {e}")
            if args.direction != 'auto':
                return 1
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
