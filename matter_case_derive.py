#!/usr/bin/env python3
"""
Derive Matter CASE session keys from a known ECDH private key.

Parses a pcapng/pcap file, finds CASE Sigma1/2/3 messages, computes
the ECDH shared secret, and derives session keys via the Matter CASE
key schedule. Outputs a keylog file for the Wireshark dissector.

Requires: cryptography (pip install cryptography)

Usage:
    python3 matter_case_derive.py capture.pcapng \
        --ecdh-privkey <32-byte-hex> \
        --ipk <16-byte-hex> \
        [--initiator-node-id 0x1b669] \
        [--responder-node-id 0x6e] \
        [-o matter_keys.log]

The ECDH private key is the P-256 private scalar used by whichever
side (initiator or responder) has been modified to use a fixed key.
The script auto-detects which side by matching the derived public key
against the ephemeral public keys in Sigma1/Sigma2.
"""

import argparse
import hashlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


SE_KEYS_INFO = b"SessionKeys"
SIGMA2_INFO = b"Sigma2"
SIGMA3_INFO = b"Sigma3"
SIGMA2_NONCE = b"NCASE_Sigma2N"
SIGMA3_NONCE = b"NCASE_Sigma3N"
MATTER_PORT = 5540


# ---------------------------------------------------------------------------
# Minimal pcapng parser
# ---------------------------------------------------------------------------
def read_pcapng_packets(path):
    """Yield raw packet bytes from a pcapng file."""
    with open(path, "rb") as f:
        data = f.read()
    pos = 0
    link_type = 1  # default Ethernet
    while pos + 8 <= len(data):
        btype = struct.unpack_from("<I", data, pos)[0]
        blen = struct.unpack_from("<I", data, pos + 4)[0]
        if blen < 12:
            break
        if btype == 0x0A0D0D0A:  # SHB
            pass
        elif btype == 1:  # IDB
            if pos + 16 <= len(data):
                link_type = struct.unpack_from("<H", data, pos + 8)[0]
        elif btype == 6:  # EPB
            if pos + 28 <= len(data):
                cap_len = struct.unpack_from("<I", data, pos + 20)[0]
                pkt_data = data[pos + 28 : pos + 28 + cap_len]
                yield link_type, pkt_data
        padded = (blen + 3) & ~3
        pos += padded
    return


def extract_udp_payloads(path, port=MATTER_PORT):
    """Extract UDP payloads to/from the given port."""
    results = []
    for link_type, pkt in read_pcapng_packets(path):
        try:
            off = 0
            if link_type == 1:  # Ethernet
                ethertype = struct.unpack_from(">H", pkt, 12)[0]
                off = 14
                if ethertype == 0x8100:  # VLAN
                    ethertype = struct.unpack_from(">H", pkt, 16)[0]
                    off = 18
            elif link_type == 113:  # Linux cooked
                ethertype = struct.unpack_from(">H", pkt, 14)[0]
                off = 16
            else:
                continue

            if ethertype == 0x0800:  # IPv4
                ihl = (pkt[off] & 0x0F) * 4
                proto = pkt[off + 9]
                if proto != 17:
                    continue
                off += ihl
            elif ethertype == 0x86DD:  # IPv6
                next_hdr = pkt[off + 6]
                off += 40
                while next_hdr in (0, 43, 44, 60):
                    ext_len = pkt[off + 1]
                    next_hdr = pkt[off]
                    off += (ext_len + 1) * 8
                if next_hdr != 17:
                    continue
            else:
                continue

            src_port = struct.unpack_from(">H", pkt, off)[0]
            dst_port = struct.unpack_from(">H", pkt, off + 2)[0]
            udp_len = struct.unpack_from(">H", pkt, off + 4)[0]
            payload = pkt[off + 8 : off + udp_len]

            if src_port == port or dst_port == port:
                results.append(payload)
        except (IndexError, struct.error):
            continue
    return results


# ---------------------------------------------------------------------------
# Matter message / TLV parsing
# ---------------------------------------------------------------------------
def parse_matter_header(data):
    """Parse Matter message header, return (header_len, fields)."""
    if len(data) < 8:
        return None, None
    flags = data[0]
    dsiz = flags & 0x03
    s_flag = (flags >> 2) & 1
    session_id = struct.unpack_from("<H", data, 1)[0]
    sec_flags = data[3]
    msg_counter = struct.unpack_from("<I", data, 4)[0]
    off = 8
    src_node = None
    if s_flag:
        src_node = struct.unpack_from("<Q", data, off)[0]
        off += 8
    dst_node = None
    if dsiz == 1:
        dst_node = struct.unpack_from("<Q", data, off)[0]
        off += 8
    elif dsiz == 2:
        dst_node = struct.unpack_from("<H", data, off)[0]
        off += 2
    return off, {
        "session_id": session_id,
        "sec_flags": sec_flags,
        "msg_counter": msg_counter,
        "src_node": src_node,
        "dst_node": dst_node,
    }


def parse_protocol_header(data, offset):
    """Parse Matter protocol header, return (next_offset, opcode, proto_id)."""
    if offset + 6 > len(data):
        return None, None, None
    exchange_flags = data[offset]
    opcode = data[offset + 1]
    proto_id = struct.unpack_from("<H", data, offset + 4)[0]
    next_off = offset + 6
    if exchange_flags & 0x10:  # V flag
        proto_id = struct.unpack_from("<H", data, next_off)[0]
        next_off += 2
    if exchange_flags & 0x02:  # A flag
        next_off += 4
    return next_off, opcode, proto_id


def parse_tlv_fields(data):
    """Parse top-level TLV fields, skipping nested containers."""
    fields = {}
    pos = 0
    if pos < len(data) and data[pos] in (0x15, 0x16, 0x17):
        pos += 1
    depth = 0
    while pos < len(data):
        ctrl = data[pos]
        pos += 1
        tag_ctrl = (ctrl >> 5) & 0x07
        elem_type = ctrl & 0x1F

        tag = None
        if tag_ctrl == 1:
            if pos >= len(data):
                break
            tag = data[pos]
            pos += 1
        elif tag_ctrl in (2, 4):
            pos += 2
        elif tag_ctrl in (3, 5):
            pos += 4
        elif tag_ctrl == 6:
            pos += 6
        elif tag_ctrl == 7:
            pos += 8

        if elem_type == 0x18:  # EndOfContainer
            if depth > 0:
                depth -= 1
                continue
            break
        if elem_type in (0x15, 0x16, 0x17):  # Container
            depth += 1
            continue
        if depth > 0:
            # Skip values inside nested containers
            if elem_type in (0x00, 0x04):
                pos += 1
            elif elem_type in (0x01, 0x05):
                pos += 2
            elif elem_type in (0x02, 0x06, 0x0A):
                pos += 4
            elif elem_type in (0x03, 0x07, 0x0B):
                pos += 8
            elif elem_type in (0x08, 0x09, 0x14):
                pass
            elif elem_type in range(0x0C, 0x14):
                if elem_type < 0x10:
                    ls = 1 << (elem_type - 0x0C)
                else:
                    ls = 1 << (elem_type - 0x10)
                if pos + ls > len(data):
                    break
                slen = int.from_bytes(data[pos : pos + ls], "little")
                pos += ls + slen
            continue

        # Top-level field
        if elem_type in (0x10, 0x11, 0x12, 0x13):  # Byte string
            ls = 1 << (elem_type - 0x10)
            if pos + ls > len(data):
                break
            slen = int.from_bytes(data[pos : pos + ls], "little")
            pos += ls
            if pos + slen > len(data):
                break
            if tag is not None:
                fields[tag] = bytes(data[pos : pos + slen])
            pos += slen
        elif elem_type in (0x0C, 0x0D, 0x0E, 0x0F):  # UTF-8 string
            ls = 1 << (elem_type - 0x0C)
            if pos + ls > len(data):
                break
            slen = int.from_bytes(data[pos : pos + ls], "little")
            pos += ls
            if pos + slen > len(data):
                break
            if tag is not None:
                fields[tag] = bytes(data[pos : pos + slen])
            pos += slen
        elif elem_type in (0x04, 0x05, 0x06, 0x07):  # Unsigned int
            vlen = 1 << (elem_type - 0x04)
            if pos + vlen > len(data):
                break
            if tag is not None:
                fields[tag] = int.from_bytes(
                    data[pos : pos + vlen], "little"
                )
            pos += vlen
        elif elem_type in (0x00, 0x01, 0x02, 0x03):  # Signed int
            vlen = 1 << elem_type
            if pos + vlen > len(data):
                break
            if tag is not None:
                fields[tag] = int.from_bytes(
                    data[pos : pos + vlen], "little", signed=True
                )
            pos += vlen
        elif elem_type in (0x08, 0x09):  # Boolean
            if tag is not None:
                fields[tag] = elem_type == 0x09
        elif elem_type == 0x14:  # Null
            if tag is not None:
                fields[tag] = None
        elif elem_type == 0x0A:
            pos += 4
        elif elem_type == 0x0B:
            pos += 8
        else:
            break
    return fields


# ---------------------------------------------------------------------------
# CASE key derivation
# ---------------------------------------------------------------------------
def ecdh_shared_secret(priv_key_bytes, peer_pub_bytes):
    """Compute P-256 ECDH shared secret."""
    priv_int = int.from_bytes(priv_key_bytes, "big")
    priv_key = ec.derive_private_key(priv_int, ec.SECP256R1())
    peer_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_pub_bytes
    )
    return priv_key.exchange(ec.ECDH(), peer_pub)


def hkdf_derive(ikm, salt, info, length):
    """HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_case_keys(
    shared_secret, ipk, sigma1_tlv, sigma2_tlv, sigma3_tlv,
    resp_random, resp_eph_pub
):
    """
    Derive CASE session keys following the Matter specification.

    Returns (i2r_key, r2i_key, attestation_challenge).
    """
    # S2K: for decrypting Sigma2 TBE (optional, for node ID extraction)
    # salt = IPK || responderRandom || responderEphPubKey || SHA256(sigma1)
    h_sigma1 = hashlib.sha256(sigma1_tlv).digest()
    s2k_salt = ipk + resp_random + resp_eph_pub + h_sigma1
    s2k = hkdf_derive(shared_secret, s2k_salt, SIGMA2_INFO, 16)

    # S3K salt = IPK || SHA256(sigma1 || sigma2)
    h_s1s2 = hashlib.sha256(sigma1_tlv + sigma2_tlv).digest()
    s3k_salt = ipk + h_s1s2
    s3k = hkdf_derive(shared_secret, s3k_salt, SIGMA3_INFO, 16)

    # Session keys salt = IPK || SHA256(sigma1 || sigma2 || sigma3)
    h_all = hashlib.sha256(sigma1_tlv + sigma2_tlv + sigma3_tlv).digest()
    sess_salt = ipk + h_all
    key_material = hkdf_derive(shared_secret, sess_salt, SE_KEYS_INFO, 48)

    i2r = key_material[0:16]
    r2i = key_material[16:32]
    att = key_material[32:48]

    return i2r, r2i, att, s2k, s3k


def pub_key_from_private(priv_bytes):
    """Derive the uncompressed P-256 public key from a private key."""
    priv_int = int.from_bytes(priv_bytes, "big")
    priv_key = ec.derive_private_key(priv_int, ec.SECP256R1())
    pub_nums = priv_key.public_key().public_numbers()
    return (
        b"\x04"
        + pub_nums.x.to_bytes(32, "big")
        + pub_nums.y.to_bytes(32, "big")
    )


# ---------------------------------------------------------------------------
# CASE Sigma message finder
# ---------------------------------------------------------------------------
SC_PROTO = 0x0000
SIGMA1_OP = 0x30
SIGMA2_OP = 0x31
SIGMA3_OP = 0x32


def find_sigma_messages(packets):
    """Find CASE Sigma1/2/3 from a list of Matter UDP payloads."""
    sigmas = {}
    for pkt in packets:
        hdr_len, hdr = parse_matter_header(pkt)
        if hdr_len is None:
            continue
        proto_off, opcode, proto_id = parse_protocol_header(pkt, hdr_len)
        if proto_off is None or proto_id != SC_PROTO:
            continue
        if opcode in (SIGMA1_OP, SIGMA2_OP, SIGMA3_OP):
            tlv_payload = pkt[proto_off:]
            sigmas[opcode] = tlv_payload
    return sigmas


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Derive Matter CASE session keys from known ECDH key"
    )
    parser.add_argument("pcap", help="pcapng capture file")
    parser.add_argument(
        "--ecdh-privkey", required=True,
        help="P-256 ECDH private key (32-byte hex)"
    )
    parser.add_argument(
        "--ipk", required=True,
        help="Identity Protection Key (16-byte hex)"
    )
    parser.add_argument(
        "--initiator-node-id", default=None,
        help="Initiator operational node ID (hex or decimal)"
    )
    parser.add_argument(
        "--responder-node-id", default=None,
        help="Responder operational node ID (hex or decimal)"
    )
    parser.add_argument(
        "-o", "--output", default="-",
        help="Output keylog file (default: stdout)"
    )
    args = parser.parse_args()

    priv_key = bytes.fromhex(args.ecdh_privkey)
    ipk = bytes.fromhex(args.ipk)
    if len(priv_key) != 32:
        print("ECDH private key must be 32 bytes", file=sys.stderr)
        return 1
    if len(ipk) != 16:
        print("IPK must be 16 bytes", file=sys.stderr)
        return 1

    # Derive public key from private
    my_pub = pub_key_from_private(priv_key)
    print(f"Derived public key: {my_pub.hex()}", file=sys.stderr)

    # Extract packets
    packets = extract_udp_payloads(args.pcap)
    print(
        f"Found {len(packets)} UDP packets on port {MATTER_PORT}",
        file=sys.stderr,
    )

    # Find Sigma messages
    sigmas = find_sigma_messages(packets)
    for op, name in [
        (SIGMA1_OP, "Sigma1"),
        (SIGMA2_OP, "Sigma2"),
        (SIGMA3_OP, "Sigma3"),
    ]:
        if op in sigmas:
            print(
                f"  {name}: {len(sigmas[op])} bytes", file=sys.stderr
            )
        else:
            print(f"  {name}: NOT FOUND", file=sys.stderr)

    if not all(op in sigmas for op in (SIGMA1_OP, SIGMA2_OP, SIGMA3_OP)):
        print(
            "Could not find all CASE Sigma messages in pcap",
            file=sys.stderr,
        )
        return 1

    # Parse Sigma1/2 TLV for ephemeral public keys
    s1_fields = parse_tlv_fields(sigmas[SIGMA1_OP])
    s2_fields = parse_tlv_fields(sigmas[SIGMA2_OP])

    init_eph_pub = s1_fields.get(4)  # Tag 4 = initiatorEphPubKey
    init_session = s1_fields.get(2)  # Tag 2 = initiatorSessionId
    resp_eph_pub = s2_fields.get(3)  # Tag 3 = responderEphPubKey
    resp_random = s2_fields.get(1)   # Tag 1 = responderRandom
    resp_session = s2_fields.get(2)  # Tag 2 = responderSessionId

    if not init_eph_pub or not resp_eph_pub:
        print("Could not extract ephemeral public keys", file=sys.stderr)
        return 1

    print(f"Initiator session: 0x{init_session:04x}", file=sys.stderr)
    print(f"Responder session: 0x{resp_session:04x}", file=sys.stderr)
    print(
        f"Initiator eph pub: {init_eph_pub.hex()[:20]}...",
        file=sys.stderr,
    )
    print(
        f"Responder eph pub: {resp_eph_pub.hex()[:20]}...",
        file=sys.stderr,
    )

    # Determine which side uses the known key
    if my_pub == init_eph_pub:
        print("Known key matches INITIATOR", file=sys.stderr)
        peer_pub = resp_eph_pub
    elif my_pub == resp_eph_pub:
        print("Known key matches RESPONDER", file=sys.stderr)
        peer_pub = init_eph_pub
    else:
        print(
            "Known ECDH key does not match either ephemeral public key.\n"
            "The provided private key's public key is:\n"
            f"  {my_pub.hex()}\n"
            "Sigma1 initiator pub:\n"
            f"  {init_eph_pub.hex()}\n"
            "Sigma2 responder pub:\n"
            f"  {resp_eph_pub.hex()}",
            file=sys.stderr,
        )
        return 1

    # ECDH
    shared_secret = ecdh_shared_secret(priv_key, peer_pub)
    print(
        f"Shared secret: {shared_secret.hex()[:16]}...", file=sys.stderr
    )

    # Derive keys
    i2r, r2i, att, s2k, s3k = derive_case_keys(
        shared_secret, ipk,
        sigmas[SIGMA1_OP], sigmas[SIGMA2_OP], sigmas[SIGMA3_OP],
        resp_random, resp_eph_pub,
    )
    print(f"I2R key: {i2r.hex()}", file=sys.stderr)
    print(f"R2I key: {r2i.hex()}", file=sys.stderr)
    print(f"Attestation challenge: {att.hex()}", file=sys.stderr)

    # Try to extract node IDs from Sigma2/3 TBE
    init_node = args.initiator_node_id
    resp_node = args.responder_node_id

    if not resp_node:
        # Try decrypting Sigma2 TBE to extract responder NOC
        tbe2 = s2_fields.get(4)
        if tbe2 and len(tbe2) > 16:
            try:
                cipher = AESCCM(s2k, tag_length=16)
                dec = cipher.decrypt(SIGMA2_NONCE, tbe2, b"")
                print(
                    f"Sigma2 TBE decrypted ({len(dec)} bytes)",
                    file=sys.stderr,
                )
            except Exception as e:
                print(
                    f"Sigma2 TBE decryption failed: {e}", file=sys.stderr
                )

    if not init_node:
        s3_fields = parse_tlv_fields(sigmas[SIGMA3_OP])
        tbe3 = s3_fields.get(1)
        if tbe3 and len(tbe3) > 16:
            try:
                cipher = AESCCM(s3k, tag_length=16)
                dec = cipher.decrypt(SIGMA3_NONCE, tbe3, b"")
                print(
                    f"Sigma3 TBE decrypted ({len(dec)} bytes)",
                    file=sys.stderr,
                )
            except Exception as e:
                print(
                    f"Sigma3 TBE decryption failed: {e}", file=sys.stderr
                )

    # Format node IDs
    def fmt_node(val):
        if val is None:
            return "0"
        if isinstance(val, str):
            if val.startswith("0x"):
                return val
            return val
        return f"0x{val:x}"

    init_node_str = fmt_node(init_node)
    resp_node_str = fmt_node(resp_node)

    # Output keylog
    output_lines = [
        "# Matter Session Key Log",
        "# Derived from CASE ECDH key by matter_case_derive.py",
        "#",
        "# Format: SESSION_ID  I2R_KEY  R2I_KEY  "
        "I2R_SRC_NODE  R2I_SRC_NODE",
        "#",
        f"# Initiator session: 0x{init_session:04x}, "
        f"Responder session: 0x{resp_session:04x}",
        f"# Attestation challenge: {att.hex()}",
        f"*  {i2r.hex()}  {r2i.hex()}"
        f"  {init_node_str}  {resp_node_str}",
        "",
    ]
    output = "\n".join(output_lines) + "\n"

    if args.output == "-":
        sys.stdout.write(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Written to {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
