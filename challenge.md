# 🕵️ CTF Challenge: Operation SILVERTHREAD
**Category:** IoT / Wireless Protocol Analysis
**Difficulty:** ⚡⚡⚡ Intermediate
**Format:** `FLAG{device-name}`

---

## Briefing

> *Rain hammers the neon-slicked streets of New Meridian. Somewhere in this city, a rogue mesh network hums beneath the noise — whispering secrets in encrypted packets no one was supposed to hear.*

You're a freelance packet jockey working a contract for **VEIL Corp**, a shadow-market intelligence outfit operating out of a server room above a noodle bar on 7th and Cross.

Their field operative — codename **MOTH** — planted a wireless sniffer inside a target's smart-home node before going dark. The sniffer captured a full Thread + Matter session before MOTH vanished.

The target is known to run consumer IoT gear configured with **default test keys**. VEIL Corp's analysts believe the target's primary Matter controller device is broadcasting its identity over the mesh. If you can extract that device name, VEIL Corp will know exactly which node to burn.

**MOTH's last transmission:**
> *"Keys were never rotated. They're running the test creds. The mesh is an open book — if you know how to read it."*

You receive one file. One chance.

**Find the device name hidden in the traffic. That's your flag.**

---

## Files

| File | Description |
|---|---|
| `operation_silverthread.pcapng` | Wireless packet capture of Thread + Matter session |

---

## Hints

<details>
<summary>💡 Hint 1 — Dead Drop Alpha</summary>

> Thread networks use a **Master Key** for network-level encryption. In test environments, this key is often the well-known default.  
> Wireshark knows how to use it — check your IEEE 802.15.4 / Thread decryption settings.

</details>

<details>
<summary>💡 Hint 2 — Dead Drop Beta</summary>

> Once Thread is decrypted, look for **Matter (CHIP)** traffic riding on top. Matter uses CASE/PASE sessions — but commissioning traffic may contain device descriptors in plaintext or under test credentials.  
> The **Basic Information Cluster** is where a device introduces itself.

</details>

<details>
<summary>💡 Hint 3 — Dead Drop Gamma</summary>

> Filter for **Matter Attribute Reports** or **Read Responses** on Cluster `0x0028` (Basic Information).  
> Attribute `0x0005` is `NodeLabel` — the human-readable device name.

</details>

---

## Technical Background

### Thread — The Mesh Beneath
Thread is an IPv6-based low-power mesh networking protocol built on IEEE 802.15.4. All Thread traffic is encrypted using a **Network Master Key** — a 128-bit AES key shared across the mesh. In production, this key is unique and secret. In test/development environments, a well-known default key is commonly used:

```
00112233445566778899aabbccddeeff
```

To decrypt Thread traffic in Wireshark:
`Edit → Preferences → Protocols → IEEE 802.15.4 → Decryption Keys`

When adding the key, set **Key hash** to **Thread hash**. Raw IEEE 802.15.4 uses the master key directly for AES-CCM encryption, but Thread does not — it derives separate MAC and MLE keys from the master key using a key derivation function (specifically, HMAC-based). Selecting "Thread hash" tells Wireshark to run the Thread KDF on the master key before attempting decryption. Using the wrong hash setting (e.g., "No hash" or "ZigBee hash") will silently fail to decrypt any frames.

#### Static Addresses (Short ↔ Extended Address Mapping)

IEEE 802.15.4 devices use both a short address (2 bytes, assigned by the network coordinator) and an extended address (EUI-64, burned into hardware). Thread encrypts frames using keys derived from the extended address, but devices typically communicate using their short address to save airtime. Wireshark needs the mapping between the two to correctly decrypt frames — without it, it sees the short address in the frame header but can't look up the extended address needed for the decryption nonce.

Configure at: `Edit → Preferences → Protocols → IEEE 802.15.4 → Static Addresses`

| Short Address | PAN ID | Extended Address |
|---|---|---|
| `f800` | `1234` | `1e4bd8f66d8d8702` |
| `4800` | `1234` | `8a6f43c9ec56be66` |

### Matter — The Protocol Above
Matter (formerly Project CHIP) runs over Thread (among other transports). It handles device commissioning, control, and attribute reporting. The **Basic Information Cluster (`0x0028`)** contains device metadata including:

| Attribute ID | Name |
|---|---|
| `0x0000` | DataModelRevision |
| `0x0001` | VendorName |
| `0x0002` | VendorID |
| `0x0004` | ProductName |
| `0x0005` | **NodeLabel** ← *your target* |
| `0x000F` | SerialNumber |


---

## Flag

`FLAG{SILVERTHREAD-01}`

---

*VEIL Corp thanks you for your service. Payment in crypto. No receipts.*
*— The Handler*
