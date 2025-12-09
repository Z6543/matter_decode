# Matter Message Decoder - Quick Reference

## Usage

```bash
python3 scripts/matter_decode_message.py <hex_message>
```

## Supported Message Types

The decoder now supports:
- **InvokeCommandRequest** - Send commands to devices (On/Off/Toggle, etc.)
- **ReadRequest** - Read attributes from devices
- **SubscribeRequest** - Subscribe to attribute changes

## Examples

### Example 1: Toggle Light Command

**Input:**
```
152800360115350137002400012401062402021835012400001818181824ff0b18
```

**Output:**
```
✓ THIS IS AN ONOFF TOGGLE COMMAND!
  Target: Endpoint 1
  Cluster: OnOff (0x0006)
  Command: Toggle (0x02)
  Action: Toggle the light on/off state
  Suppress Response: False (controller expects a response)
```

### Example 2: Read VendorName Request

**Input:**
```
153600172402002403282404011818290324ff0c18
```

**Output:**
```
✓ THIS IS A READ REQUEST!
  Reading: VendorName from BasicInformation cluster
  Fabric Filtered: True
  
Attribute Path:
  Endpoint ID: 0
  Cluster ID: 0x0028 (BasicInformation)
  Attribute ID: 0x0001 (VendorName)
```

## Decoded Structure

The message is a TLV (Tag-Length-Value) encoded InvokeCommandRequest:

```
Structure (Anonymous root)
├── Tag=0: SuppressResponse = False
├── Tag=1: InvokeRequests (Array)
│   └── Anonymous Structure
│       └── Tag=1: CommandDataIB (Structure)
│           ├── Tag=0: CommandPath (List)
│           │   ├── Tag=0: EndpointId = 1
│           │   ├── Tag=1: ClusterId = 0x0006 (OnOff)
│           │   └── Tag=2: CommandId = 0x02 (Toggle)
│           └── Tag=1: CommandFields (Structure)
│               └── Tag=0: (empty - no parameters)
└── Tag=255: InteractionModelRevision = 11
```

## Common Matter Commands

### OnOff Cluster (0x0006)
- **Command 0x00**: Off - Turn device off
- **Command 0x01**: On - Turn device on
- **Command 0x02**: Toggle - Toggle device on/off state

### LevelControl Cluster (0x0008)
- **Command 0x00**: MoveToLevel - Move to specific level
- **Command 0x01**: Move - Start moving up/down
- **Command 0x02**: Step - Step up/down by amount
- **Command 0x03**: Stop - Stop level change
- **Command 0x04**: MoveToLevelWithOnOff
- **Command 0x05**: MoveWithOnOff
- **Command 0x06**: StepWithOnOff
- **Command 0x07**: StopWithOnOff

## How to Capture Messages

1. **From chip-tool with logging:**
   ```bash
   ./chip-tool onoff toggle 1 1 --trace-to json:log.json
   ```

2. **From Wireshark/packet capture:**
   - Capture Matter over Thread/WiFi
   - Extract the decrypted payload (after using matter_decrypt.py)
   
3. **From serial logs:**
   - Enable Matter message logging in your device
   - Look for TLV-encoded payloads

## Related Tools

- **matter_decrypt.py** - Decrypt encrypted Matter session payloads
- **matter_decrypt_simple.py** - Simple decryption tool
- **matter_decode_message.py** - This tool, decodes clear text TLV messages
