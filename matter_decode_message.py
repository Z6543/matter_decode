#!/usr/bin/env python3
"""
Matter Message Decoder

Decodes clear text Matter messages (TLV-encoded payloads) to show the structure
and content of commands, attributes, and data.

Usage:
    python3 matter_decode_message.py <hex_message>
    python3 matter_decode_message.py 152800360115350137002400012401062402021835012400001818181824ff0b18
"""

import sys
import struct


class TLVElement:
    """Represents a TLV element"""
    def __init__(self, tag_control, tag, value_type, value, raw_bytes):
        self.tag_control = tag_control
        self.tag = tag
        self.value_type = value_type
        self.value = value
        self.raw_bytes = raw_bytes
    
    def __repr__(self):
        tag_str = f"Tag={self.tag}" if self.tag is not None else "Anonymous"
        return f"TLV({tag_str}, Type={self.value_type}, Value={self.value})"


class MatterTLVDecoder:
    """
    Decoder for Matter TLV (Tag-Length-Value) format.
    Based on Matter specification section 7.18 (TLV Format)
    """
    
    # Element Types
    ELEMENT_TYPES = {
        0x00: "Signed Integer (1-byte)",
        0x01: "Signed Integer (2-byte)",
        0x02: "Signed Integer (4-byte)",
        0x03: "Signed Integer (8-byte)",
        0x04: "Unsigned Integer (1-byte)",
        0x05: "Unsigned Integer (2-byte)",
        0x06: "Unsigned Integer (4-byte)",
        0x07: "Unsigned Integer (8-byte)",
        0x08: "Boolean False",
        0x09: "Boolean True",
        0x0A: "Floating Point (4-byte)",
        0x0B: "Floating Point (8-byte)",
        0x0C: "UTF-8 String (1-byte length)",
        0x0D: "UTF-8 String (2-byte length)",
        0x0E: "UTF-8 String (4-byte length)",
        0x0F: "UTF-8 String (8-byte length)",
        0x10: "Byte String (1-byte length)",
        0x11: "Byte String (2-byte length)",
        0x12: "Byte String (4-byte length)",
        0x13: "Byte String (8-byte length)",
        0x14: "Null",
        0x15: "Structure",
        0x16: "Array",
        0x17: "List",
        0x18: "End of Container",
    }
    
    # Tag Control values
    TAG_CONTROL = {
        0: "Anonymous",
        1: "Context-specific (1-byte)",
        2: "Common Profile (2-byte)",
        3: "Common Profile (4-byte)",
        4: "Implicit Profile (2-byte)",
        5: "Implicit Profile (4-byte)",
        6: "Fully-qualified (6-byte)",
        7: "Fully-qualified (8-byte)",
    }
    
    def __init__(self, data):
        if isinstance(data, str):
            data = bytes.fromhex(data.replace(' ', '').replace('0x', ''))
        self.data = data
        self.pos = 0
        self.indent_level = 0
    
    def read_bytes(self, count):
        """Read bytes from current position"""
        if self.pos + count > len(self.data):
            raise ValueError(f"Not enough data: need {count} bytes at position {self.pos}")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result
    
    def read_uint(self, size):
        """Read unsigned integer (little-endian)"""
        data = self.read_bytes(size)
        if size == 1:
            return struct.unpack('<B', data)[0]
        elif size == 2:
            return struct.unpack('<H', data)[0]
        elif size == 4:
            return struct.unpack('<I', data)[0]
        elif size == 8:
            return struct.unpack('<Q', data)[0]
    
    def read_int(self, size):
        """Read signed integer (little-endian)"""
        data = self.read_bytes(size)
        if size == 1:
            return struct.unpack('<b', data)[0]
        elif size == 2:
            return struct.unpack('<h', data)[0]
        elif size == 4:
            return struct.unpack('<i', data)[0]
        elif size == 8:
            return struct.unpack('<q', data)[0]
    
    def decode_control_byte(self, control):
        """Decode control byte into tag control and element type"""
        tag_control = (control >> 5) & 0x07
        element_type = control & 0x1F
        return tag_control, element_type
    
    def read_tag(self, tag_control):
        """Read tag based on tag control value"""
        if tag_control == 0:  # Anonymous
            return None
        elif tag_control == 1:  # Context-specific (1-byte)
            return self.read_uint(1)
        elif tag_control == 2:  # Common Profile (2-byte)
            return self.read_uint(2)
        elif tag_control == 3:  # Common Profile (4-byte)
            return self.read_uint(4)
        elif tag_control == 4:  # Implicit Profile (2-byte)
            return self.read_uint(2)
        elif tag_control == 5:  # Implicit Profile (4-byte)
            return self.read_uint(4)
        elif tag_control == 6:  # Fully-qualified (6-byte)
            vendor_id = self.read_uint(2)
            profile_num = self.read_uint(2)
            tag_num = self.read_uint(2)
            return (vendor_id, profile_num, tag_num)
        elif tag_control == 7:  # Fully-qualified (8-byte)
            vendor_id = self.read_uint(2)
            profile_num = self.read_uint(2)
            tag_num = self.read_uint(4)
            return (vendor_id, profile_num, tag_num)
    
    def read_element_value(self, element_type):
        """Read the value based on element type"""
        if element_type == 0x00:  # Signed int 1-byte
            return self.read_int(1)
        elif element_type == 0x01:  # Signed int 2-byte
            return self.read_int(2)
        elif element_type == 0x02:  # Signed int 4-byte
            return self.read_int(4)
        elif element_type == 0x03:  # Signed int 8-byte
            return self.read_int(8)
        elif element_type == 0x04:  # Unsigned int 1-byte
            return self.read_uint(1)
        elif element_type == 0x05:  # Unsigned int 2-byte
            return self.read_uint(2)
        elif element_type == 0x06:  # Unsigned int 4-byte
            return self.read_uint(4)
        elif element_type == 0x07:  # Unsigned int 8-byte
            return self.read_uint(8)
        elif element_type == 0x08:  # Boolean false
            return False
        elif element_type == 0x09:  # Boolean true
            return True
        elif element_type == 0x0A:  # Float 4-byte
            data = self.read_bytes(4)
            return struct.unpack('<f', data)[0]
        elif element_type == 0x0B:  # Float 8-byte
            data = self.read_bytes(8)
            return struct.unpack('<d', data)[0]
        elif element_type in [0x0C, 0x0D, 0x0E, 0x0F]:  # UTF-8 String
            length_size = 1 << (element_type - 0x0C)
            length = self.read_uint(length_size)
            return self.read_bytes(length).decode('utf-8')
        elif element_type in [0x10, 0x11, 0x12, 0x13]:  # Byte String
            length_size = 1 << (element_type - 0x10)
            length = self.read_uint(length_size)
            return self.read_bytes(length)
        elif element_type == 0x14:  # Null
            return None
        elif element_type in [0x15, 0x16, 0x17]:  # Structure/Array/List
            return "Container Start"
        elif element_type == 0x18:  # End of Container
            return "Container End"
        else:
            raise ValueError(f"Unknown element type: 0x{element_type:02x}")
    
    def decode_element(self):
        """Decode a single TLV element"""
        start_pos = self.pos
        control = self.read_uint(1)
        tag_control, element_type = self.decode_control_byte(control)
        
        tag = self.read_tag(tag_control)
        value = self.read_element_value(element_type)
        
        end_pos = self.pos
        raw_bytes = self.data[start_pos:end_pos]
        
        return TLVElement(tag_control, tag, element_type, value, raw_bytes)
    
    def decode_all(self, verbose=True):
        """Decode all elements in the message"""
        elements = []
        
        while self.pos < len(self.data):
            element = self.decode_element()
            elements.append(element)
            
            if verbose:
                self.print_element(element)
        
        return elements
    
    def print_element(self, element):
        """Pretty print a TLV element"""
        indent = "  " * self.indent_level
        
        # Get element type name
        type_name = self.ELEMENT_TYPES.get(element.value_type, f"Unknown(0x{element.value_type:02x})")
        
        # Get tag info
        tag_str = ""
        if element.tag is not None:
            if isinstance(element.tag, tuple):
                tag_str = f"Tag=(Vendor:{element.tag[0]}, Profile:{element.tag[1]}, Tag:{element.tag[2]})"
            else:
                tag_str = f"Tag={element.tag}"
        else:
            tag_str = "Anonymous"
        
        # Handle container types
        if element.value_type == 0x15:  # Structure
            print(f"{indent}[Structure] {tag_str}")
            self.indent_level += 1
        elif element.value_type == 0x16:  # Array
            print(f"{indent}[Array] {tag_str}")
            self.indent_level += 1
        elif element.value_type == 0x17:  # List
            print(f"{indent}[List] {tag_str}")
            self.indent_level += 1
        elif element.value_type == 0x18:  # End of Container
            self.indent_level = max(0, self.indent_level - 1)
            indent = "  " * self.indent_level
            print(f"{indent}[End of Container]")
        else:
            # Regular value
            value_str = element.value
            if isinstance(element.value, bytes):
                value_str = element.value.hex()
            
            print(f"{indent}{tag_str}: {type_name} = {value_str}")
            print(f"{indent}  Raw bytes: {element.raw_bytes.hex()}")


def interpret_matter_command(elements):
    """
    Interpret TLV elements as a Matter command/request.
    This provides semantic meaning to common Matter command structures.
    """
    print("\n" + "="*70)
    print("MATTER MESSAGE INTERPRETATION")
    print("="*70)
    
    # Common cluster IDs
    CLUSTER_IDS = {
        0x0003: "Identify",
        0x0004: "Groups",
        0x0005: "Scenes",
        0x0006: "OnOff",
        0x0008: "LevelControl",
        0x001D: "Descriptor",
        0x0028: "BasicInformation",
        0x0029: "OtaSoftwareUpdateRequestor",
        0x002A: "LocalizationConfiguration",
        0x0030: "GeneralCommissioning",
        0x0031: "NetworkCommissioning",
        0x0032: "DiagnosticLogs",
        0x0033: "GeneralDiagnostics",
        0x003C: "AdministratorCommissioning",
        0x003E: "OperationalCredentials",
        0x003F: "GroupKeyManagement",
    }
    
    # Common attribute IDs for BasicInformation cluster (0x0028)
    BASIC_INFO_ATTRIBUTES = {
        0x0000: "DataModelRevision",
        0x0001: "VendorName",
        0x0002: "VendorID",
        0x0003: "ProductName",
        0x0004: "ProductID",
        0x0005: "NodeLabel",
        0x0006: "Location",
        0x0007: "HardwareVersion",
        0x0008: "HardwareVersionString",
        0x0009: "SoftwareVersion",
        0x000A: "SoftwareVersionString",
        0x000B: "ManufacturingDate",
        0x000C: "PartNumber",
        0x000D: "ProductURL",
        0x000E: "ProductLabel",
        0x000F: "SerialNumber",
        0x0010: "LocalConfigDisabled",
        0x0011: "Reachable",
        0x0012: "UniqueID",
        0xFFF8: "GeneratedCommandList",
        0xFFF9: "AcceptedCommandList",
        0xFFFA: "EventList",
        0xFFFB: "AttributeList",
        0xFFFC: "FeatureMap",
        0xFFFD: "ClusterRevision",
    }
    
    # OnOff cluster attributes
    ONOFF_ATTRIBUTES = {
        0x0000: "OnOff",
        0x4000: "GlobalSceneControl",
        0x4001: "OnTime",
        0x4002: "OffWaitTime",
        0x4003: "StartUpOnOff",
        0xFFFD: "ClusterRevision",
    }
    
    # OnOff cluster commands
    ONOFF_COMMANDS = {
        0x00: "Off",
        0x01: "On",
        0x02: "Toggle",
    }
    
    # Determine message type by examining structure
    message_type = None
    has_suppress_response = False
    has_invoke_requests = False
    has_attribute_requests = False
    has_attribute_reports = False
    has_fabric_filtered = False
    has_more_chunked = False
    
    # First pass: determine message type
    for i, elem in enumerate(elements):
        if elem.tag == 0 and elem.value_type in [0x08, 0x09] and i < 3:
            has_suppress_response = True
        if elem.tag == 1 and elem.value_type == 0x16:  # Array at tag 1
            # Could be InvokeRequests or AttributeReportIBs
            # Check what's inside to distinguish
            if i + 1 < len(elements):
                # Look ahead to see if there's a data version (Tag=0) which indicates a report
                for j in range(i + 1, min(i + 10, len(elements))):
                    if elements[j].tag == 0 and elements[j].value_type in [0x06, 0x07]:  # Data version
                        has_attribute_reports = True
                        break
                    if elements[j].tag == 0 and elements[j].value_type == 0x17:  # CommandPath List
                        has_invoke_requests = True
                        break
        if elem.tag == 0 and elem.value_type == 0x16:  # Array at tag 0
            has_attribute_requests = True
        if elem.tag == 3 and elem.value_type in [0x08, 0x09]:
            has_fabric_filtered = True
        if elem.tag == 4 and elem.value_type in [0x08, 0x09]:
            has_more_chunked = True
    
    if has_invoke_requests:
        message_type = "InvokeCommandRequest"
    elif has_attribute_reports:
        message_type = "ReadResponse"
    elif has_attribute_requests and has_fabric_filtered:
        message_type = "ReadRequest"
    elif has_attribute_requests:
        message_type = "SubscribeRequest"
    
    print(f"\nMessage Type: {message_type if message_type else 'Unknown'}")
    
    # Parse based on message type
    if message_type == "ReadRequest" or message_type == "SubscribeRequest":
        # Parse Read/Subscribe Request
        endpoint_id = None
        cluster_id = None
        attribute_id = None
        fabric_filtered = None
        im_revision = None
        
        for i, elem in enumerate(elements):
            # Tag=2 = EndpointId, Tag=3 = ClusterId, Tag=4 = AttributeId within AttributePathIB
            if elem.tag == 2 and elem.value_type in [0x04, 0x05, 0x06]:
                endpoint_id = elem.value
            elif elem.tag == 3 and elem.value_type in [0x04, 0x05, 0x06]:
                # Could be cluster or fabric_filtered boolean
                if i > 0 and elements[i-1].tag in [2, 4]:  # If preceded by endpoint or attribute
                    cluster_id = elem.value
            elif elem.tag == 4 and elem.value_type in [0x04, 0x05, 0x06]:
                attribute_id = elem.value
            elif elem.tag == 3 and elem.value_type in [0x08, 0x09]:
                fabric_filtered = elem.value
            elif elem.tag == 0xFF:
                im_revision = elem.value
        
        # Print findings
        if fabric_filtered is not None:
            print(f"\n--- Fabric Filtered: {fabric_filtered} ---")
        
        if im_revision is not None:
            print(f"--- Interaction Model Revision: {im_revision} ---")
        
        if endpoint_id is not None or cluster_id is not None or attribute_id is not None:
            print("\n--- Attribute Path ---")
            
            if endpoint_id is not None:
                print(f"  Endpoint ID: {endpoint_id}")
            
            if cluster_id is not None:
                cluster_name = CLUSTER_IDS.get(cluster_id, "Unknown")
                print(f"  Cluster ID: 0x{cluster_id:04x} ({cluster_name})")
            
            if attribute_id is not None:
                # Try to get attribute name based on cluster
                attr_name = "Unknown"
                if cluster_id == 0x0028:
                    attr_name = BASIC_INFO_ATTRIBUTES.get(attribute_id, "Unknown")
                elif cluster_id == 0x0006:
                    attr_name = ONOFF_ATTRIBUTES.get(attribute_id, "Unknown")
                print(f"  Attribute ID: 0x{attribute_id:04x} ({attr_name})")
            
            # Interpret the request
            if message_type == "ReadRequest":
                print("\n" + "="*70)
                print("✓ THIS IS A READ REQUEST!")
                print("="*70)
                if cluster_id == 0x0028 and attribute_id == 1:
                    print("  Reading: VendorName from BasicInformation cluster")
                elif cluster_id and attribute_id is not None:
                    cluster_name = CLUSTER_IDS.get(cluster_id, f"0x{cluster_id:04x}")
                    print(f"  Reading: Attribute 0x{attribute_id:04x} from {cluster_name} cluster")
                    if endpoint_id is not None:
                        print(f"  Target: Endpoint {endpoint_id}")
                print(f"  Fabric Filtered: {fabric_filtered}")
    
    elif message_type == "ReadResponse":
        # Parse Read Response
        endpoint_id = None
        cluster_id = None
        attribute_id = None
        data_version = None
        attribute_value = None
        more_chunked = None
        im_revision = None
        
        for i, elem in enumerate(elements):
            # Tag=0 at structure level is often DataVersion
            if elem.tag == 0 and elem.value_type in [0x06, 0x07]:  # uint32 or uint64
                data_version = elem.value
            # Tag=2,3,4 within AttributePathIB
            elif elem.tag == 2 and elem.value_type in [0x04, 0x05, 0x06]:
                endpoint_id = elem.value
            elif elem.tag == 3 and elem.value_type in [0x04, 0x05, 0x06]:
                cluster_id = elem.value
            elif elem.tag == 4 and elem.value_type in [0x04, 0x05, 0x06]:
                attribute_id = elem.value
            # Tag=2 at higher level could be the actual data value
            elif elem.tag == 2 and elem.value_type not in [0x04, 0x05, 0x06, 0x15, 0x16, 0x17]:
                attribute_value = elem.value
            elif elem.tag == 4 and elem.value_type in [0x08, 0x09]:
                more_chunked = elem.value
            elif elem.tag == 0xFF:
                im_revision = elem.value
        
        # Print findings
        if more_chunked is not None:
            print(f"\n--- More Chunked Messages: {more_chunked} ---")
        
        if im_revision is not None:
            print(f"--- Interaction Model Revision: {im_revision} ---")
        
        if data_version is not None:
            print(f"\n--- Data Version: {data_version} ---")
        
        if endpoint_id is not None or cluster_id is not None or attribute_id is not None:
            print("\n--- Attribute Path ---")
            
            if endpoint_id is not None:
                print(f"  Endpoint ID: {endpoint_id}")
            
            if cluster_id is not None:
                cluster_name = CLUSTER_IDS.get(cluster_id, "Unknown")
                print(f"  Cluster ID: 0x{cluster_id:04x} ({cluster_name})")
            
            if attribute_id is not None:
                # Try to get attribute name based on cluster
                attr_name = "Unknown"
                if cluster_id == 0x0028:
                    attr_name = BASIC_INFO_ATTRIBUTES.get(attribute_id, "Unknown")
                elif cluster_id == 0x0006:
                    attr_name = ONOFF_ATTRIBUTES.get(attribute_id, "Unknown")
                print(f"  Attribute ID: 0x{attribute_id:04x} ({attr_name})")
        
        if attribute_value is not None:
            print("\n--- Attribute Value ---")
            if isinstance(attribute_value, bytes):
                try:
                    decoded = attribute_value.decode('utf-8')
                    print(f"  Value (string): \"{decoded}\"")
                except:
                    print(f"  Value (bytes): {attribute_value.hex()}")
            else:
                print(f"  Value: {attribute_value}")
        
        # Interpret the response
        print("\n" + "="*70)
        print("✓ THIS IS A READ RESPONSE!")
        print("="*70)
        if cluster_id == 0x0028 and attribute_id == 0x0003:
            print(f"  Attribute: ProductName from BasicInformation cluster")
            if attribute_value:
                print(f"  Value: \"{attribute_value}\"")
        elif cluster_id == 0x0028 and attribute_id == 0x0001:
            print(f"  Attribute: VendorName from BasicInformation cluster")
            if attribute_value:
                print(f"  Value: \"{attribute_value}\"")
        elif cluster_id and attribute_id is not None:
            cluster_name = CLUSTER_IDS.get(cluster_id, f"0x{cluster_id:04x}")
            attr_name = "Unknown"
            if cluster_id == 0x0028:
                attr_name = BASIC_INFO_ATTRIBUTES.get(attribute_id, f"0x{attribute_id:04x}")
            elif cluster_id == 0x0006:
                attr_name = ONOFF_ATTRIBUTES.get(attribute_id, f"0x{attribute_id:04x}")
            print(f"  Cluster: {cluster_name}")
            print(f"  Attribute: {attr_name}")
            if attribute_value is not None:
                print(f"  Value: {attribute_value}")
    
    elif message_type == "InvokeCommandRequest":
        # Original InvokeCommand parsing
        endpoint_id = None
        cluster_id = None
        command_id = None
        suppress_response = None
        
        # Parse through all elements looking for specific tags
        for i, elem in enumerate(elements):
            # Tag=0 at root level is SuppressResponse
            if elem.tag == 0 and elem.value_type in [0x08, 0x09] and i < 5:
                suppress_response = elem.value
            
            # Tag=0,1,2 with unsigned int values inside nested structures are endpoint/cluster/command
            if elem.tag == 0 and elem.value_type in [0x04, 0x05, 0x06]:
                # Check context - if we're after a List element, this is likely endpoint
                if i > 0 and elements[i-1].value_type == 0x17:  # After a List start
                    endpoint_id = elem.value
            elif elem.tag == 1 and elem.value_type in [0x04, 0x05, 0x06]:
                # Likely cluster ID
                if endpoint_id is not None and cluster_id is None:
                    cluster_id = elem.value
            elif elem.tag == 2 and elem.value_type in [0x04, 0x05, 0x06]:
                # Likely command ID
                if cluster_id is not None and command_id is None:
                    command_id = elem.value
            
            # Tag=255 is typically InteractionModelRevision
            if elem.tag == 0xFF:
                im_revision = elem.value
        
        # Print findings
        if suppress_response is not None:
            print(f"\n--- Suppress Response: {suppress_response} ---")
        
        if endpoint_id is not None:
            print("\n--- Command Path ---")
            print(f"  Endpoint ID: {endpoint_id}")
        
        if cluster_id is not None:
            cluster_name = CLUSTER_IDS.get(cluster_id, "Unknown")
            print(f"  Cluster ID: 0x{cluster_id:04x} ({cluster_name})")
        
        if command_id is not None:
            if cluster_id == 0x0006:  # OnOff cluster
                command_name = ONOFF_COMMANDS.get(command_id, "Unknown")
                print(f"  Command ID: 0x{command_id:02x} ({command_name})")
            else:
                print(f"  Command ID: 0x{command_id:02x}")
        
        print("\n--- Command Fields ---")
        print("  (Empty structure - Toggle command has no parameters)")
        
        # Interpret the command
        if cluster_id == 0x0006 and command_id == 0x02:
            print("\n" + "="*70)
            print("✓ THIS IS AN ONOFF TOGGLE COMMAND!")
            print("="*70)
            print(f"  Target: Endpoint {endpoint_id}")
            print(f"  Cluster: OnOff (0x0006)")
            print(f"  Command: Toggle (0x02)")
            print(f"  Action: Toggle the light on/off state")
            print(f"  Suppress Response: {suppress_response} (controller expects a response)")
        elif cluster_id == 0x0006 and command_id == 0x01:
            print("\n" + "="*70)
            print("✓ THIS IS AN ONOFF ON COMMAND!")
            print("="*70)
            print(f"  Target: Endpoint {endpoint_id}")
            print(f"  Action: Turn the light ON")
        elif cluster_id == 0x0006 and command_id == 0x00:
            print("\n" + "="*70)
            print("✓ THIS IS AN ONOFF OFF COMMAND!")
            print("="*70)
            print(f"  Target: Endpoint {endpoint_id}")
            print(f"  Action: Turn the light OFF")
    
    else:
        print("\nCould not determine message type or unsupported message format")
    
    # This was outside the try-except, removing the exception handler
    # except Exception as e:
    #     print(f"Note: Could not fully interpret command structure: {e}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 matter_decode_message.py <hex_message>")
        print("\nExample (OnOff Toggle command):")
        print("  python3 matter_decode_message.py 152800360115350137002400012401062402021835012400001818181824ff0b18")
        sys.exit(1)
    
    message_hex = sys.argv[1]
    
    print("="*70)
    print("MATTER MESSAGE DECODER")
    print("="*70)
    print(f"\nInput (hex): {message_hex}")
    print(f"Length: {len(message_hex)//2} bytes")
    print("\n" + "="*70)
    print("TLV STRUCTURE")
    print("="*70 + "\n")
    
    decoder = MatterTLVDecoder(message_hex)
    elements = decoder.decode_all(verbose=True)
    
    # Interpret the command
    interpret_matter_command(elements)
    
    print("\n" + "="*70)
    print(f"Successfully decoded {len(elements)} TLV elements")
    print("="*70)


if __name__ == '__main__':
    main()
