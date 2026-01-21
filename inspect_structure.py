import struct
import sys

def inspect(path):
    with open(path, 'rb') as f:
        data = f.read()
        
    PE_TEXT_SECTION_OFFSET = 414
    HEADER_PAYLOAD_OFFSET = 584
    HEADER_PAYLOAD_LENGTH_OFFSET = HEADER_PAYLOAD_OFFSET + 4
    
    text_section_raw_data = struct.unpack_from('<I', data, PE_TEXT_SECTION_OFFSET)[0]
    payload_offset_rel = struct.unpack_from('<I', data, HEADER_PAYLOAD_OFFSET)[0]
    payload_offset = text_section_raw_data + payload_offset_rel
    
    payload_length = struct.unpack_from('<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
    
    print(f"File: {path}")
    print(f"File Size: {len(data)}")
    print(f"Text Section Raw Data: {text_section_raw_data}")
    print(f"Payload Offset: {payload_offset} (Rel: {payload_offset_rel})")
    print(f"Payload Length (from header): {payload_length}")
    
    # Check bounds
    end_of_payload = payload_offset + payload_length
    print(f"End of Payload: {end_of_payload}")
    
    suffix_len = len(data) - end_of_payload
    print(f"Suffix Length: {suffix_len}")
    
    if suffix_len > 0:
        print(f"Suffix Data (first 64 bytes): {data[end_of_payload:end_of_payload+64].hex()}")
        # Check for zeros
        suffix = data[end_of_payload:]
        if all(b == 0 for b in suffix):
            print("Suffix is all ZEROs (Padding).")
        else:
            print("Suffix contains NON-ZERO data.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script <file>")
    else:
        inspect(sys.argv[1])
