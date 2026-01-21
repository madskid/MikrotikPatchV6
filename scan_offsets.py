import struct
import sys

def scan(path, target_val):
    with open(path, 'rb') as f:
        data = f.read(4096) # Read header area
        
    print(f"Scanning for {target_val} ({hex(target_val)}) in {path}...")
    
    found = False
    for i in range(0, len(data) - 4):
        val = struct.unpack_from('<I', data, i)[0]
        if val == target_val:
            print(f"Found match at offset {i} (0x{i:X})")
            found = True
            
    if not found:
        print("No match found.")

if __name__ == "__main__":
    scan('vmlinuz_orig', 2027653)
