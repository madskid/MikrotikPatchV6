import struct
import sys

def check(path):
    with open(path, 'rb') as f:
        data = f.read(1024)
        
    ramdisk_image = struct.unpack_from('<I', data, 0x218)[0]
    ramdisk_size = struct.unpack_from('<I', data, 0x21C)[0]
    
    print(f"ramdisk_image: {ramdisk_image} (0x{ramdisk_image:X})")
    print(f"ramdisk_size: {ramdisk_size} (0x{ramdisk_size:X})")

if __name__ == "__main__":
    check("vmlinuz_orig")
