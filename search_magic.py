import lzma
import sys

def search_magic(bzimage_path, magic_bytes):
    # 1. Extract and Decompress vmlinux
    with open(bzimage_path, 'rb') as f:
        data = f.read()
        
    xz_magic = b'\xFD\x37\x7A\x58\x5A\x00'
    try:
        start = data.index(xz_magic)
    except ValueError:
        print("No XZ header.")
        return

    try:
        dec = lzma.LZMADecompressor()
        vmlinux = dec.decompress(data[start:])
    except Exception:
        # Fallback if trailing garbage
        # We just want the code
        pass
        
    print(f"Decompressed vmlinux size: {len(vmlinux)}")
    
    # 2. Search for magic
    print(f"Scanning for {magic_bytes.hex()}...")
    offset = vmlinux.find(magic_bytes)
    
    if offset != -1:
        print(f"Found magic in vmlinux at offset {offset}")
    else:
        print("Magic NOT found in vmlinux.")

if __name__ == "__main__":
    # Magic from suffix start: 35d4c8b7
    magic = bytes.fromhex("35d4c8b7")
    search_magic("vmlinuz_orig", magic)
