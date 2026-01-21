import lzma
import sys
import re

def scan_strings(path):
    with open(path, 'rb') as f:
        data = f.read()
        
    xz_magic = b'\xFD\x37\x7A\x58\x5A\x00'
    try:
        start = data.index(xz_magic)
        dec = lzma.LZMADecompressor()
        vmlinux = dec.decompress(data[start:])
    except:
        return

    strings = re.findall(b"[A-Za-z0-9_ .]{6,}", vmlinux)
    for s in strings:
        s_dec = s.decode('utf-8', errors='ignore')
        if any(x in s_dec.lower() for x in ['verify', 'signature', 'keyring', 'public key', 'ecdsa', 'ed25519']):
            print(f"Found: {s_dec}")

if __name__ == "__main__":
    scan_strings("vmlinuz_orig")
