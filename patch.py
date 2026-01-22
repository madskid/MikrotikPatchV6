import subprocess
import lzma
import struct
import os
from npk import NovaPackage, NpkPartID, NpkFileContainer


def compress_xz(data):
    # Use external xz tool with settings that produce a single block and minimal headers.
    # --check=crc32 is important as some bootloaders don't support crc64.
    # --lzma2=dict=32MiB matches original Mikrotik 6.42.6 dictionary size.
    cmd = [
        "xz", 
        "--format=xz", 
        "--check=crc32", 
        "--block-size=4294967295", # Force single block
        "--lzma2=dict=32MiB,lc=3,lp=0,pb=2", 
        "--stdout"
    ]
    try:
        p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return p.stdout
    except subprocess.CalledProcessError as e:
        print(f"XZ compression failed: {e.stderr.decode()}")
        raise
    except FileNotFoundError:
         # Fallback to lzma module if xz is missing, but warn
         print("Warning: 'xz' tool not found. Falling back to internal lzma (may break legacy boot).")
         return lzma.compress(data, check=lzma.CHECK_CRC32, filters=[
            {"id": lzma.FILTER_LZMA2, "preset": 6, "dict_size": 32*1024*1024, "lc": 3, "lp": 0, "pb": 2}
         ])

def update_syssize(new_data):
    # Update syssize (Offset 0x1F4) for bootloaders (Syslinux/GRUB)
    # syssize = (protected_mode_size + 15) / 16
    setup_sects = new_data[0x1F1]
    if setup_sects == 0:
        setup_sects = 4
    setup_size = (setup_sects + 1) * 512
    total_size = len(new_data)
    protected_mode_size = total_size - setup_size
    syssize = (protected_mode_size + 15) // 16
    print(f"Updating syssize at 0x1F4: {syssize} paragraphs ({protected_mode_size} bytes)")
    struct.pack_into('<I', new_data, 0x1F4, syssize)

def patch_bzimage(data: bytes, key_dict: dict):
    PE_TEXT_SECTION_OFFSET = 414
    HEADER_PAYLOAD_OFFSET = 584
    HEADER_PAYLOAD_LENGTH_OFFSET = HEADER_PAYLOAD_OFFSET + 4
    text_section_raw_data = struct.unpack_from(
        '<I', data, PE_TEXT_SECTION_OFFSET)[0]
    payload_offset = text_section_raw_data + \
        struct.unpack_from('<I', data, HEADER_PAYLOAD_OFFSET)[0]
    payload_length = struct.unpack_from(
        '<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
    # last 4 bytes is uncompressed size(z_output_len)
    payload_length = payload_length - 4
    z_output_len = struct.unpack_from(
        '<I', data, payload_offset+payload_length)[0]
    vmlinux_xz = data[payload_offset:payload_offset+payload_length]
    vmlinux = lzma.decompress(vmlinux_xz)
    assert z_output_len == len(
        vmlinux), 'vmlinux size is not equal to expected'
    CPIO_HEADER_MAGIC = b'07070100'
    CPIO_FOOTER_MAGIC = b'TRAILER!!!\x00\x00\x00\x00'
    cpio_offset1 = vmlinux.index(CPIO_HEADER_MAGIC)
    initramfs = vmlinux[cpio_offset1:]
    cpio_offset2 = initramfs.index(CPIO_FOOTER_MAGIC)+len(CPIO_FOOTER_MAGIC)
    initramfs = initramfs[:cpio_offset2]
    new_initramfs = initramfs
    for old_public_key, new_public_key in key_dict.items():
        if old_public_key in new_initramfs:
            print(f'initramfs public key patched {old_public_key[:16].hex().upper()}...')
            new_initramfs = new_initramfs.replace(
                old_public_key, new_public_key)
    new_vmlinux = vmlinux.replace(initramfs, new_initramfs)
    
    new_vmlinux_xz = compress_xz(new_vmlinux)
    new_payload_length = len(new_vmlinux_xz) + 4
    
    new_data = bytearray(data)
    struct.pack_into('<I', new_data, HEADER_PAYLOAD_LENGTH_OFFSET, new_payload_length)
    
    # Construct new payload with size suffix
    new_payload_full = new_vmlinux_xz + struct.pack('<I', z_output_len)
    
    # Replace in file. Since size changes, we concatenate.
    # Header up to payload_offset + New Payload + Trailer after original payload
    original_payload_full_size = payload_length + 4
    result = new_data[:payload_offset] + new_payload_full + new_data[payload_offset + original_payload_full_size:]
    
    # Update syssize on the result
    result = bytearray(result)
    update_syssize(result)
    return result

def patch_legacy_bzimage(data: bytes, key_dict: dict):
    xz_magic = b'\xFD7zXZ\x00'
    try:
        payload_offset = data.index(xz_magic)
    except ValueError:
        raise Exception('XZ header not found in bzImage')

    try:
        decomp = lzma.LZMADecompressor()
        vmlinux = decomp.decompress(data[payload_offset:])
    except Exception as e:
         raise Exception(f'Decompression failed: {e}')

    compressed_size = len(data) - len(decomp.unused_data) - payload_offset
    z_output_len = struct.unpack_from('<I', data, payload_offset + compressed_size)[0]
    
    CPIO_HEADER_MAGIC = b'07070100'
    CPIO_FOOTER_MAGIC = b'TRAILER!!!\x00\x00\x00\x00'
    
    try:
        cpio_offset1 = vmlinux.index(CPIO_HEADER_MAGIC)
        initramfs = vmlinux[cpio_offset1:]
        cpio_offset2 = initramfs.index(CPIO_FOOTER_MAGIC)+len(CPIO_FOOTER_MAGIC)
        initramfs = initramfs[:cpio_offset2]
        new_initramfs = initramfs
        for old_public_key, new_public_key in key_dict.items():
            if old_public_key in new_initramfs:
                print(f'initramfs public key patched {old_public_key[:16].hex().upper()}...')
                new_initramfs = new_initramfs.replace(old_public_key, new_public_key)
        new_vmlinux = vmlinux.replace(initramfs, new_initramfs)
    except ValueError:
        print("Warning: CPIO magic not found in vmlinux, scanning whole file for keys...")
        new_vmlinux = vmlinux
        for old, new in key_dict.items():
             if old in new_vmlinux:
                 print(f'Public key patched in vmlinux {old[:16].hex().upper()}...')
                 new_vmlinux = new_vmlinux.replace(old, new)

    new_vmlinux_xz = compress_xz(new_vmlinux)
    new_payload_full = new_vmlinux_xz + struct.pack('<I', z_output_len)
    
    # PAD with zeros to match original compressed size if smaller
    if len(new_payload_full) < (compressed_size + 4):
        padding_size = (compressed_size + 4) - len(new_payload_full)
        print(f"Padding payload with {padding_size} bytes")
        new_payload_full += b'\x00' * padding_size
    elif len(new_payload_full) > (compressed_size + 4):
        # This is risky but we already updated payload_length field
        print(f"Warning: New payload is larger than original ({len(new_payload_full)} > {compressed_size + 4})")

    new_data = bytearray(data)
    HEADER_PAYLOAD_LENGTH_OFFSET = 588
    old_total_len = compressed_size + 4
    stored_len = struct.unpack_from('<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
    
    suffix = data[payload_offset + compressed_size + 4:]
    result = new_data[:payload_offset] + new_payload_full + suffix
    
    result = bytearray(result)
    
    # Update payload length if protocol version >= 2.08
    # Only update syssize if we actually changed the total file size
    if len(result) != len(data):
        update_syssize(result)
    else:
        print("File size unchanged (padded), skipping syssize update for stability.")
    return result

def patch_kernel(data: bytes, key_dict):
    if data[:2] == b'MZ':
        print('patching EFI Kernel')
        if data[56:60] == b'ARM\x64':
            print('patching arm64')
            return patch_elf(data, key_dict)
        else:
            print('patching x86_64')
            return patch_bzimage(data, key_dict)
    elif data[:4] == b'\x7FELF':
        print('patching ELF')
        return patch_elf(data, key_dict)
    elif data[:5] == b'\xFD7zXZ':
        print('patching initrd')
        return patch_initrd_xz(data, key_dict)
    elif b'HdrS' in data[:1024]:
        print('patching Legacy bzImage')
        return patch_legacy_bzimage(data, key_dict)
    else:
        raise Exception('unknown kernel format')

def patch_squashfs(path, key_dict):
    for root, dirs, files in os.walk(path):
        for file in files:
            file = os.path.join(root, file)
            if os.path.isfile(file):
                data = open(file, 'rb').read()
                for old_public_key, new_public_key in key_dict.items():
                    if old_public_key in data:
                        print(f'{file} public key patched {old_public_key[:16].hex().upper()}...')
                        data = data.replace(old_public_key, new_public_key)
                        open(file, 'wb').write(data)

def run_shell_command(command):
    try:
        process = subprocess.run(
            command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process.stdout, process.stderr
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(f"Exit Code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        raise

def patch_npk_package(package, key_dict):
    if package[NpkPartID.NAME_INFO].data.name == 'system':
        file_container = NpkFileContainer.unserialize_from(
            package[NpkPartID.FILE_CONTAINER].data)
        for item in file_container:
            if item.name in [b'boot/EFI/BOOT/BOOTX64.EFI', b'boot/kernel', b'boot/initrd.rgz']:
                print(f'patch {item.name} ...')
                item.data = patch_kernel(item.data, key_dict)
        package[NpkPartID.FILE_CONTAINER].data = file_container.serialize()
        squashfs_file = 'squashfs-root.sfs'
        extract_dir = 'squashfs-root'
        open(squashfs_file, 'wb').write(package[NpkPartID.SQUASHFS].data)
        print(f"extract {squashfs_file} ...")
        run_shell_command(f"unsquashfs -f -d {extract_dir} {squashfs_file}")
        patch_squashfs(extract_dir, key_dict)
        print(f"pack {extract_dir} ...")
        run_shell_command(f"rm -f {squashfs_file}")
        run_shell_command(f"mksquashfs {extract_dir} {squashfs_file} -quiet -comp xz -no-xattrs -b 256k -Xbcj x86")
        print(f"clean ...")
        run_shell_command(f"rm -rf {extract_dir}")
        package[NpkPartID.SQUASHFS].data = open(squashfs_file, 'rb').read()
        run_shell_command(f"rm -f {squashfs_file}")

def patch_initrd_xz(initrd_xz:bytes,key_dict:dict,ljust=True):
    try:
        initrd = lzma.decompress(initrd_xz)
    except Exception:
        initrd = lzma.LZMADecompressor().decompress(initrd_xz)
    new_initrd = initrd
    for old_public_key,new_public_key in key_dict.items():
        if old_public_key in new_initrd:
            print(f'initrd public key patched {old_public_key[:16].hex().upper()}...')
            new_initrd = new_initrd.replace(old_public_key,new_public_key)
            
    # Use safe compression (Stream format, no size header)
    new_initrd_xz = compress_xz(new_initrd)
    
    # We do NOT pad (ljust). Padded XZ can cause decompression failures in some kernels/loaders.
    # The caller (patch_pe) checks size constraints if necessary.
    # For file-based initrd, size change is fine.
    
    return new_initrd_xz

def patch_elf(data: bytes, key_dict: dict):
    initrd_xz = find_7zXZ_data(data)
    new_initrd_xz = patch_initrd_xz(initrd_xz, key_dict)
    return data.replace(initrd_xz, new_initrd_xz)

def patch_pe(data: bytes, key_dict: dict):
    vmlinux_xz = find_7zXZ_data(data)
    vmlinux = lzma.decompress(vmlinux_xz)
    initrd_xz_offset = vmlinux.index(b'\xFD7zXZ\x00\x00\x01')
    initrd_xz_size = vmlinux[initrd_xz_offset:].index(
        b'\x00\x00\x00\x00\x01\x59\x5A') + 7
    initrd_xz = vmlinux[initrd_xz_offset:initrd_xz_offset+initrd_xz_size]
    new_initrd_xz = patch_initrd_xz(initrd_xz, key_dict)
    new_vmlinux = vmlinux.replace(initrd_xz, new_initrd_xz)
    
    # Use custom compression
    new_vmlinux_xz = compress_xz(new_vmlinux)

    assert len(new_vmlinux_xz) <= len(
        vmlinux_xz), 'new vmlinux xz size is too big'
    print(f'new vmlinux xz size:{len(new_vmlinux_xz)}')
    print(f'old vmlinux xz size:{len(vmlinux_xz)}')
    # Removing ljust padding. 
    # new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')
    new_data = data.replace(vmlinux_xz, new_vmlinux_xz)
    return new_data

def patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, input_file, output_file=None):
    try:
        npk = NovaPackage.load(input_file)
    except (AssertionError, Exception) as e:
        print(f"Skipping invalid NPK: {input_file} ({e})")
        return

    if len(npk._packages) > 0:
        for package in npk._packages:
            patch_npk_package(package, key_dict)
    else:
        patch_npk_package(npk, key_dict)
    npk.sign(kcdsa_private_key, eddsa_private_key)
    npk.save(output_file or input_file)


if __name__ == '__main__':
    import argparse
    import os
    parser = argparse.ArgumentParser(description='MikroTik patcher')
    subparsers = parser.add_subparsers(dest="command")
    npk_parser = subparsers.add_parser('npk', help='patch and sign npk file')
    npk_parser.add_argument('input', type=str, help='Input file')
    npk_parser.add_argument('-O', '--output', type=str, help='Output file')
    kernel_parser = subparsers.add_parser('kernel', help='patch kernel file')
    kernel_parser.add_argument('input', type=str, help='Input file')
    kernel_parser.add_argument('-O', '--output', type=str, help='Output file')
    block_parser = subparsers.add_parser('block', help='patch block file')
    block_parser.add_argument('dev', type=str, help='block device')
    block_parser.add_argument('file', type=str, help='file path')
    netinstall_parser = subparsers.add_parser(
        'netinstall', help='patch netinstall file')
    netinstall_parser.add_argument('input', type=str, help='Input file')
    netinstall_parser.add_argument(
        '-O', '--output', type=str, help='Output file')
    args = parser.parse_args()
    key_dict = {
        bytes.fromhex(os.environ['MIKRO_LICENSE_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY']),
        bytes.fromhex(os.environ['MIKRO_NPK_SIGN_PUBLIC_KEY']): bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PUBLIC_KEY'])
    }
    kcdsa_private_key = bytes.fromhex(os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])
    eddsa_private_key = bytes.fromhex(
        os.environ['CUSTOM_NPK_SIGN_PRIVATE_KEY'])
    if args.command == 'npk':
        print(f'patching {args.input} ...')
        patch_npk_file(key_dict, kcdsa_private_key,
                       eddsa_private_key, args.input, args.output)
    elif args.command == 'kernel':
        print(f'patching {args.input} ...')
        data = patch_kernel(open(args.input, 'rb').read(), key_dict)
        open(args.output or args.input, 'wb').write(data)
    elif args.command == 'block':
        print(f'patching {args.file} in {args.dev} ...')
        patch_block(args.dev, args.file, key_dict)
    elif args.command == 'netinstall':
        print(f'patching {args.input} ...')
        patch_netinstall(key_dict, args.input, args.output)
    else:
        parser.print_help()