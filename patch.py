import subprocess
import lzma
import struct
import os
from npk import NovaPackage, NpkPartID, NpkFileContainer


def compress_xz(data):
    # Use external xz tool to ensure stream mode (Block Flags 0x00)
    # Python's lzma module often adds size fields (Flags 0x01/0x02) which legacy kernels dislike.
    cmd = [
        "xz", 
        "--format=xz", 
        "--check=crc32", 
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
    CPIO_FOOTER_MAGIC = b'TRAILER!!!\x00\x00\x00\x00'  # 545241494C455221212100000000
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
    
    # Use custom compression
    new_vmlinux_xz = compress_xz(new_vmlinux)

    new_payload_length = len(new_vmlinux_xz)
    assert new_payload_length <= payload_length, 'new vmlinux.xz size is too big'
    # last 4 bytes is uncompressed size(z_output_len)
    new_payload_length = new_payload_length + 4
    new_data = bytearray(data)
    struct.pack_into(
        '<I', new_data, HEADER_PAYLOAD_LENGTH_OFFSET, new_payload_length)
    vmlinux_xz += struct.pack('<I', z_output_len)
    new_vmlinux_xz += struct.pack('<I', z_output_len)
    # Removing ljust padding to ensure size field is at the end
    # new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')
    new_data = new_data.replace(vmlinux_xz, new_vmlinux_xz)
    
    # Update syssize (Offset 0x1F4) for bootloaders (Syslinux/GRUB)
    setup_sects = new_data[0x1F1]
    if setup_sects == 0:
        setup_sects = 4
    setup_size = (setup_sects + 1) * 512
    total_size = len(new_data)
    protected_mode_size = total_size - setup_size
    syssize = (protected_mode_size + 15) // 16
    
    print(f"Updating syssize at 0x1F4: {syssize} paragraphs ({protected_mode_size} bytes)")
    struct.pack_into('<I', new_data, 0x1F4, syssize)
    
    return new_data


def patch_block(dev:str,file:str,key_dict):
    BLOCK_SIZE = 4096
    #sudo debugfs /dev/nbd0p1 -R 'stats' | grep "Block size" | sed -n '1p' | cut -d ':' -f 2 

    #sudo debugfs /dev/nbd0p1 -R 'stat boot/initrd.rgz' 2> /dev/null | sed -n '11p'
    stdout,_ = run_shell_command(f"debugfs {dev} -R 'stat {file}' 2> /dev/null | sed -n '11p' ")
    #(0-11):1592-1603, (IND):1173, (12-15):1604-1607, (16-26):1424-1434
    blocks_info = stdout.decode().strip().split(',')
    print(f'blocks_info : {blocks_info}')
    blocks = []
    ind_block_id = None
    for block_info in blocks_info:
        _tmp = block_info.strip().split(':')
        if _tmp[0].strip() == '(IND)':
            ind_block_id =  int(_tmp[1])
        else:
            print(f'block_info : {block_info}')
            id_range = _tmp[0].strip().replace('(','').replace(')','').split('-')
            block_range = _tmp[1].strip().replace('(','').replace(')','').split('-')
            blocks += [id for id in range(int(block_range[0]),int(block_range[1])+1)]
    print(f' blocks : {len(blocks)} ind_block_id : {ind_block_id}')
    
    #sudo debugfs /dev/nbd0p1  -R 'cat boot/initrd.rgz' > data
    data,stderr = run_shell_command(f"debugfs {dev} -R 'cat {file}' 2> /dev/null")
    new_data = patch_kernel(data,key_dict)
    print(f'write block {len(blocks)} : [',end="")
    with open(dev,'wb') as f:
        for index,block_id in enumerate(blocks):
            print('#',end="")
            f.seek(block_id*BLOCK_SIZE)
            f.write(new_data[index*BLOCK_SIZE:(index+1)*BLOCK_SIZE])
        f.flush()
        print(']')


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
    preset = 6
    new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset }] )
    while len(new_initrd_xz) > len(initrd_xz) and preset < 9:
        print(f'preset:{preset}')
        print(f'new initrd xz size:{len(new_initrd_xz)}')
        print(f'old initrd xz size:{len(initrd_xz)}')
        preset += 1
        new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=[{"id": lzma.FILTER_LZMA2, "preset": preset }] )
    if len(new_initrd_xz) > len(initrd_xz):
        new_initrd_xz = lzma.compress(new_initrd,check=lzma.CHECK_CRC32,filters=[{"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME,'dict_size': 32*1024*1024,"lc": 4,"lp": 0, "pb": 0,}] )
    if ljust:
        print(f'preset:{preset}')
        print(f'new initrd xz size:{len(new_initrd_xz)}')
        print(f'old initrd xz size:{len(initrd_xz)}')
        print(f'ljust size:{len(initrd_xz)-len(new_initrd_xz)}')
        assert len(new_initrd_xz) <= len(initrd_xz),'new initrd xz size is too big'
        new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz),b'\0')
    return new_initrd_xz


def find_7zXZ_data(data: bytes):
    offset1 = 0
    _data = data
    while b'\xFD7zXZ\x00\x00\x01' in _data:
        offset1 = offset1 + _data.index(b'\xFD7zXZ\x00\x00\x01') + 8
        _data = _data[offset1:]
    offset1 -= 8
    offset2 = 0
    _data = data
    while b'\x00\x00\x00\x00\x01\x59\x5A' in _data:
        offset2 = offset2 + _data.index(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
        _data = _data[offset2:]
    print(f'found 7zXZ data offset:{offset1} size:{offset2-offset1}')
    return data[offset1:offset2]


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
    # Removing ljust padding. PE format might require section alignment, 
    # but internal payload replacement shouldn't pad the XZ stream itself 
    # if it breaks the size field position. 
    # We rely on the container to handle external alignment if needed.
    # new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')
    new_data = data.replace(vmlinux_xz, new_vmlinux_xz)
    return new_data


def patch_netinstall(key_dict: dict, input_file, output_file=None):
    netinstall = open(input_file, 'rb').read()
    if netinstall[:2] == b'MZ':
        import pefile
        ROUTEROS_BOOT = {
            129: {'arch': 'power', 'name': 'Powerboot'},
            130: {'arch': 'e500', 'name': 'e500_boot'},
            131: {'arch': 'mips', 'name': 'Mips_boot'},
            135: {'arch': '400', 'name': '440__boot'},
            136: {'arch': 'tile', 'name': 'tile_boot'},
            137: {'arch': 'arm', 'name': 'ARM__boot'},
            138: {'arch': 'mmips', 'name': 'MMipsBoot'},
            139: {'arch': 'arm64', 'name': 'ARM64__boot'},
            143: {'arch': 'x86_64', 'name': 'x86_64boot'}
        }
        with pefile.PE(input_file) as pe:
            for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                    for sub_resource in resource.directory.entries:
                        if sub_resource.id in ROUTEROS_BOOT:
                            bootloader = ROUTEROS_BOOT[sub_resource.id]
                            print(f'found {bootloader["arch"]}({sub_resource.id}) bootloader')
                            rva = sub_resource.directory.entries[0].data.struct.OffsetToData
                            size = sub_resource.directory.entries[0].data.struct.Size
                            data = pe.get_data(rva, size)
                            _size = struct.unpack('<I', data[:4])[0]
                            _data = data[4:4+_size]
                            try:
                                if _data[:2] == b'MZ':
                                    new_data = patch_pe(_data, key_dict)
                                elif _data[:4] == b'\x7FELF':
                                    new_data = patch_elf(_data, key_dict)
                                else:
                                    raise Exception(f'unknown bootloader format {_data[:4].hex().upper()}')
                            except Exception as e:
                                print(f'patch {bootloader["arch"]}({sub_resource.id}) bootloader failed {e}')
                                new_data = _data
                            new_data = struct.pack(
                                "<I", _size) + new_data.ljust(len(_data), b'\0')
                            new_data = new_data.ljust(size, b'\0')
                            pe.set_bytes_at_rva(rva, new_data)
            pe.write(output_file or input_file)
    elif netinstall[:4] == b'\x7FELF':
        import re
        # 83 00 00 00 C4 68 C4 0B  5A C2 04 08 10 9E 52 00
        # 8A 00 00 00 C3 68 C4 0B  6A 60 57 08 C0 3D 54 00
        # 81 00 00 00 D3 68 C4 0B  2A 9E AB 08 5C 1B 78 00
        # 82 00 00 00 E8 6B C4 0B  86 B9 23 09 78 01 82 00
        # 87 00 00 00 ED 6B C4 0B  FE BA A5 09 44 BF 7B 00
        # 89 00 00 00 0C 6A C4 0B  42 7A 21 0A C4 1D 3E 00
        # 8B 00 00 00 1E 69 C4 0B  06 98 5F 0A 28 95 5E 00
        # 8C 00 00 00 F1 6B C4 0B  2E 2D BE 0A 78 EA 5D 00
        # 88 00 00 00 03 69 C4 0B  A6 17 1C 0B 28 55 4A 00
        # 8F 00 00 00 FC 6B C4 0B  CE 6C 66 0B E0 E8 58 00
        SECTION_HEADER_OFFSET_IN_FILE = struct.unpack_from(
            b'<I', netinstall[0x20:])[0]
        SECTION_HEADER_ENTRY_SIZE = struct.unpack_from(
            b'<H', netinstall[0x2E:])[0]
        NUMBER_OF_SECTION_HEADER_ENTRIES = struct.unpack_from(
            b'<H', netinstall[0x30:])[0]
        STRING_TABLE_INDEX = struct.unpack_from(b'<H', netinstall[0x32:])[0]
        section_name_offset = SECTION_HEADER_OFFSET_IN_FILE + \
            STRING_TABLE_INDEX * SECTION_HEADER_ENTRY_SIZE + 16
        SECTION_NAME_BLOCK = struct.unpack_from(
            b'<I', netinstall[section_name_offset:])[0]
        for i in range(NUMBER_OF_SECTION_HEADER_ENTRIES):
            section_offset = SECTION_HEADER_OFFSET_IN_FILE + i * SECTION_HEADER_ENTRY_SIZE
            name_offset, _, _, addr, offset = struct.unpack_from(
                '<IIIII', netinstall[section_offset:])
            name = netinstall[SECTION_NAME_BLOCK+name_offset:].split(b'\0')[0]
            if name == b'.text':
                print(f'found .text section at {hex(offset)} addr {hex(addr)}')
                text_section_addr = addr
                text_section_offset = offset
                break
        offset = re.search(
            rb'\x83\x00\x00\x00.{12}\x8A\x00\x00\x00.{12}\x81\x00\x00\x00.{12}', netinstall).start()
        print(f'found bootloaders offset {hex(offset)}')
        for i in range(10):
            id, name_ptr, data_ptr, data_size = struct.unpack_from(
                '<IIII', netinstall[offset+i*16:offset+i*16+16])
            name = netinstall[text_section_offset +
                              name_ptr-text_section_addr:].split(b'\0')[0]
            data = netinstall[text_section_offset+data_ptr -
                              text_section_addr:text_section_offset+data_ptr-text_section_addr+data_size]
            print(f'found {name.decode()}({id}) bootloader offset {hex(text_section_offset+data_ptr-text_section_addr)} size {data_size}')
            try:
                if data[:2] == b'MZ':
                    new_data = patch_pe(data, key_dict)
                elif data[:4] == b'\x7FELF':
                    new_data = patch_elf(data, key_dict)
                else:
                    raise Exception(f'unknown bootloader format {data[:4].hex().upper()}')
            except Exception as e:
                print(f'patch {name.decode()}({id}) bootloader failed {e}')
                new_data = data
            new_data = new_data.ljust(len(data), b'\0')
            netinstall = netinstall.replace(data, new_data)
        open(output_file or input_file, 'wb').write(netinstall)


def patch_legacy_bzimage(data: bytes, key_dict: dict):
    xz_magic = b'\xFD7zXZ\x00'
    try:
        payload_offset = data.index(xz_magic)
    except ValueError:
        raise Exception('XZ header not found in bzImage')

    # Decompress to find end of stream
    try:
        decomp = lzma.LZMADecompressor()
        vmlinux = decomp.decompress(data[payload_offset:])
    except Exception as e:
         raise Exception(f'Decompression failed: {e}')

    compressed_size = len(data) - len(decomp.unused_data) - payload_offset
    z_output_len = struct.unpack_from('<I', data, payload_offset + compressed_size)[0]
    
    # Patching Logic (Extract CPIO)
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

    # Recompress using custom xz to avoid block header size fields
    new_vmlinux_xz = compress_xz(new_vmlinux)
    
    # Add size suffix
    new_vmlinux_xz += struct.pack('<I', z_output_len)
    
    new_data = bytearray(data)
    
    # Update Length in Header if matches (Offset 588)
    HEADER_PAYLOAD_LENGTH_OFFSET = 588
    old_total_len = compressed_size + 4
    stored_len = struct.unpack_from('<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
    
    if stored_len == old_total_len:
         print(f"Updating payload length at {HEADER_PAYLOAD_LENGTH_OFFSET}")
         struct.pack_into('<I', new_data, HEADER_PAYLOAD_LENGTH_OFFSET, len(new_vmlinux_xz))
    
    suffix = data[payload_offset + compressed_size + 4:]
    
    # Update syssize (Offset 0x1F4) for bootloaders
    setup_sects = new_data[0x1F1]
    if setup_sects == 0: setup_sects = 4
    setup_size = (setup_sects + 1) * 512
    
    # Calculate expected total size
    total_size = payload_offset + len(new_vmlinux_xz) + len(suffix)
    protected_mode_size = total_size - setup_size
    syssize = (protected_mode_size + 15) // 16
    
    print(f"Updating syssize at 0x1F4: {syssize} paragraphs ({protected_mode_size} bytes)")
    struct.pack_into('<I', new_data, 0x1F4, syssize)

    return new_data[:payload_offset] + new_vmlinux_xz + suffix


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
