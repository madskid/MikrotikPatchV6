import sys
import os
from npk import NovaPackage, NpkPartID, NpkFileContainer

def extract_kernel(npk_path, output_dir):
    try:
        npk = NovaPackage.load(npk_path)
    except Exception as e:
        print(f"Error loading NPK: {e}")
        sys.exit(1)

    target_pkg = None
    # Check if it's a bundle or single package
    if len(npk._packages) > 0:
        for p in npk._packages:
            if p[NpkPartID.NAME_INFO].data.name == 'system':
                target_pkg = p
                break
    elif npk[NpkPartID.NAME_INFO].data.name == 'system':
        target_pkg = npk

    if not target_pkg:
        print("Error: 'system' package not found in NPK.")
        sys.exit(1)

    container = NpkFileContainer.unserialize_from(target_pkg[NpkPartID.FILE_CONTAINER].data)
    
    found_kernel = False
    found_initrd = False

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print("Files in NPK container:")
    for item in container:
        name = item.name.decode()
        print(f" - {name}")
        
        # Kernel logic
        if not found_kernel:
            if name in ['boot/kernel', 'boot/vmlinuz', 'vmlinuz', 'kernel']:
                print(f"Found kernel: {name} -> extracting to kernel")
                with open(os.path.join(output_dir, 'kernel'), 'wb') as f:
                    f.write(item.data)
                found_kernel = True
        
        # Initrd logic
        if not found_initrd:
            if name in ['boot/initrd.rgz', 'initrd.rgz']:
                print(f"Found initrd: {name} -> extracting to initrd.rgz")
                with open(os.path.join(output_dir, 'initrd.rgz'), 'wb') as f:
                    f.write(item.data)
                found_initrd = True
    
    if found_kernel and found_initrd:
        print("Extraction successful.")
    else:
        print("Warning: Kernel or initrd not found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 extract_kernel.py <npk_file> <output_dir>")
        sys.exit(1)
    extract_kernel(sys.argv[1], sys.argv[2])
