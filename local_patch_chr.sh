#!/bin/bash
set -e

# Usage: sudo ./local_patch_chr.sh chr-6.42.6.img

IMAGE="$1"
if [ -z "$IMAGE" ]; then
    echo "Usage: sudo ./local_patch_chr.sh <chr_image.img>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Requirements check
for cmd in qemu-nbd extlinux python3; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd not found. Install qemu-utils, syslinux/extlinux, python3."
        exit 1
    fi
done

echo "Patching $IMAGE..."

# Load NBD
modprobe nbd max_part=8

# Connect Image
NBD_DEV=/dev/nbd0
qemu-nbd -c $NBD_DEV -f raw "$IMAGE"
sleep 2

# Mount Boot Partition (Partition 1)
mkdir -p mnt_boot
mount ${NBD_DEV}p1 mnt_boot

echo "Mounted boot partition."

# Identify Kernel and Initrd
KERNEL=""
for f in "vmlinuz-64" "boot/vmlinuz-64" "vmlinuz" "kernel"; do
    if [ -f "mnt_boot/$f" ]; then
        KERNEL="mnt_boot/$f"
        break
    fi
done

INITRD=""
for f in "initrd.rgz" "boot/initrd.rgz"; do
    if [ -f "mnt_boot/$f" ]; then
        INITRD="mnt_boot/$f"
        break
    fi
done

if [ -z "$KERNEL" ] || [ -z "$INITRD" ]; then
    echo "Error: Kernel or Initrd not found!"
    umount mnt_boot
    qemu-nbd -d $NBD_DEV
    exit 1
fi

echo "Found Kernel: $KERNEL"
echo "Found Initrd: $INITRD"

# Patch All Kernels and Initrd
PATCH_SCRIPT="./MikrotikPatchV6/patch.py"
if [ ! -f "$PATCH_SCRIPT" ]; then
    PATCH_SCRIPT="./patch.py"
fi

echo "Applying patches to all kernels..."
# Patch any vmlinuz file found
find mnt_boot -name "vmlinuz*" -exec python3 "$PATCH_SCRIPT" kernel {} \;
# Patch initrd
if [ -f "$INITRD" ]; then
    python3 "$PATCH_SCRIPT" kernel "$INITRD"
fi

# Install Syslinux Bootloader
echo "Installing Syslinux..."
mkdir -p mnt_boot/BOOT
extlinux --install -H 64 -S 32 mnt_boot/BOOT

# Configure Syslinux
# We prioritize vmlinuz-64 if it exists, otherwise use what was found
BEST_KERNEL="/vmlinuz-64"
if [ ! -f "mnt_boot/vmlinuz-64" ]; then
    BEST_KERNEL="/${KERNEL#mnt_boot/}"
fi

cat > mnt_boot/BOOT/syslinux.cfg <<EOF
default system
timeout 10
label system
    kernel $BEST_KERNEL
    initrd /${INITRD#mnt_boot/}
    append load_ramdisk=1 root=/dev/ram0 quiet console=tty0 console=ttyS0,115200
label backup
    kernel /vmlinuz-smp
    initrd /${INITRD#mnt_boot/}
    append load_ramdisk=1 root=/dev/ram0 quiet console=tty0 console=ttyS0,115200
EOF

echo "Syslinux configured with priority: $BEST_KERNEL"

# Install MBR to the disk (to ensure BIOS boots the partition)
if [ -f "./MikrotikPatchV6/mbr.bin" ]; then
    echo "Installing local MBR..."
    dd if="./MikrotikPatchV6/mbr.bin" of=$NBD_DEV bs=440 count=1
elif [ -f "./mbr.bin" ]; then
    echo "Installing local MBR..."
    dd if="./mbr.bin" of=$NBD_DEV bs=440 count=1
elif [ -f "/usr/lib/syslinux/mbr/mbr.bin" ]; then
    echo "Installing system MBR..."
    dd if=/usr/lib/syslinux/mbr/mbr.bin of=$NBD_DEV bs=440 count=1
elif [ -f "/usr/lib/EXTLINUX/mbr.bin" ]; then
    echo "Installing system MBR..."
    dd if=/usr/lib/EXTLINUX/mbr.bin of=$NBD_DEV bs=440 count=1
else
    echo "Warning: Syslinux MBR (mbr.bin) not found. Image might not boot if MBR is missing or corrupted."
fi

# Cleanup
umount mnt_boot
qemu-nbd -d $NBD_DEV
rm -rf mnt_boot

echo "Done! Image $IMAGE is patched and bootable."
