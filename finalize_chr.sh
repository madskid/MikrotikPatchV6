#!/bin/bash
set -e

# Configuration
VERSION="6.42.6"
IMAGE="chr-$VERSION.img"
PATCHED_IMAGE="chr-$VERSION-patched.img"
PATCHED_NPK="patched_packages/routeros-$VERSION.npk"
EFI_BOOTLOADER="refind-bin-0.14.2/refind/refind_x64.efi"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Check tools
for cmd in qemu-nbd qemu-img extlinux mount umount cp mkdir rm modprobe; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd could not be found. Please install required packages (qemu-utils, syslinux/extlinux)."
        exit 1
    fi
done

echo "Creating patched image: $PATCHED_IMAGE"
cp "$IMAGE" "$PATCHED_IMAGE"

echo "Loading NBD module..."
modprobe nbd max_part=8

echo "Connecting image to /dev/nbd0..."
qemu-nbd -c /dev/nbd0 -f raw "$PATCHED_IMAGE"
# Wait for partitions to appear
sleep 2

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    if mountpoint -q ./mnt_boot; then umount ./mnt_boot; fi
    if mountpoint -q ./mnt_ros; then umount ./mnt_ros; fi
    qemu-nbd -d /dev/nbd0
    rm -rf ./mnt_boot ./mnt_ros
}
trap cleanup EXIT

mkdir -p ./mnt_boot ./mnt_ros

echo "Mounting partitions..."
if [ ! -b /dev/nbd0p1 ]; then
    echo "Error: /dev/nbd0p1 not found. NBD mapping failed or partitions missing."
    exit 1
fi
mount /dev/nbd0p1 ./mnt_boot
mount /dev/nbd0p2 ./mnt_ros

echo "Extracting Kernel and Initrd from Patched NPK..."
python3 extract_kernel.py "$PATCHED_NPK" ./mnt_boot

echo "Configuring Syslinux..."
# Check which kernel we have
KERNEL_FILE="/kernel"
if [ -f "./mnt_boot/vmlinuz-64" ]; then
    KERNEL_FILE="/vmlinuz-64"
fi

if [ ! -f "./mnt_boot/BOOT/syslinux.cfg" ]; then
    echo "Creating new syslinux.cfg..."
    cat > syslinux.cfg <<EOF
default system
timeout 10
label system
	kernel /vmlinuz
	initrd /initrd.rgz
	append root=/dev/sda2 rootwait console=tty0 console=ttyS0,115200
label backup
	kernel /vmlinuz-smp
	initrd /initrd.rgz
	append root=/dev/sda2 rootwait console=tty0 console=ttyS0,115200
EOF
    cp syslinux.cfg ./mnt_boot/BOOT/
    rm syslinux.cfg
else
    echo "Keeping existing syslinux.cfg."
fi

# Update Syslinux map (required because files changed)
echo "Updating Syslinux map..."
extlinux --update ./mnt_boot/BOOT

echo "Injecting Patched RouterOS Package..."
# The target path might vary slightly, but standard CHR structure is usually this:
TARGET_PATH="./mnt_ros/var/pdb/system/image"
# Ensure directory exists? usually it does.
if [ ! -d "$(dirname "$TARGET_PATH")" ]; then
    echo "Warning: Target directory $(dirname "$TARGET_PATH") does not exist. Creating..."
    mkdir -p "$(dirname "$TARGET_PATH")"
fi

cp "$PATCHED_NPK" "$TARGET_PATH"

echo "Syncing..."
sync

echo "Unmounting..."
umount ./mnt_boot
umount ./mnt_ros
# Trap will handle qemu-nbd disconnect, but good to be explicit if success
qemu-nbd -d /dev/nbd0
trap - EXIT # Disable trap to avoid double cleanup

echo "Converting to qcow2..."
qemu-img convert -f raw -O qcow2 "$PATCHED_IMAGE" "chr-$VERSION-patched.qcow2"

echo "Done! Patched image is chr-$VERSION-patched.img (and .qcow2)"
