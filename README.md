# Notice

# Download

You can download the automatically generated RouterOS image from [here](https://github.com/madskid/MikroTikPatchV6/releases).

# How to generate license key

I have already generated the keys for you. You can use them to generate a license key and sign packages.

**RouterOS v6 (Verified on 6.42.6):**
```bash
export MIKRO_NPK_SIGN_PUBLIC_KEY="C275D7235766AEC866D4C59573C8E188A51339936E94D2CCF11F9FF5BAED7137"
export MIKRO_LICENSE_PUBLIC_KEY="8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"
# Note: For v6, the NPK sign private key is used for package signing.
export CUSTOM_NPK_SIGN_PRIVATE_KEY="7D008D9B80B036FB0205601FEE79D550927EBCA937B7008CC877281F2F8AC640"
# Corrected Public Key derived from Private Key:
export CUSTOM_NPK_SIGN_PUBLIC_KEY="9522B44B781CBC64E930C563588E6872FBDCDBEF16E963D52BD07E29A15D1B12"
export CUSTOM_LICENSE_PRIVATE_KEY="9DBC845E9018537810FDAE62824322EEE1B12BAD81FCA28EC295FB397C61CE0B"
export CUSTOM_LICENSE_PUBLIC_KEY="723A34A6E3300F23E4BAA06156B9327514AEC170732655F16E04C17928DD770F"
```

You can generate your own keys yourself, but in this case you will have to manually create a MikroTik image.

- Install Python 3.x
- Clone this repository

Here is the command to generate your own keys:

```bash
python3 license.py genkey
```

## RouterOS License Generation

### v6 License (Level 6 + Extra Channel)
For RouterOS v6, you must specify the version and feature level.
- `-v 6`: Specifies RouterOS v6.
- `-f 22`: Specifies Level 6 + Extra Channel (Decimal 22).

```bash
python3 license.py licgenros <SOFTWARE_ID> $CUSTOM_LICENSE_PRIVATE_KEY -v 6 -f 22
```

## Cloud Hosted Router (CHR) License

Let's assume that your system_id is: `pjLQ21gHzfI`

```bash
python3 license.py licgenchr pjLQ21gHzfI $CUSTOM_LICENSE_PRIVATE_KEY
```

# Generate own images

## Requirements

### Debian 12

```bash
apt-get update
apt-get install -y wget curl mkisofs xorriso sudo zip unzip git squashfs-tools \
rsync ca-certificates python3 python3-pefile qemu-utils extlinux dosfstools --no-install-recommends
```

## Download dependencies

```bash
export VERSION="6.42.6"

wget https://download.mikrotik.com/routeros/$VERSION/mikrotik-$VERSION.iso
wget https://download.mikrotik.com/routeros/$VERSION/install-image-$VERSION.zip
wget https://download.mikrotik.com/routeros/$VERSION/chr-$VERSION.img.zip
wget https://nchc.dl.sourceforge.net/project/refind/0.14.2/refind-bin-0.14.2.zip
git clone -b main --single-branch --depth=1 https://github.com/madskid/MikrotikPatchV6
unzip install-image-$VERSION.zip
unzip chr-$VERSION.img.zip
unzip refind-bin-0.14.2.zip refind-bin-0.14.2/refind/refind_x64.efi
cp mikrotik-$VERSION.iso ./MikroTikPatch/mikrotik.iso
cp install-image-$VERSION.img ./MikroTikPatch/install-image.img
cp chr-$VERSION.img ./MikroTikPatch/chr.img
cd ./MikroTikPatch
```

## Patching RouterOS v6 (Legacy)

This process has been verified for RouterOS v6.42.6.

1.  **Export Keys for v6**:
    ```bash
    export MIKRO_NPK_SIGN_PUBLIC_KEY="C275D7235766AEC866D4C59573C8E188A51339936E94D2CCF11F9FF5BAED7137"
    export MIKRO_LICENSE_PUBLIC_KEY="8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"
    export CUSTOM_NPK_SIGN_PRIVATE_KEY="7D008D9B80B036FB0205601FEE79D550927EBCA937B7008CC877281F2F8AC640"
    export CUSTOM_NPK_SIGN_PUBLIC_KEY="9522B44B781CBC64E930C563588E6872FBDCDBEF16E963D52BD07E29A15D1B12"
    export CUSTOM_LICENSE_PRIVATE_KEY="9DBC845E9018537810FDAE62824322EEE1B12BAD81FCA28EC295FB397C61CE0B"
    export CUSTOM_LICENSE_PUBLIC_KEY="723A34A6E3300F23E4BAA06156B9327514AEC170732655F16E04C17928DD770F"
    ```

2.  **Prepare Directory**:
    ```bash
    mkdir -p patched_iso
    mkdir -p iso
    mount -o loop,ro mikrotik-6.42.6.iso iso/
    cp -r iso/* patched_iso/
umount iso/
chmod -R u+w patched_iso/
rm -rf squashfs-root  # Clean up if exists
    ```

3.  **Patch Kernel (initrd)**:
    ```bash
    python3 patch.py kernel patched_iso/isolinux/initrd.rgz
    ```

4.  **Patch NPK Packages**:
    ```bash
    for file in patched_iso/*.npk; do
      echo "Patching $file"
      python3 patch.py npk "$file"
    done
    ```
    *Note: `system-6.42.6.npk` is automatically handled during the initrd patching step in some workflows, but running it here ensures consistency.*

5.  **Create ISO**:
    ```bash
    mkisofs -o mikrotik-6.42.6-patched.iso \
             -V "MikroTik 6.42.6" \
             -sysid "" -preparer "MiKroTiK" \
             -publisher "" -A "MiKroTiK RouterOS" \
             -input-charset utf-8 \
             -b isolinux/isolinux.bin \
             -c isolinux/boot.cat \
             -no-emul-boot \
             -boot-load-size 4 \
             -boot-info-table \
             -R -J \
             -quiet \
             patched_iso/
    ```

## Patch install-image

```bash
cp install-image.img install-image-$VERSION-patched.img
modprobe nbd
qemu-nbd -c /dev/nbd0 -f raw install-image-$VERSION-patched.img
mkdir ./install-image
mount /dev/nbd0 ./install-image
cp ../refind-bin-0.14.2/refind/refind_x64.efi ./install-image/EFI/BOOT/BOOTX64.EFI
cp ./BOOTX64.EFI ./install-image/linux
NPK_FILES=($(find ./all_packages/*.npk))
for ((i=1; i<=${#NPK_FILES[@]}; i++))
do
  echo "${NPK_FILES[$i-1]}=>$i.npk" 
  cp ${NPK_FILES[$i-1]} ./install-image/$i.npk
done
umount /dev/nbd0
qemu-nbd -d /dev/nbd0
rm -rf ./install-image

qemu-img convert -f raw -O qcow2 install-image-$VERSION-patched.img install-image-$VERSION-patched.qcow2
qemu-img convert -f raw -O vmdk install-image-$VERSION-patched.img install-image-$VERSION-patched.vmdk
qemu-img convert -f raw -O vpc install-image-$VERSION-patched.img install-image-$VERSION-patched.vhd
qemu-img convert -f raw -O vhdx install-image-$VERSION-patched.img install-image-$VERSION-patched.vhdx
qemu-img convert -f raw -O vdi install-image-$VERSION-patched.img install-image-$VERSION-patched.vdi
```

## Patch Cloud Hosted Router

```bash
cp chr.img chr-$VERSION-patched.img
modprobe nbd
qemu-nbd -c /dev/nbd0 -f raw chr-$VERSION-patched.img
mkdir -p ./chr/{boot,routeros}
mount /dev/nbd0p1 ./chr/boot/
mkdir -p ./chr/boot/BOOT
cp ./BOOTX64.EFI ./chr/boot/EFI/BOOT/BOOTX64.EFI
extlinux --install -H 64 -S 32 ./chr/boot/BOOT
echo -e "default system\nlabel system\n\tkernel /EFI/BOOT/BOOTX64.EFI\n\tappend load_ramdisk=1 root=/dev/ram0 quiet" > syslinux.cfg
cp syslinux.cfg ./chr/boot/BOOT/
rm syslinux.cfg
umount /dev/nbd0p1
mount /dev/nbd0p2 ./chr/routeros/
cp ./all_packages/routeros-$VERSION.npk ./chr/routeros/var/pdb/system/image
umount /dev/nbd0p2
qemu-nbd -d /dev/nbd0
rm -rf ./chr

qemu-img convert -f raw -O qcow2 chr-$VERSION-patched.img chr-$VERSION-patched.qcow2
qemu-img convert -f raw -O vmdk chr-$VERSION-patched.img chr-$VERSION-patched.vmdk
qemu-img convert -f raw -O vpc chr-$VERSION-patched.img chr-$VERSION-patched.vhd
qemu-img convert -f raw -O vhdx chr-$VERSION-patched.img chr-$VERSION-patched.vhdx
qemu-img convert -f raw -O vdi chr-$VERSION-patched.img chr-$VERSION-patched.vdi
```

## Patch Netinstall

```bash
wget https://download.mikrotik.com/routeros/$VERSION/netinstall-$VERSION.zip
unzip netinstall-$VERSION.zip
python3 patch.py netinstall netinstall.exe
zip netinstall-$VERSION-patched.zip netinstall.exe
rm netinstall-$VERSION.zip netinstall.exe LICENSE.txt
```
