# MikrotikPatchOld (v6 Legacy)

Tools untuk melakukan patching MikroTik RouterOS v6 (khususnya versi lama seperti 6.42.6) agar dapat menggunakan lisensi custom.

## Fitur
*   **Patch ISO:** Memodifikasi installer ISO agar menerima kunci publik custom.
*   **Patch CHR:** Memodifikasi image disk CHR (Cloud Hosted Router) baik partisi boot (kernel) maupun paket sistem.
*   **Patch All Packages:** Memodifikasi seluruh paket tambahan (`all_packages`) agar kompatibel.
*   **Image Conversion:** Konversi otomatis image CHR ke format VM lain (VDI, VMDK, VHDX).
*   **Keygen:** Generate kunci ECDSA custom.
*   **License Gen:** Membuat lisensi valid (Level 1/P1, Level 6/Unlimited) untuk sistem yang sudah di-patch.

## Struktur File
*   `patch.py`: Script utama untuk memodifikasi binary (initrd, npk, block device).
*   `mikro.py` & `toyecc/`: Library kriptografi.
*   `npk.py`: Manipulasi format paket NPK.
*   `license.py`: Generator lisensi.

## Persiapan
Install dependencies Python:
```bash
pip install -r requirements.txt
```
Install system tools (Debian/Ubuntu):
```bash
sudo apt-get install -y wget unzip mkisofs qemu-utils e2fsprogs mtools
```

## Penggunaan

### 1. Setup Environment Variables (Keys)
Anda harus meng-export kunci publik/privat berikut (Gunakan nilai ini atau generate sendiri):
```bash
# Kunci Publik Asli MikroTik
export MIKRO_NPK_SIGN_PUBLIC_KEY="C275D7235766AEC866D4C59573C8E188A51339936E94D2CCF11F9FF5BAED7137"
export MIKRO_LICENSE_PUBLIC_KEY="8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"
export MIKRO_CLOUD_PUBLIC_KEY="8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"

# Kunci Custom (Gunakan Private Key Anda untuk generate lisensi)
export CUSTOM_NPK_SIGN_PRIVATE_KEY="7D008D9B80B036FB0205601FEE79D550927EBCA937B7008CC877281F2F8AC640"
export CUSTOM_NPK_SIGN_PUBLIC_KEY="28F886E32C141123126CFBCAD56766E99D1720CEB1F12BE2468BEBE7662FBEDB"
export CUSTOM_LICENSE_PRIVATE_KEY="9DBC845E9018537810FDAE62824322EEE1B12BAD81FCA28EC295FB397C61CE0B"
export CUSTOM_LICENSE_PUBLIC_KEY="723A34A6E3300F23E4BAA06156B9327514AEC170732655F16E04C17928DD770F"
export CUSTOM_CLOUD_PUBLIC_KEY="723A34A6E3300F23E4BAA06156B9327514AEC170732655F16E04C17928DD770F"
```

### 2. Patching ISO (Installer)
1.  Extract ISO asli.
2.  Patch `initrd.rgz`.
3.  Patch semua file `.npk`.
4.  Rebuild ISO.

### 3. Patching CHR (Disk Image)
1.  Extract partisi Boot (P1) dan System (P2).
2.  **P1 (Boot):** Patch kernel `initrd.rgz` secara langsung (block patch).
3.  **P2 (System):** Extract paket `routeros-x86` (atau `system`), patch, dan inject kembali.
4.  Gabungkan kembali partisi.

### 4. Patching All Packages
1.  Download zip `all_packages`.
2.  Extract.
3.  Jalankan `python3 patch.py npk <file>` untuk setiap `.npk`.

### 5. Konversi Image (CHR)
Setelah mendapatkan `chr-patched.img`:
```bash
qemu-img convert -f raw -O vmdk chr-patched.img chr-patched.vmdk
qemu-img convert -f raw -O vdi chr-patched.img chr-patched.vdi
qemu-img convert -f raw -O vhdx chr-patched.img chr-patched.vhdx
```

### 6. Generate Lisensi
Gunakan `license.py` dengan kunci privat Anda.
*   **P1 (Level 1):** `python3 license.py licgenchr <SYSTEM_ID> $CUSTOM_LICENSE_PRIVATE_KEY`

## GitHub Workflow
Repository ini dilengkapi `.github/workflows/patch_v6.yml` yang otomatis:
1.  Download ISO, CHR, dan All Packages.
2.  Patch semua file.
3.  Konversi CHR ke VMDK/VDI/VHDX.
4.  Upload hasilnya sebagai Artifact.
