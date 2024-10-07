#!/bin/bash
# Author: Marek Bubeník
# Date: 27.09.2024
# About part 2: Generate private and public keys, enroll public key to MOK list, sign kernel/GRUB/kernel modules
#
#
# https://www.youtube.com/watch?v=Yfzn2zPp_f0
# https://medium.com/@allypetitt/digging-into-the-linux-secure-boot-process-9631a70b158b
#
#
# Secure Boot architecture
# ========================
# - Secure boot is a method of booting an operating system by verifying that all key operating system components are unaltered and digitally signed
# 
# Platform Key (PK)
# -----------------
# - Overall owner key for your machine, stored in UEFI = comes from device manufacturer
# - Ultimate signing rights over everything
# - Used to sign key exchange keys
#
# Key Exchange Keys (KEK)
# -----------------------
# - Used for updating two databases of keys that are stored in the UEFI:
#
#           db (signing keys)
#           -----------------
#           - keys that are actually used to sign stuff that boots
#
#           dbx (blocked keys)
#           ------------------
#           - keys that have been locked out / prohibited from being used to sign any kind of bootloader
#
# - PK signs KEK -> KEK signs db and dbx updates -> db and dbx updates installed in firmware
# - this builds a chain of trust that then allows secure boot to sign other things like GRUB bootloader
#
#
# Secure Boot with MS keys
# ========================
# - Uses shim bootloader EFI binary that is signed with Microsoft keys
# - shim introduces a new key store called Machine Owner Keys (MOK)
# - shim accepts bootloaders signed with MOKs
# - shim defaults to using GRUB
# (The "shim" loader is a small bootloader for UEFI based x86_64 machines. It is signed by the Microsoft UEFI CA, which is embedded in all UEFI BIOSes.)
# (provides a bridge to enroll keys yourself without tampering with anything else in the Secure Boot process)
#
#
# Secure Boot process with MS keys
# ================================
#   UEFI      -   checks signature on bootloader using db
#    |
#    V
#   shim      -   signed by MS key from db, checks signature on GRUB
#    |
#    V
#   GRUB      -   signed by MOK key, checks signature on kernel
#    |
#    V
#   Kernel    -   Signed by MOK key
#
#
# Pre-requisites we need for to sign kernel modules
# =================================================
# shim-signed                   Secure Boot chain-loading bootloader (Microsoft-signed binary)
# sbsigntool                    Tools to manipulate signatures on UEFI binaries and drivers
# build-essential               Contains a list of packages that are required to create a Debian package (deb)
# dkms                          Program/framework that enables generating Linux kernel modules whose sources generally reside outside the kernel source tree
# linux-headers-$(uname -r)     Package providing the Linux kernel headers (The headers act as an interface between internal kernel components and also between userspace and the kernel)
# efivar                        Tools to manage UEFI variables
#
#

OLDKEYFILE="VM_123"
TMPDIR="/tmp/keys"
MOKDIR="/usr/lib/mok"
PKGS=(shim-signed sbsigntool build-essential dkms linux-headers-"$(uname -r)" efivar)

pkgsInstall () {
    # install packages
    apt-get install -qq "${PKGS[@]}"
    mkdir -p $MOKDIR
}

shimFunc () {
    # shim bootloader, creates entry
    cd /usr/lib/shim/ || exit
    cp shimx64.efi.signed /boot/efi/EFI/debian/BOOTX64.EFI
    cp mmx64.efi.signed /boot/efi/EFI/debian/mmx64.efi  
    efibootmgr --unicode --disk /dev/sda --part 1 --create --label debian-signed --loader /EFI/debian/BOOTx64.efi
}

genPrivKeys () {
    # Generate the public and private key pair
    openssl req -newkey rsa:4096 -nodes -keyout /usr/lib/mok/"$(uname -n)".key -new -x509 -sha256 -days 3650 -subj "/CN=$(uname -n)-mok" -out /usr/lib/mok/"$(uname -n)".crt
    openssl x509 -outform DER -in /usr/lib/mok/"$(uname -n)".crt -out /usr/lib/mok/"$(uname -n)".cer
}

keyMokEnroll () {
    # Enrolling public key on target system by adding the public key to the MOK list
    # Optional: Check enrolled keys: mokutil --list-enrolled
    mokutil --generate-hash=$OLDKEYFILE > $TMPDIR/hashfile
    mokutil --import /usr/lib/mok/"$(uname -n)".cer --hash-file $TMPDIR/hashfile
    rm -rf $TMPDIR/hashfile
}

signKernelAndModules () {
    # Sign kernel with MOK key
    sbsign --key /usr/lib/mok/"$(uname -n)".key --cert /usr/lib/mok/"$(uname -n)".crt --output /boot/vmlinuz-"$(uname -r)" /boot/vmlinuz-"$(uname -r)"
    # Sign kernel modules with MOK key
    cd /usr/lib/modules/"$(uname -r)" || exit
    find . -name *.ko -exec /usr/lib/modules/"$(uname -r)"/source/scripts/sign-file sha256 /usr/lib/mok/"$(uname -n)".key /usr/lib/mok/"$(uname -n)".cer {} \;
    # Rebuild initramfs
    update-initramfs -u -k all
}

# TODO: incorporate into /etc/kernel/postinst.d/initramfs-tools ????


# Restrictions
# ============
# - GRUB
#       - All GRUB modules must be contained in GRUB EFI image
#       - All files loaded from disk must be signed by GRUB GPG key
#       - Requires Secure Boot Advanced Targeting (SBAT)
#
# - Kernel lockdown mode
#       - All kernel modules must be signed
#       - Hibernation is disabled
#

# # SBAT
# #echo "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\ngrub,3,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/\ngrub.ubuntu,1,Ubuntu,grub2,2.06-2ubuntu14.1,https://www.ubuntu.com/" > /usr/share/grub/sbat.csv

genSbat () {
    echo "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\ngrub,1,Free Software Foundation,grub,2.04,https://www.gnu.org/software/grub/\grub.debian,1,Debian,grub2,2.04-12,https://packages.debian.org/source/sid/grub2" > /usr/share/grub/sbat.csv
}

# STOP HERE #
genGpgKeys () {
    echo "error"
    exit 1
    # gpg --gen-key
    # gpg --export xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | sudo tee /usr/lib/mok/$(uname -n).asc > /dev/null
}
# STOP HERE #

signGrubModules () {
    # unSign GRUB modules
    cd /usr/lib/grub/x86_64-efi || exit
    sudo find . -name "*.mod" -exec gpg --detach-sign {} \;
    sudo find . -name "*.lst" -exec gpg --detach-sign {} \;
    sudo find . -name "*.img" -exec gpg --detach-sign {} \;
}

signGrub () {
    # unSign GRUB
    cd /boot/grub || exit
    sudo find . -type f -exec gpg --detach-sign {} \;
}

signKernel () {
    # unSign kernel
    cd /boot/ || exit
    sudo find . -name "vmlinuz*" -exec gpg --detach-sign {} \;
    sudo find . -name "initrd*" -exec gpg --detach-sign {} \;
} 

grubInitial () {
    echo "
    #Initial skeleton config to bootstrap grub
    #Enforce checking signatures on all loaded files

    set check_signatures=enforce
    export check_signatures
    insmod part_gpt
    insmod ext2
    set root='hd0,gpt2'
    if [ x$feature_platform_search_hint = xy ]; then
    search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  c8c39dcd-6333-4fda-8036-d757243f781c
    else
    search --no-floppy --fs-uuid --set=root c8c39dcd-6333-4fda-8036-d757243f781c
    fi 
    
    configfile /grub/grub.cfg" > /boot/grub/grub-initial.cfg
}

grubMkStandalone () {
    GRUB_MODULES="acpi all_video boot btrfs cat chain configfile echo efifwsetup efinet ext2 fat font gettext gfxmenu gfxterm gfxterm_background gzio halt help hfsplus iso9660 jpeg keystatus loadenv loopback linux ls lsefi lsefimmap lsefisystab lssal memdisk minicmd normal ntfs part_apple part_msdos part_gpt password_pbkdf2 png probe reboot regexp search search_fs_uuid search_fs_file search_label sleep smbios squash4 test true video xfs zfs zfscrypt zfsinfo cpuid linuxefi play tpm cryptodisk gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5 gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268 gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256 gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool luks lvm efi_uga efi_gop crypto disk diskfilter pcidump setpci lspci"
    GRUB_DIR="/usr/lib/grub/x86_64-efi"
    GRUB_PUB_KEY="/usr/lib/mok/$(uname -n).asc"
    GRUB_SBAT="/usr/share/grub/sbat.csv"
    GRUB_OUTPUT="/root/grubx64.efi"
    GRUB_INIT_CONFIG="/boot/grub/grub-initial.cfg"
    grub-mkstandalone --directory "$GRUB_DIR" --format x86_64-efi --modules "$GRUB_MODULES" --pubkey "$GRUB_PUB_KEY" --sbat "$GRUB_SBAT" --output "$GRUB_OUTPUT" "boot/grub/grub.cfg=$GRUB_INIT_CONFIG"
    cp /root/grubx64.efi /boot/efi/EFI/debian/
}

signNewGrubImage () {
    sbsign --key /usr/lib/mok/"$(uname -n)".key --cert /usr/lib/mok/"$(uname -n)".crt --output /boot/efi/EFI/debian/grubx64.efi /boot/efi/EFI/debian/grubx64.efi
}

# final
executeFunc () {
    pkgsInstall
    shimFunc
    genPrivKeys
    keyMokEnroll
    signKernelAndModules
    genSbat
    genGpgKeys
    signGrubModules
    signGrub
    signKernel
    grubInitial
    grubMkStandalone
    signNewGrubImage
}

# Check if script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root.  Try:
        sudo $0
        "
    exit 1
fi

executeFunc