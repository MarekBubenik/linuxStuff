#!/bin/bash
# Author: Marek Bubeník
# Date: 27.09.2024
# About part 1: Rotate keyfiles for LUKS partition, generate and enroll keys for TPM, generate new image and update grub
# About part 2: Generate private and public keys, enroll public key to MOK list, sign kernel/GRUB/kernel modules with keys
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

OLDKEYFILE="VM_123"
TMPDIR="/tmp/keys"
MOKDIR="/usr/lib/mok"
PKGS=(shim-signed sbsigntool build-essential dkms linux-headers-"$(uname -r)" efivar tpm2-tools) #dracut
CRYPTOPART=$(blkid -t TYPE=crypto_LUKS | cut -d ":" -f 1)       # determine LUKS partition

##########
# Part 1 #
##########

pkgsInstall () {
    # install packages
    apt -y -qq install "${PKGS[@]}"
    mkdir -p $TMPDIR
    mkdir -p $MOKDIR
}

keyfileGen () {
    # keyfile generator
    if [[ "$CRYPTOPART" ]];then
        printf %s "$OLDKEYFILE" | install -m 0600 /dev/stdin $TMPDIR/old_keyfile.key
        dd bs=512 count=4 if=/dev/random iflag=fullblock | install -m 0600 /dev/stdin $TMPDIR/new_keyfile.key
        echo "###################"
        echo "Keyfiles generated!"
        echo "###################"
    fi
}

keyRotate () {
    # rotate passphrase with the new keyfile
    if [[ -d "$TMPDIR" ]];then
        cryptsetup luksChangeKey "$CRYPTOPART" --key-file $TMPDIR/old_keyfile.key $TMPDIR/new_keyfile.key
        echo "#################"
        echo "Keyfiles changed!"
        echo "#################"
    fi
}

keyTpmEnroll () {
    # generate keys for TPM
    # deletes tmp keyfiles
    # https://wiki.archlinux.org/title/Trusted_Platform_Module#Accessing_PCR_registers
    for key in "$TMPDIR"/*.key
    do
        if [ -f "$key" ];then
            systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7+11 --unlock-key-file=$TMPDIR/new_keyfile.key "$CRYPTOPART"
            #rm -rf /tmp/keys
            echo "#########################"
            echo "Keyfile enrolled for TPM!"
            echo "#########################"
        fi
    done
}

imageReg () {
    # rd.auto / enable auto assembly of special devices like cryptoLUKS, dmraid, mdraid or lvm
    # rd.luks=1 / enable crypto LUKS detection
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="rd.auto rd.luks=1"/g' /etc/default/grub

    # systemd-cryptenroll puts the list of PCRs in the LUKS header, comment out for automatic decryption by TPM
    sed -i 's/^/# /' /etc/crypttab

    # adding modules before building a new initramfs image
    echo "add_dracutmodules+=\" tpm2-tss crypt \"" >> /etc/dracut.conf

    dracut -f
    update-grub
}

##########
# Part 2 #
##########

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
#
shimFunc () {
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


# sbsign --key /usr/lib/mok/$(uname -n).key --cert /usr/lib/mok/$(uname -n).crt --output /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r)
# cd /usr/lib/modules/$(uname -r) || exit
# find . -name *.ko -exec /usr/lib/modules/$(uname -r)/source/scripts/sign-file sha256 /usr/lib/mok/$(uname -n).key /usr/lib/mok/$(uname -n).cer {} \;
# update-initramfs -u

# # SBAT
# echo "sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\ngrub,3,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/\ngrub.ubuntu,1,Ubuntu,grub2,2.06-2ubuntu14.1,https://www.ubuntu.com/" > /usr/share/grub/sbat.csv

# gpg --gen-key
# gpg --export 0EFB3D9489462E0A3D7DA33D3AD202800BE568FE | sudo tee /usr/lib/mok/$(uname -n).asc > /dev/null

# # Sign GRUB modules
# cd /usr/lib/grub/x86_64-efi
# sudo find . -name "*.mod" -exec gpg --detach-sign {} \;
# sudo find . -name "*.lst" -exec gpg --detach-sign {} \;
# sudo find . -name "*.img" -exec gpg --detach-sign {} \;
# # Sign GRUB
# cd /boot/grub
# sudo find . -type f -exec gpg --detach-sign {} \;
# # Sign kernel
# cd /boot/
# sudo find . -name "vmlinuz*" -exec gpg --detach-sign {} \;
# sudo find . -name "initrd*" -exec gpg --detach-sign {} \;


# Initial skeleton config to bootstrap grub
# Enforce checking signatures on all loaded files

# set check_signatures=enforce
# export check_signatures
# insmod part_gpt
# insmod ext2
# set root='hd0,gpt2'
# if [ x$feature_platform_search_hint = xy ]; then
#   search --no-floppy --fs-uuid --set=root --hint-bios=hd0,gpt2 --hint-efi=hd0,gpt2 --hint-baremetal=ahci0,gpt2  c8c39dcd-6333-4fda-8036-d757243f781c
# else
#   search --no-floppy --fs-uuid --set=root c8c39dcd-6333-4fda-8036-d757243f781c
# fi

# configfile /grub/grub.cfg



signFunc () {
    # Signing a kernel with the private key
    # Optional: Check the signatures: pesign --show-signature --in /root/vmlinuz-"$(uname -r)".signed
    pesign -c 'Custom Secure Boot key' --in /boot/vmlinuz-"$(uname -r)" --out /root/vmlinuz-"$(uname -r)".signed --sign
    mv /root/vmlinuz-"$(uname -r)".signed /boot/vmlinuz-"$(uname -r)"

    # Signing a GRUB build with the private key
    # Optional: Check the signatures: pesign --in /root/grubx64.efi.signed --show-signature
    pesign -c 'Custom Secure Boot key' --in /boot/efi/EFI/debian/grubx64.efi --out /root/grubx64.efi.signed  --sign
    mv /root/grubx64.efi.signed /boot/efi/EFI/debian/grubx64.efi

    # Signing kernel modules with the private key
    echo ""

}

executeFunc () {
    pkgsInstall
    #keyfileGen
    #keyRotate
    #keyTpmEnroll
    #imageReg
    shimFunc
    genPrivKeys
    keyMokEnroll
    #signFunc
}


# Check if script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root.  Try:
        sudo $0
        "
    exit 1
fi

executeFunc


# TODO!
# play with TPM PCRs, try other combinations
# https://wiki.debian.org/SecureBoot
#