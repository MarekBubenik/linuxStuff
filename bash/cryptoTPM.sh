#!/bin/bash
# Author: Marek Bubeník
# Date: 27.09.2024
# About part 1: Rotate keyfiles for LUKS partition, generate and  enroll keys for TPM, generate new image and update grub
# About part 2: Generate private and public keys, enroll public key to MOK list, sign kernel/GRUB/kernel modules with keys
#
#
# Pre-requisites we need for to sign kernel modules
# SBPKGS="shim-signed sbsigntool build-essentials dkms linux-headers-$(uname -r) efivar"
# shim-signed                   Secure Boot chain-loading bootloader (Microsoft-signed binary)
# sbsigntool                    Tools to manipulate signatures on UEFI binaries and drivers
# build-essentials              Contains a list of packages that are required to create a Debian package (deb)
# dkms                          Program/framework that enables generating Linux kernel modules whose sources generally reside outside the kernel source tree
# linux-headers-$(uname -r)     Package providing the Linux kernel headers (The headers act as an interface between internal kernel components and also between userspace and the kernel)
# efivar                        Tools to manage UEFI variables
#
#

OLDKEYFILE="VM_123"
TMPDIR="/tmp/keys"
PKGS=(dracut tpm2-tools)
CRYPTOPART=$(blkid -t TYPE=crypto_LUKS | cut -d ":" -f 1)       # determine LUKS partition

##########
# Part 1 #
##########

pkgsInstall () {
    # install packages
    apt -y -qq install "${PKGS[@]}"
}

keyfileGen () {
    # keyfile generator
    if [[ "$CRYPTOPART" ]];then
        mkdir -p $TMPDIR
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
        echo "##############################"
        echo "Keyfiles successfully changed!"
        echo "##############################"
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
            rm -rf /tmp/keys
            echo "######################################"
            echo "Keyfile successfully enrolled for TPM!"
            echo "######################################"
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

genPrivKeys () {
    # Generate the public and private key pair
    echo ""
}

keyMokEnroll () {
    # Enrolling public key on target system by adding the public key to the MOK list
    echo ""
}

signFunc () {
    # Signing a kernel with the private key
    echo ""

    # Signing a GRUB build with the private key
    echo ""

    # Signing kernel modules with the private key
    echo ""

}

executeFunc () {
    pkgsInstall
    keyfileGen
    keyRotate
    keyTpmEnroll
    imageReg
    genPrivKeys
    keyMokEnroll
    signFunc
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