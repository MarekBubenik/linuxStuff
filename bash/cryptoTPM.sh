#!/bin/bash
#
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

PKGS=(dracut tpm2-tools)
CRYPTOPART=$(blkid -t TYPE=crypto_LUKS | cut -d ":" -f 1)       # determine LUKS partition

# install packages from $PKGS
pkgsFunc () {
        apt -y install "${PKGS[@]}"
}

# random string generator
# number 20 determine how long the string is going to be
passGenFunc () {
        # array=()
        # for i in {a..z} {A..Z} {0..9};
        #         do
        #         array[$RANDOM]=$i
        # done
        # printf %s "${array[@]::20}" > /root/old_keyfile.key
        mkdir -p /tmp/keys
        printf "VM_123" | install -m 0600 /dev/stdin /tmp/keys/old_keyfile.key
        dd bs=512 count=4 if=/dev/random iflag=fullblock | install -m 0600 /dev/stdin /tmp/keys/new_keyfile.key
}

# rotate passphrase on LUKS partition
passRotateFunc () {
    if [ "$CRYPTOPART" ];then
        #cryptsetup luksChangeKey "$CRYPTOPART" --key-file ./oldpass.txt --new-keyfile ./newpass.txt
        cryptsetup luksAddKey "$CRYPTOPART" --new-keyfile /tmp/keys/new_keyfile.key --key-file /tmp/keys/old_keyfile.key
        cryptsetup luksKillSlot "$CRYPTOPART" 0 --key-file /tmp/keys/new_keyfile.key
        echo "################################################"
        echo "Passphrase successfully changed! New keyslot = 1"
        echo "################################################"
    fi
}

# generate keys for TPM
# new passphrase is passed
# deletes temp keyfiles
# https://wiki.archlinux.org/title/Trusted_Platform_Module#Accessing_PCR_registers
passTpmFunc () {
    systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7+11 --unlock-key-file=/tmp/keys/new_keyfile.key "$CRYPTOPART"
    rm -rf /tmp/keys
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

pkgsFunc
passGenFunc
passRotateFunc
passTpmFunc
imageReg

# TODO!
# figure out keyslot, why there is 0 and not just 1
# play with TPM PCRs, try other combinations
# https://wiki.debian.org/SecureBoot
#