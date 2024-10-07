#!/bin/bash
# Author: Marek Bubeník
# Date: 27.09.2024
# About part 1: Rotate keyfiles for LUKS partition, generate and enroll keys for TPM via clevis, generate new initramfs and update grub
# 
#

OLDKEYFILE="VM_123"
TMPDIR="/tmp/keys"
PKGS=(clevis clevis-tpm2 clevis-luks initramfs-tools clevis-initramfs)  # tss2 tpm2-tools
CRYPTOPART=$(blkid -t TYPE=crypto_LUKS | cut -d ":" -f 1)   # determine LUKS partition

# Supply optional parameter $1 for keyphrase
if [[ -n "$1" ]];then 
    OLDKEYFILE=$1
fi

preReq () {
    # Secure boot check
    SBENB=$(mokutil --sb)
    if [[ $SBENB =~ "enabled" ]];then
        echo "Secure boot       -   [ detected ]"
    else
        echo "Secure boot not detected, enable Secure boot in UEFI settings! Exiting..."
        exit 1
    fi

    # LUKS partition check
    LUKSENB=$(blkid -t TYPE=crypto_LUKS)
    if [[ $LUKSENB ]];then
        echo "LUKS partition    -   [ detected ]"
    else
        echo "LUKS partition not detected, this script works only with LUKS encrypted partitions! Exiting..."
        exit 1
    fi

    # TPM 2.0 module check
    if [[ -c /dev/tpmrm0 ]];then
        echo "TPM 2.0 module    -   [ detected ]"
    else
        echo "TPM 2.0 module not detected, this script works only with TPM 2.0 enabled devices! Exiting..."
        exit 1
    fi
    sleep 3
    clear
}

pkgsInstall () {
    # install packages
    apt-get install -qq "${PKGS[@]}"
    mkdir -p $TMPDIR
    clear
}

keyGen () {
    # keyfile generator (20 length string)
    if [[ -d "$TMPDIR" ]];then
        array=()
        for i in {a..z} {A..Z} {0..9}; 
            do
            array["$RANDOM"]=$i
        done
        printf %s "${array[@]::20}" | install -m 0600 /dev/stdin $TMPDIR/new_keyfile.key
        printf %s "$OLDKEYFILE" | install -m 0600 /dev/stdin $TMPDIR/old_keyfile.key
    else
        echo "Temporary /tmp/keys directory not found - cannot generate temporary keyfiles! Exiting..."
        exit 1    
    fi
}

keyRotate () {
    # rotate passphrase with the new keyfile
    if [[ "$CRYPTOPART" ]];then
        cryptsetup luksChangeKey "$CRYPTOPART" --key-file $TMPDIR/old_keyfile.key $TMPDIR/new_keyfile.key
    else
        echo "LUKS partition not found - no LUKS keys has been changed! Exiting..."
        exit 1   
    fi
}

keyEnroll () {
    # clevis pass keys for TPM
    # deletes tmp keyfiles
    if [[ "$CRYPTOPART" ]];then
        LUKSKEY=$(<$TMPDIR/new_keyfile.key)
        clevis luks bind -d "$CRYPTOPART" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}' <<< "$LUKSKEY"
        sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="rd.emergency=reboot rd.shell=0 \1"/g' /etc/default/grub
        update-initramfs -u -k all
        update-grub
        rm -rf $TMPDIR       # uncomment just in case files wont delete from tmp folder after reboot
    else
        echo "LUKS partition not found - no LUKS keys has been passed to TPM! Exiting..."
        exit 1
    fi
}

executeFunc () {
    preReq
    pkgsInstall
    keyGen
    keyRotate
    keyEnroll
}

# Check if script is run as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "This script must be run as root.  Try:
        sudo $0
        "
    exit 1
fi

executeFunc

##########
# SOURCES
##########
#
# 
# https://wiki.archlinux.org/title/Trusted_Platform_Module#Accessing_PCR_registers
# https://221b.uk/safe-automatic-decryption-luks-partition-tpm2#background
# https://www.reddit.com/r/linuxquestions/comments/106ntat/comment/j3hwfdc/?utm_source=share&utm_medium=web3x&utm_name=web3xcss&utm_term=1&utm_content=share_button
# https://pulsesecurity.co.nz/advisories/tpm-luks-bypass
#
# The process generate a new independent secret, tying your LUKS partition to the TPM2 as an alternative decryption method.
# So if it does not work you may still just enter your decryption passphrase as usual.
# 
# On every update of your system that makes changes to the kernel, grub2 or initramfs you’ll have to rebind the TPM2, if you opted to use PCR 9. 
# CRYPTOPART=$(blkid -t TYPE=crypto_LUKS | cut -d ":" -f 1)
# clevis luks regen -q -d "$CRYPTOPART" -s 1 tpm2
#
#
#
#
