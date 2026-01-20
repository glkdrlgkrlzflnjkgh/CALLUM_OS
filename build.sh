#!/usr/bin/env bash
set -euo pipefail

#######################################
# Configuration
#######################################

# Paths
SRC_DIR="src/kernel"
BUILD_DIR="build"
ISO_DIR="iso"
GRUB_DIR="$ISO_DIR/boot/grub"

# Artifacts
KERNEL_ELF="$BUILD_DIR/kernel.elf"
ISO_NAME="CallumOS.iso"
DISK_IMG="disk.img"
DISK_SIZE_MB="${DISK_SIZE_MB:-64}"   # size of disk image
MNT_DIR="${MNT_DIR:-/mnt/callumos}"  # temp mountpoint for FAT32

# Tools (override via env if needed)
CC="${CC:-gcc}"
LD="${LD:-ld}"
AS="${AS:-gcc}"          # switch to nasm if you want: AS=nasm
GRUB_MKRESCUE="${GRUB_MKRESCUE:-grub-mkrescue}"
DD="${DD:-dd}"
QEMU="${QEMU:-qemu-system-i386}"
PARTED="${PARTED:-parted}"
LOSETUP="${LOSETUP:-losetup}"
MKFS_VFAT="${MKFS_VFAT:-mkfs.vfat}"
RSYNC="${RSYNC:-rsync}"

# Flags (tweak as needed)
CFLAGS="${CFLAGS:--m32 -O0 -g -Wall -Wextra -ffreestanding -fno-pic -fno-pie -fno-stack-protector -fno-asynchronous-unwind-tables}"
ASFLAGS="${ASFLAGS:--m32 -g}"
LDFLAGS="${LDFLAGS:--m elf_i386 -nostdlib}"

#######################################
# Utility functions
#######################################

log() {
    printf '[*] %s\n' "$*"
}

ok() {
    printf '[+] %s\n' "$*"
}

error() {
    printf '[-] ERROR: %s\n' "$*" >&2
    exit 1
}

check_tool() {
    local tool="$1"
    command -v "$tool" >/dev/null 2>&1 || error "Required tool '$tool' not found in PATH"
}

require_root_for_disk_ops() {
    if [[ "$(id -u)" -ne 0 ]]; then
        error "Disk image creation requires root (loop devices, partitioning, mount). Re-run with: sudo $0 $*"
    fi
}

#######################################
# Environment checks
#######################################

check_env() {
    log "Checking required tools..."
    check_tool "$CC"
    check_tool "$LD"
    check_tool "$AS"
    check_tool "$GRUB_MKRESCUE"
    check_tool "$DD"
    check_tool "$PARTED"
    check_tool "$LOSETUP"
    check_tool "$MKFS_VFAT"
    check_tool "$RSYNC"
}

#######################################
# Build steps
#######################################

prepare_dirs() {
    log "Preparing directories..."
    mkdir -p "$BUILD_DIR"
    mkdir -p "$GRUB_DIR"
}

# Compile all sources under SRC_DIR (.c, .S, .s).
compile_sources() {
    log "Scanning source directory for .c/.S/.s files..."
    local src rel obj ext
    local -a objects=()

    mapfile -t sources < <(find "$SRC_DIR" -type f \( -name '*.c' -o -name '*.S' -o -name '*.s' \) -print)

    if [[ ${#sources[@]} -eq 0 ]]; then
        error "No source files (.c, .S, .s) found in $SRC_DIR"
    fi

    for src in "${sources[@]}"; do
        rel="${src#"$SRC_DIR"/}"
        obj="$BUILD_DIR/${rel//\//_}"
        obj="${obj%.*}.o"

        mkdir -p "$(dirname "$obj")" || true

        ext="${src##*.}"

        case "$ext" in
            c)
                log "Compiling C: $src -> $obj"
                "$CC" $CFLAGS -c "$src" -o "$obj"
                ;;
            S|s)
                log "Assembling: $src -> $obj"
                if [[ "${AS##*/}" == "nasm" ]]; then
                    nasm -f elf32 "$src" -o "$obj"
                else
                    "$AS" $ASFLAGS -c "$src" -o "$obj"
                fi
                ;;
            *)
                log "Skipping unknown file type: $src"
                continue
                ;;
        esac

        objects+=("$obj")
    done

    if [[ ${#objects[@]} -eq 0 ]]; then
        error "No object files produced; aborting"
    fi

    COMPILED_OBJECTS=("${objects[@]}")
    ok "Compiled ${#objects[@]} source(s)"
}

link_kernel() {
    log "Linking kernel with linker.ld..."
    if [[ -z "${COMPILED_OBJECTS[*]:-}" ]]; then
        mapfile -t COMPILED_OBJECTS < <(find "$BUILD_DIR" -maxdepth 1 -type f -name '*.o' -print || true)
    fi

    if [[ ${#COMPILED_OBJECTS[@]} -eq 0 ]]; then
        error "No object files to link. Run the build (all) to compile sources first."
    fi

    if [[ ! -f "$SRC_DIR/linker.ld" ]]; then
        error "Linker script not found: $SRC_DIR/linker.ld"
    fi

    "$LD" $LDFLAGS -T "$SRC_DIR/linker.ld" -o "$KERNEL_ELF" "${COMPILED_OBJECTS[@]}"
    ok "kernel.elf linked (${#COMPILED_OBJECTS[@]} objects)"
}

prepare_iso_tree() {
    log "Preparing ISO tree..."
    mkdir -p "$ISO_DIR/boot"
    cp "$KERNEL_ELF" "$ISO_DIR/boot/"

    local grub_cfg_root="$ISO_DIR/grub.cfg"
    local grub_cfg_boot="$GRUB_DIR/grub.cfg"

    if [[ -f "$grub_cfg_root" ]]; then
        log "Found existing grub.cfg at $grub_cfg_root — not creating or overwriting it."
    elif [[ -f "$grub_cfg_boot" ]]; then
        log "Found existing grub.cfg at $grub_cfg_boot — not creating or overwriting it."
    else
        log "No grub.cfg found in ISO tree; creating minimal grub.cfg at $grub_cfg_boot..."
        mkdir -p "$(dirname "$grub_cfg_boot")"
        cat > "$grub_cfg_boot" <<EOF
set timeout=0
set default=0

menuentry "CallumOS" {
    multiboot /boot/$(basename "$KERNEL_ELF")
    boot
}
EOF
        ok "Minimal grub.cfg created at $grub_cfg_boot"
    fi

    ok "ISO tree ready"
}

build_iso() {
    log "Building bootable ISO: $ISO_NAME"
    "$GRUB_MKRESCUE" -o "$ISO_NAME" "$ISO_DIR"
    ok "ISO built: $ISO_NAME"
}

#######################################
# FAT32 disk image creation
#######################################

create_fat32_disk_image() {
    require_root_for_disk_ops "disk"

    log "Creating raw disk image: $DISK_IMG (${DISK_SIZE_MB}MB)"
    "$DD" if=/dev/zero of="$DISK_IMG" bs=1M count="$DISK_SIZE_MB" status=progress conv=fsync

    log "Partitioning disk image with MBR + single FAT32 partition..."
    "$PARTED" -s "$DISK_IMG" mklabel msdos
    "$PARTED" -s "$DISK_IMG" mkpart primary fat32 1MiB 100%
    "$PARTED" -s "$DISK_IMG" set 1 boot on

    log "Attaching loop device..."
    local loopdev
    loopdev="$("$LOSETUP" --find --show --partscan "$DISK_IMG")"
    log "Using loop device: $loopdev"

    local part="${loopdev}p1"
    if [[ ! -b "$part" ]]; then
        part="$loopdev"
        log "Partition node not found; falling back to $part"
    fi

    log "Creating FAT32 filesystem on $part..."
    "$MKFS_VFAT" -F 32 -n "CALLUMOS" "$part"

    log "Mounting FAT32 filesystem at $MNT_DIR..."
    mkdir -p "$MNT_DIR"
    mount "$part" "$MNT_DIR"

    log "Copying ISO tree into FAT32 filesystem..."
    "$RSYNC" -a --no-owner --no-group --no-perms --delete "$ISO_DIR"/ "$MNT_DIR"/

    sync

    log "Installing GRUB into disk image via grub-install..."
    grub-install \
        --target=i386-pc \
        --boot-directory="$MNT_DIR/boot" \
        --modules="normal multiboot biosdisk part_msdos fat" \
        "$loopdev"

    sync
    log "Unmounting..."
    umount "$MNT_DIR"

    log "Detaching loop device..."
    "$LOSETUP" -d "$loopdev"

    ok "FAT32 disk image created and GRUB installed: $DISK_IMG"
}

#######################################
# QEMU
#######################################

run_qemu() {
    command -v "$QEMU" >/dev/null 2>&1 || error "QEMU not found; install qemu-system-i386 or set QEMU env var"
    [[ -f "$DISK_IMG" ]] || error "Disk image '$DISK_IMG' not found. Run '$0 all' first."
    log "Launching QEMU with disk image..."
    "$QEMU" -drive file="$DISK_IMG",format=raw -boot d -m 256M
}

#######################################
# Clean
#######################################

clean() {
    log "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR" "$ISO_DIR" "$ISO_NAME" "$DISK_IMG"
    ok "Clean complete"
}

#######################################
# CLI
#######################################

usage() {
    cat <<EOF
Usage: $0 [command]

Commands:
  all       Build kernel, ISO, and FAT32 disk image
  iso       Build only the ISO (requires compiled kernel)
  disk      Build only the FAT32 disk image from existing ISO (requires root)
  run       Run QEMU with the built disk image
  clean     Remove build artifacts
  help      Show this help

Examples:
  $0
  $0 all
  sudo $0 disk
  $0 run
  $0 clean

Notes:
  - If you already provide a grub.cfg anywhere in the iso tree (iso/grub.cfg or iso/boot/grub/grub.cfg),
    the script will NOT create or overwrite it.
  - Disk image creation uses a single MBR + FAT32 partition and copies the ISO tree into it.
  - Disk operations (partitioning, mkfs, mount) require root; use sudo for 'all' or 'disk' if needed.
  - You can override CC, LD, GRUB_MKRESCUE, DD, QEMU, PARTED, LOSETUP, MKFS_VFAT, RSYNC, and flags via environment.
EOF
}

main() {
    local cmd="${1:-all}"

    case "$cmd" in
        all)
            check_env
            prepare_dirs
            compile_sources
            link_kernel
            prepare_iso_tree
            build_iso
            create_fat32_disk_image
            ok "Build complete: $DISK_IMG"
            ;;
        iso)
            check_env
            prepare_dirs
            # assumes objects already built; you can force rebuild if you want
            link_kernel
            prepare_iso_tree
            build_iso
            ;;
        disk)
            check_env
            [[ -f "$ISO_NAME" ]] || error "ISO '$ISO_NAME' not found. Run '$0 all' or '$0 iso' first."
            create_fat32_disk_image
            ;;
        run)
            run_qemu
            ;;
        clean)
            clean
            ;;
        help|-h|--help)
            usage
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
