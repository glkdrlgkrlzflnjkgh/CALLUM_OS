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

# Tools (override via env if needed)
CC="${CC:-gcc}"
LD="${LD:-ld}"
AS="${AS:-gcc}"          # switch to nasm if you want: AS=nasm
GRUB_MKRESCUE="${GRUB_MKRESCUE:-grub-mkrescue}"
DD="${DD:-dd}"
QEMU="${QEMU:-qemu-system-i386}"

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
}

#######################################
# Build steps
#######################################

prepare_dirs() {
    log "Preparing directories..."
    mkdir -p "$BUILD_DIR"
    mkdir -p "$GRUB_DIR"
}

compile_kernel() {
    log "Compiling kernel.c..."
    "$CC" -m32 -O0 -g -Wall -Wextra \
        -ffreestanding -fno-pic -fno-pie \
        -fno-stack-protector -fno-asynchronous-unwind-tables \
        -c "$SRC_DIR/kernel.c" -o "$BUILD_DIR/kernel.o"
    ok "kernel.c compiled"
}

compile_irq_stubs() {
    log "Compiling irq.S..."
    # If you switch to NASM:
    #   AS=nasm ./build.sh
    # and replace this with:
    #   nasm -f elf32 "$SRC_DIR/irq.S" -o "$BUILD_DIR/irq_stubs.o"
    if [[ "$AS" == "nasm" ]]; then
        nasm -f elf32 "$SRC_DIR/irq.S" -o "$BUILD_DIR/irq_stubs.o"
    else
        "$AS" -m32 -c "$SRC_DIR/irq.S" -o "$BUILD_DIR/irq_stubs.o"
    fi
    ok "irq.S compiled"
}

link_kernel() {
    log "Linking kernel with linker.ld..."
    "$LD" -m elf_i386 -nostdlib -T "$SRC_DIR/linker.ld" \
        -o "$KERNEL_ELF" \
        "$BUILD_DIR/kernel.o" "$BUILD_DIR/irq_stubs.o"
    ok "kernel.elf linked"
}

prepare_iso_tree() {
    log "Preparing ISO tree..."
    mkdir -p "$ISO_DIR/boot"
    cp "$KERNEL_ELF" "$ISO_DIR/boot/"

    local grub_cfg="$GRUB_DIR/grub.cfg"
    if [[ ! -f "$grub_cfg" ]]; then
        log "Creating minimal grub.cfg..."
        cat > "$grub_cfg" <<EOF
set timeout=0
set default=0

menuentry "CallumOS" {
    multiboot /boot/kernel.elf
    boot
}
EOF
    fi
    ok "ISO tree ready"
}

build_iso() {
    log "Building bootable ISO: $ISO_NAME"
    "$GRUB_MKRESCUE" -o "$ISO_NAME" "$ISO_DIR"
    ok "ISO built: $ISO_NAME"
}

create_disk_image() {
    log "Creating bootable virtual disk: $DISK_IMG"
    "$DD" if="$ISO_NAME" of="$DISK_IMG" bs=4M status=progress conv=fsync
    ok "Disk image created: $DISK_IMG"
}

run_qemu() {
    command -v "$QEMU" >/dev/null 2>&1 || error "QEMU not found; install qemu-system-i386 or set QEMU env var"
    [[ -f "$DISK_IMG" ]] || error "Disk image '$DISK_IMG' not found. Run '$0 all' first."
    log "Launching QEMU..."
    "$QEMU" -cdrom "$DISK_IMG" -boot d -m 256M
}

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
  all       Build kernel, ISO, and disk image (default)
  iso       Build only the ISO (requires compiled kernel)
  disk      Build only the disk image from existing ISO
  run       Run QEMU with the built disk image
  clean     Remove build artifacts
  help      Show this help

Examples:
  $0
  $0 all
  $0 run
  $0 clean
EOF
}

main() {
    local cmd="${1:-all}"

    case "$cmd" in
        all)
            check_env
            prepare_dirs
            compile_kernel
            compile_irq_stubs
            link_kernel
            prepare_iso_tree
            build_iso
            create_disk_image
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
            [[ -f "$ISO_NAME" ]] || error "ISO '$ISO_NAME' not found. Run '$0 all' first."
            create_disk_image
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
