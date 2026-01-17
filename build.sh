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

# Compile all sources under SRC_DIR (.c, .S, .s). Object filenames are created
# from the source path relative to SRC_DIR, with '/' replaced by '_' to avoid
# collisions (e.g. src/kernel/foo/bar.c -> build/foo_bar.o).
compile_sources() {
    log "Scanning source directory for .c/.S/.s files..."
    local src
    local rel
    local obj
    local ext
    local -a objects=()

    # Find relevant source files
    mapfile -t sources < <(find "$SRC_DIR" -type f \( -name '*.c' -o -name '*.S' -o -name '*.s' \) -print)

    if [[ ${#sources[@]} -eq 0 ]]; then
        error "No source files (.c, .S, .s) found in $SRC_DIR"
    fi

    for src in "${sources[@]}"; do
        # Create a deterministic object filename based on relative path
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
                    # Use nasm for .S/.s if requested (nasm expects -f elf32 for 32-bit)
                    nasm -f elf32 "$src" -o "$obj"
                else
                    "$AS" $ASFLAGS -c "$src" -o "$obj"
                fi
                ;;
            *)
                # shouldn't get here due to find filter
                log "Skipping unknown file type: $src"
                continue
                ;;
        esac

        objects+=("$obj")
    done

    if [[ ${#objects[@]} -eq 0 ]]; then
        error "No object files produced; aborting"
    fi

    # Export objects as global variable for link step
    COMPILED_OBJECTS=("${objects[@]}")
    ok "Compiled ${#objects[@]} source(s)"
}

link_kernel() {
    log "Linking kernel with linker.ld..."
    if [[ -z "${COMPILED_OBJECTS[*]:-}" ]]; then
        # If COMPILED_OBJECTS isn't set, try to collect any existing .o files in build/
        mapfile -t COMPILED_OBJECTS < <(find "$BUILD_DIR" -maxdepth 1 -type f -name '*.o' -print || true)
    fi

    if [[ ${#COMPILED_OBJECTS[@]} -eq 0 ]]; then
        error "No object files to link. Run the build (all) to compile sources first."
    fi

    # Ensure linker script exists
    if [[ ! -f "$SRC_DIR/linker.ld" ]]; then
        error "Linker script not found: $SRC_DIR/linker.ld"
    fi

    # Link. Use LDFLAGS and explicit linker script.
    "$LD" $LDFLAGS -T "$SRC_DIR/linker.ld" -o "$KERNEL_ELF" "${COMPILED_OBJECTS[@]}"
    ok "kernel.elf linked (${#COMPILED_OBJECTS[@]} objects)"
}

prepare_iso_tree() {
    log "Preparing ISO tree..."
    mkdir -p "$ISO_DIR/boot"
    cp "$KERNEL_ELF" "$ISO_DIR/boot/"

    # Respect any existing grub configuration placed either at iso/grub.cfg
    # or iso/boot/grub/grub.cfg. Do NOT create or overwrite grub.cfg if present.
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

Notes:
  - If you already provide a grub.cfg anywhere in the iso tree (iso/grub.cfg or iso/boot/grub/grub.cfg),
    the script will NOT create or overwrite it.
  - Set AS=nasm if you prefer nasm for assembling .S/.s files.
  - You can override CC, LD, GRUB_MKRESCUE, DD, QEMU, and flags (CFLAGS/ASFLAGS/LDFLAGS) via environment.
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
