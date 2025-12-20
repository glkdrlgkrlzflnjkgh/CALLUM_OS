#!/bin/bash
set -e

# Paths
SRC_DIR=src/kernel
BUILD_DIR=build
ISO_DIR=iso

# Ensure build and iso directories exist
mkdir -p "$BUILD_DIR"
mkdir -p "$ISO_DIR/boot/grub"

echo "[1] Compiling kernel.c..."
gcc -m32 -O0 -g -ffreestanding -fno-pic -fno-pie \
    -fno-stack-protector -fno-asynchronous-unwind-tables \
    -c "$SRC_DIR/kernel.c" -o "$BUILD_DIR/kernel.o"

echo "[2] Compiling irq.S..."
gcc -m32 -c "$SRC_DIR/irq.S" -o "$BUILD_DIR/irq_stubs.o"

echo "[3] Linking objects with linker.ld..."
ld -m elf_i386 -nostdlib -T "$SRC_DIR/linker.ld" \
   -o "$BUILD_DIR/kernel.elf" \
   "$BUILD_DIR/kernel.o" "$BUILD_DIR/irq_stubs.o"

echo "[4] Copying kernel.elf into ISO tree..."
cp "$BUILD_DIR/kernel.elf" "$ISO_DIR/boot/"

echo "[5] Building bootable ISO..."
grub-mkrescue -o CallumOS.iso "$ISO_DIR"

echo "[6] Creating bootable virtual disk..."
dd if=CallumOS.iso of=disk.img bs=4M status=progress
echo "✅ Build complete: disk.img"
