# CallumOS

CallumOS is a small 32-bit x86 operating-system kernel written in C and
assembly. It boots through GRUB using the Multiboot protocol and currently
launches a simple user-mode shell called COSH.

This is an experimental operating-system project. It is useful for exploring
booting, x86 privilege levels, interrupts, system calls, device I/O, and basic
kernel memory management. It is not intended to be a daily-use operating
system.

## Current Features

- GRUB/Multiboot kernel boot
- VGA text-mode output
- GDT with ring 0 and ring 3 code/data segments
- TSS and a dedicated ring-0 stack for user-to-kernel transitions
- IDT exception handlers and remapped PIC interrupts
- PIT timer and PS/2 keyboard input
- Ring-3 COSH shell
- `int 0x80` system calls for writing, keyboard input, allocation, yielding,
	exiting, rebooting, panic testing, and FAT32 directory access
- Simple kernel heap allocator with `kmalloc` and `kfree`
- Basic ATA PIO LBA28 read support
- FAT32 partition mounting and short-name directory traversal
- COSH `ls`, `cd`, and `pwd` commands

ELF32 data structures are present for future loading work. A complete ELF
loader and process scheduler are not implemented yet.

## Repository Layout

```text
bootloader/              Older bootloader experiments
build.sh                 Build, image, and QEMU helper script
iso/boot/grub/grub.cfg   GRUB menu configuration
src/kernel/kernel.c      Kernel entry point and most kernel services
src/kernel/irq.S         Interrupt, exception, and syscall stubs
src/kernel/block_device.c ATA PIO block-device code
src/kernel/fat32.c       FAT32 mount and directory traversal
src/kernel/fat32.h       FAT32 kernel interface
src/kernel/elf.h         ELF32 type and program-header definitions
src/kernel/linker.ld     Kernel linker script; loads at 1 MiB
build/                   Generated object files and kernel ELF
```

## Requirements

Build from a Linux environment such as Debian or WSL. The build script needs:

- GCC with 32-bit compilation support
- GNU binutils, including `ld`
- GRUB utilities, including `grub-mkrescue` and `grub-install`
- `xorriso`
- `qemu-system-i386`
- `parted`, `losetup`, `mkfs.vfat`, `rsync`, and standard shell tools

On Debian, the usual starting point is:

```sh
sudo apt update
sudo apt install build-essential gcc-multilib grub-pc-bin grub-common \
	xorriso qemu-system-x86 parted util-linux dosfstools rsync
```

## Build

Make the script executable once, then build the kernel, bootable ISO, and
FAT32 disk image:

```sh
chmod +x build.sh
./build.sh all
```

Disk-image creation uses loop devices, partitioning, mounting, and GRUB
installation, so `all` may need to be run with root privileges:

```sh
sudo ./build.sh all
```

The build produces:

- `build/kernel.elf` - linked kernel image
- `CallumOS.iso` - GRUB bootable ISO
- `disk.img` - 64 MiB FAT32 disk image with GRUB installed

## Build Commands

```sh
./build.sh all     # Compile, link, build the ISO, and create disk.img
./build.sh iso     # Link existing objects and build only the ISO
sudo ./build.sh disk  # Create disk.img from an existing ISO
./build.sh run     # Start QEMU with disk.img
./build.sh clean   # Remove generated build and image artifacts
./build.sh help    # Display command help
```

Run the image with:

```sh
./build.sh run
```

QEMU starts with 256 MiB of memory and four virtual CPUs. The GRUB menu also
contains shutdown and reboot entries.

## Kernel Flow

The kernel starts in `kernel_main`, installs the GDT, TSS, IDT, PIC, PIT, and
keyboard support, runs basic allocator and ATA tests, mounts the FAT32
partition, and then enters COSH.

`enter_userland` uses `iret` to load ring-3 `CS`, `SS`, `EIP`, and `ESP`. COSH
invokes system calls with `int 0x80`. The CPU changes to the TSS ring-0 stack,
executes the kernel syscall handler, and `iret` returns to ring 3.

Useful COSH commands include:

```text
ls [DIR] List a directory
cd DIR   Change directory
pwd      Print the working directory
help     List commands
echo X   Print X
probe    Show interrupt privilege/stack probes
stacks   Show kernel stack and TSS information
ret      Show the last recorded return frame
exit     Reboot the machine
crash    Trigger the kernel panic path
```

The current FAT32 implementation supports short 8.3 names, directory
traversal, and basic `mkdir` support. Long filenames, general file reads and
writes, deletion, and directory growth are planned for the next filesystem
step.

## Development Notes

The project targets 32-bit protected mode (`elf_i386`) and uses a freestanding
kernel build. It does not use the host operating system's C runtime or a
standard library. Changes to assembly stubs, GDT/IDT entries, TSS setup, or
the linker script should be tested by rebuilding and booting the image in
QEMU.

Generated files such as `build/`, `CallumOS.iso`, and `disk.img` can be
removed with `./build.sh clean`.

## License

CallumOS is released under the MIT License. See [LICENSE](LICENSE).
