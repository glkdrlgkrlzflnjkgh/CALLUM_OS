/* linker.ld */
ENTRY(kernel_main)

SECTIONS {
  /* Load kernel at 1 MiB */
  . = 1M;

  /* Multiboot header must come first */
  .multiboot : {
    *(.multiboot)
  }

  /* Code */
  .text : {
    *(.text*)
  }

  /* Read‑only data */
  .rodata : {
    *(.rodata*)
  }

  /* Initialized data */
  .data : {
    *(.data*)
  }

  /* Reserve space for user programs */
  . = 0x400000;
  .userland : {
    /* nothing here yet */
  }

  /* Uninitialized data (zeroed at runtime) */
  .bss : {
    *(COMMON)
    *(.bss*)
  }
}
