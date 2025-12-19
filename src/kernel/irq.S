.intel_syntax noprefix

/* ========== Exports ========== */
.global irq_timer
.global irq_keyboard_stub
.global irq_0x22, irq_0x23, irq_0x24, irq_0x25, irq_0x26, irq_0x27
.global irq_0x28, irq_0x29, irq_0x2A, irq_0x2B, irq_0x2C, irq_0x2D, irq_0x2E, irq_0x2F
.global isr_syscall

.global isr_exc_0x00, isr_exc_0x01, isr_exc_0x02, isr_exc_0x03
.global isr_exc_0x04, isr_exc_0x05, isr_exc_0x06, isr_exc_0x07
.global isr_exc_0x08, isr_exc_0x09, isr_exc_0x0A, isr_exc_0x0B, isr_exc_0x0C
.global isr_exc_0x0D, isr_exc_0x0E
.global isr_exc_0x10, isr_exc_0x11, isr_exc_0x12, isr_exc_0x13
.global isr_exc_0x1D, isr_exc_0x1E, isr_exc_0x1F

/* ========== C-side symbols ========== */
/* IRQ handlers */
.extern irq_timer_c
.extern keyboard_isr_c
.extern irq_unhandled_c

/* Syscall handler (returns uint32_t) */
.extern isr_syscall_c

/* Exception diagnostics */
.extern exc_common_noerr_c
.extern exc_common_err_c
.extern exc_gp_c
.extern exc_pf_c

/* Probes written by IRQ stubs */
.extern isr_probe_ss
.extern isr_probe_esp
.extern isr_probe_cpl

/* ========== IRQ stubs ========== */

/* PIT timer (IRQ0 -> 0x20) */
irq_timer:
    cld
    /* Capture CPL (from CS RPL), SS, ESP at entry */
    mov ax, cs
    and ax, 0x0003
    mov WORD PTR [isr_probe_cpl], ax
    mov ax, ss
    mov WORD PTR [isr_probe_ss], ax
    mov eax, esp
    mov DWORD PTR [isr_probe_esp], eax

    /* Switch to KDS (0x10) for C */
    push ds
    push es
    push fs
    push gs
    mov ax, 0x10
    mov ds, ax
    mov es, ax

    pusha
    call irq_timer_c
    popa

    pop gs
    pop fs
    pop es
    pop ds
    iret

/* Keyboard (IRQ1 -> 0x21) */
irq_keyboard_stub:
    cld
    mov ax, cs
    and ax, 0x0003
    mov WORD PTR [isr_probe_cpl], ax
    mov ax, ss
    mov WORD PTR [isr_probe_ss], ax
    mov eax, esp
    mov DWORD PTR [isr_probe_esp], eax

    push ds
    push es
    push fs
    push gs
    mov ax, 0x10
    mov ds, ax
    mov es, ax

    pusha
    call keyboard_isr_c
    popa

    pop gs
    pop fs
    pop es
    pop ds
    iret

/* Unhandled IRQs (0x22–0x2F) */
#define DECL_IRQ(vec)             \
    .global irq_##vec             ;\
irq_##vec:                        ;\
    cld                           ;\
    push ds                       ;\
    push es                       ;\
    push fs                       ;\
    push gs                       ;\
    mov ax, 0x10                  ;\
    mov ds, ax                    ;\
    mov es, ax                    ;\
    pusha                         ;\
    mov eax, vec                  ;\
    push eax                      ;\
    call irq_unhandled_c          ;\
    add  esp, 4                   ;\
    popa                          ;\
    pop gs                        ;\
    pop fs                        ;\
    pop es                        ;\
    pop ds                        ;\
    iret

DECL_IRQ(0x22)
DECL_IRQ(0x23)
DECL_IRQ(0x24)
DECL_IRQ(0x25)
DECL_IRQ(0x26)
DECL_IRQ(0x27)
DECL_IRQ(0x28)
DECL_IRQ(0x29)
DECL_IRQ(0x2A)
DECL_IRQ(0x2B)
DECL_IRQ(0x2C)
DECL_IRQ(0x2D)
DECL_IRQ(0x2E)
DECL_IRQ(0x2F)

/* ========== Syscall stub (int 0x80) ========== */
/* Trap gate, DPL=3 in IDT. Preserve registers, pass EAX (num), EBX (arg) to C, write return into saved EAX. */
isr_syscall:
    cld
    pusha                           /* push EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI */

    /* Extract syscall number and arg from saved pusha frame */
    mov eax, DWORD PTR [esp+0]      /* saved EAX (syscall number) */
    mov ebx, DWORD PTR [esp+12]     /* saved EBX (first argument) */

    /* Call C handler: uint32_t ret = isr_syscall_c(eax, ebx) */
    push ebx
    push eax
    call isr_syscall_c
    add  esp, 8

    /* Place ret into saved EAX so user sees it after iret */
    mov DWORD PTR [esp+0], eax

    popa
    iret

/* ========== Exception stubs ========== */
/* NO error code vectors: CPU pushed EIP,CS,EFLAGS */
#define EXC_NOERR(vecnum)          \
    .global isr_exc_##vecnum       ;\
isr_exc_##vecnum:                  ;\
    push ebp                       ;\
    mov  ebp, esp                  ;\
    mov  eax, DWORD PTR [ebp+4]    /* EIP */ ;\
    mov  ecx, DWORD PTR [ebp+8]    /* CS  */ ;\
    mov  edx, DWORD PTR [ebp+12]   /* EFLAGS */ ;\
    push edx                       ;\
    push ecx                       ;\
    push eax                       ;\
    push vecnum                    ;\
    call exc_common_noerr_c        ;\
    cli                            ;\
    hlt

/* WITH error code vectors: CPU pushed ERR,EIP,CS,EFLAGS */
#define EXC_ERR(vecnum)            \
    .global isr_exc_##vecnum       ;\
isr_exc_##vecnum:                  ;\
    push ebp                       ;\
    mov  ebp, esp                  ;\
    mov  eax, DWORD PTR [ebp+4]    /* ERR */ ;\
    mov  edx, DWORD PTR [ebp+8]    /* EIP */ ;\
    mov  ecx, DWORD PTR [ebp+12]   /* CS  */ ;\
    mov  ebx, DWORD PTR [ebp+16]   /* EFLAGS */ ;\
    push ebx                       ;\
    push ecx                       ;\
    push edx                       ;\
    push eax                       ;\
    push vecnum                    ;\
    call exc_common_err_c          ;\
    cli                            ;\
    hlt

/* Generate the stubs you install in kernel.c */
EXC_NOERR(0x00)
EXC_NOERR(0x01)
EXC_NOERR(0x02)
EXC_NOERR(0x03)
EXC_NOERR(0x04)
EXC_NOERR(0x05)
EXC_NOERR(0x06)
EXC_NOERR(0x07)

EXC_ERR(0x08)
EXC_NOERR(0x09)
EXC_ERR(0x0A)
EXC_ERR(0x0B)
EXC_ERR(0x0C)

/* Specialized handlers for GP (0x0D) and PF (0x0E) */
.global isr_exc_0x0D
isr_exc_0x0D:
    push ebp
    mov  ebp, esp
    mov  eax, DWORD PTR [ebp+4]    /* ERR */
    mov  edx, DWORD PTR [ebp+8]    /* EIP */
    mov  ecx, DWORD PTR [ebp+12]   /* CS  */
    mov  ebx, DWORD PTR [ebp+16]   /* EFLAGS */
    push ebx
    push ecx
    push edx
    push eax
    call exc_gp_c
    cli
    hlt

.global isr_exc_0x0E
isr_exc_0x0E:
    push ebp
    mov  ebp, esp
    mov  eax, DWORD PTR [ebp+4]    /* ERR */
    mov  edx, DWORD PTR [ebp+8]    /* EIP */
    mov  ecx, DWORD PTR [ebp+12]   /* CS  */
    mov  ebx, DWORD PTR [ebp+16]   /* EFLAGS */
    push ebx
    push ecx
    push edx
    push eax
    call exc_pf_c
    cli
    hlt

/* Remaining exceptions wired by kernel.c */
EXC_NOERR(0x10)
EXC_ERR(0x11)
EXC_NOERR(0x12)
EXC_NOERR(0x13)
EXC_NOERR(0x1D)
EXC_NOERR(0x1E)
EXC_NOERR(0x1F)
