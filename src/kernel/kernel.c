/* ---------- TODOS  ---------- */
// ✓ add Kmalloc
// ✓ add Kfree
// Filesystem
// ELF loader
// A video driver?



/* src/kernel/kernel.c — CallumOS full kernel (i386, Multiboot, VGA TTY, IRQs, syscalls, userland) */
#include <stdint.h>
#include <stddef.h>
#include "elf.h" // Include elf.h, it contains all the constants I need for the upcoming ELF loader.
#include "block_device.h"
/* ---------- Multiboot header ---------- */

#define MULTIBOOT_HEADER_MAGIC    0x1BADB002U
#define MULTIBOOT_HEADER_FLAGS    0x0U
#define MULTIBOOT_HEADER_CHECKSUM (-(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS))
__attribute__((section(".multiboot")))
const struct { uint32_t magic, flags, checksum; } multiboot_header = {
    MULTIBOOT_HEADER_MAGIC, MULTIBOOT_HEADER_FLAGS, MULTIBOOT_HEADER_CHECKSUM // we actually HAVE to do this.
// because GRUB wont think our kernel is valid unless we add this!
};

/* ---------- KMALLOC constants  ---------- */

extern char _end;
uintptr_t heap_ptr = (uintptr_t)&_end;

#define HEAP_SIZE 0x100000   // 1 MiB heap for now
uintptr_t heap_end = (uintptr_t)&_end + HEAP_SIZE;

#define MARKER_STACK_SIZE 1024
uintptr_t marker_stack[MARKER_STACK_SIZE];
int marker_top = 0;
/* ---------- ISR/IRQ externs (irq.S) ---------- */
extern void irq_timer(void);
extern void irq_keyboard_stub(void);
extern void irq_0x22(void); extern void irq_0x23(void); extern void irq_0x24(void);
extern void irq_0x25(void); extern void irq_0x26(void); extern void irq_0x27(void);
extern void irq_0x28(void); extern void irq_0x29(void); extern void irq_0x2A(void);
extern void irq_0x2B(void); extern void irq_0x2C(void); extern void irq_0x2D(void);
extern void irq_0x2E(void); extern void irq_0x2F(void);
extern void isr_syscall(void);

/* Exceptions (assembly stubs defined in irq.S) */
extern void isr_exc_0x00(void); extern void isr_exc_0x01(void); extern void isr_exc_0x02(void);
extern void isr_exc_0x03(void); extern void isr_exc_0x04(void); extern void isr_exc_0x05(void);
extern void isr_exc_0x06(void); extern void isr_exc_0x07(void); extern void isr_exc_0x08(void);
extern void isr_exc_0x09(void); extern void isr_exc_0x0A(void); extern void isr_exc_0x0B(void);
extern void isr_exc_0x0C(void); extern void isr_exc_0x0D(void); extern void isr_exc_0x0E(void);
extern void isr_exc_0x10(void); extern void isr_exc_0x11(void); extern void isr_exc_0x12(void);
extern void isr_exc_0x13(void); extern void isr_exc_0x1D(void); extern void isr_exc_0x1E(void);
extern void isr_exc_0x1F(void);

/* ---------- I/O ---------- */
static inline void outb(uint16_t port, uint8_t val){
    __asm__ __volatile__(".intel_syntax noprefix\n\tmov dx,%0\n\tmov al,%1\n\tout dx,al\n\t.att_syntax prefix\n\t"::"r"(port),"r"(val):"dx","al");
}
static inline uint8_t inb(uint16_t port){
    uint8_t v;
    __asm__ __volatile__(".intel_syntax noprefix\n\tmov dx,%1\n\tin al,dx\n\tmov %0,al\n\t.att_syntax prefix\n\t":"=r"(v):"r"(port):"dx","al");
    return v;
}
static inline void io_wait(void){ outb(0x80,0); }

void* kmalloc(size_t size) {
    // Align to 8 bytes
    heap_ptr = (heap_ptr + 7) & ~7;

    if (marker_top >= MARKER_STACK_SIZE)
        return NULL; // too many nested allocations (the marker stack will overflow if we allocate any more!)

    if (heap_ptr + size > heap_end)
        return NULL; // out of memory (if we didn't have this, its heap corruption time!)

    marker_stack[marker_top++] = heap_ptr;

    void* addr = (void*)heap_ptr;
    heap_ptr += size;

    return addr;
}

void kfree() {
    if (marker_top == 0)
        return; // nothing to free

    heap_ptr = marker_stack[--marker_top];
}
/* ---------- VGA ---------- */
static volatile uint16_t* const VGA = (uint16_t*)0xB8000;
static int cursor_row=0, cursor_col=0;
static inline uint16_t vga_cell(char ch, uint8_t attr){ return (uint16_t)ch | ((uint16_t)attr<<8); }
static void vga_hw_cursor_set(int row,int col){
    uint16_t pos=(uint16_t)(row*80+col);
    outb(0x3D4,0x0F); outb(0x3D5,(uint8_t)(pos&0xFF));
    outb(0x3D4,0x10); outb(0x3D5,(uint8_t)((pos>>8)&0xFF));
}
static void vga_clear(uint8_t attr){
    uint16_t fill = vga_cell(' ', attr);
    for(int i=0;i<80*25;i++) VGA[i] = fill;
    cursor_row=0; cursor_col=0; vga_hw_cursor_set(cursor_row,cursor_col);
}
static void vga_putc(char c, uint8_t attr) {
    if (c == '\n') {
        cursor_row++;
        cursor_col = 0;
    } else if (c == '\r') {
        cursor_col = 0;
    } else if (c == '\t') {
        cursor_col = (cursor_col + 4) & ~3;
    } else if (c == '\b') {
        // Backspace: move cursor left and erase
        if (cursor_col > 0) {
            cursor_col--;
        } else if (cursor_row > 0) {
            cursor_row--;
            cursor_col = 79; // wrap to end of previous line
        }
        VGA[cursor_row * 80 + cursor_col] = vga_cell(' ', attr);
    } else {
        VGA[cursor_row * 80 + cursor_col] = vga_cell(c, attr);
        cursor_col++;
        if (cursor_col >= 80) {
            cursor_col = 0;
            cursor_row++;
        }
    }

    // Scroll if needed
    if (cursor_row >= 25) {
        for (int r = 1; r < 25; r++)
            for (int c = 0; c < 80; c++)
                VGA[(r - 1) * 80 + c] = VGA[r * 80 + c];
        for (int c = 0; c < 80; c++)
            VGA[24 * 80 + c] = vga_cell(' ', 0x07);
        cursor_row = 24;
    }

    vga_hw_cursor_set(cursor_row, cursor_col);
}
static void vga_write(const char* s,uint8_t attr){ for(int i=0;s[i];i++) vga_putc(s[i],attr); }
static void print_hex8(uint8_t v, uint8_t attr){
    const char* h="0123456789ABCDEF"; char out[3];
    out[0]=h[(v>>4)&0xF]; out[1]=h[v&0xF]; out[2]=0; vga_write(out,attr);
}
static void print_hex16(uint16_t v, uint8_t attr){
    const char* h="0123456789ABCDEF"; char out[5];
    out[0]=h[(v>>12)&0xF]; out[1]=h[(v>>8)&0xF]; out[2]=h[(v>>4)&0xF]; out[3]=h[v&0xF]; out[4]=0; vga_write(out,attr);
}
static void print_hex32(uint32_t v, uint8_t attr){
    const char* h="0123456789ABCDEF"; char out[9];
    for(int i=0;i<8;i++) out[7-i]=h[(v>>(i*4))&0xF]; out[8]=0; vga_write(out,attr);
}
static void speaker_on(uint32_t freq) {
    uint32_t div = 1193182 / freq;
    outb(0x43, 0xB6);              // Command: channel 2, mode 3, binary
    outb(0x42, (uint8_t)(div & 0xFF));   // Low byte
    outb(0x42, (uint8_t)((div >> 8) & 0xFF)); // High byte
    uint8_t tmp = inb(0x61);
    if (!(tmp & 3)) outb(0x61, tmp | 3); // Enable speaker
}

static void speaker_off(void) {
    uint8_t tmp = inb(0x61);
    outb(0x61, tmp & ~3); // Disable speaker
}
#define VGA_COLS 80
#define VGA_ROWS 25
#define BSOD_ATTR 0x1F  /* white on blue */

/* VGA is already defined at line 47:
   static volatile uint16_t* const VGA = (uint16_t*)0xB8000;
   so we just use it here. */

extern uint16_t vga_cell(char ch, uint8_t attr);
extern void vga_putc(char ch, uint8_t attr);

/* helpers */
static int str_len(const char* s) { int n=0; while(s[n]) n++; return n; }

static void vga_puts_at(int row, int col, const char* s, uint8_t attr) {
    while (*s) {
        VGA[row * VGA_COLS + col++] = vga_cell(*s++, attr);
    }
}

static void vga_putdec_at(int row, int col, int n, uint8_t attr) {
    char buf[12]; int i=0;
    if (n==0) { VGA[row*VGA_COLS+col]=vga_cell('0',attr); return; }
    while (n>0) { buf[i++]='0'+(n%10); n/=10; }
    while (i--) VGA[row*VGA_COLS+col++]=vga_cell(buf[i],attr);
}

static void vga_puthex32_at(int row, int col, uint32_t val, uint8_t attr) {
    VGA[row*VGA_COLS+col++]=vga_cell('0',attr);
    VGA[row*VGA_COLS+col++]=vga_cell('x',attr);
    for (int i=7;i>=0;i--) {
        int d=(val>>(i*4))&0xF;
        char c=(d<10)?('0'+d):('A'+(d-10));
        VGA[row*VGA_COLS+col++]=vga_cell(c,attr);
    }
}

/* panic handler */
__attribute__((noreturn)) void panic(const char* msg) {
    __asm__ __volatile__("cli");   // disable interrupts

    /* Clear screen */
    for (int r=0;r<VGA_ROWS;r++)
        for (int c=0;c<VGA_COLS;c++)
            VGA[r*VGA_COLS+c]=vga_cell(' ',BSOD_ATTR);

    /* Banner */
    const char* banner="===== CALLUMOS KERNEL PANIC =====";
    int banner_col=(VGA_COLS-str_len(banner))/2;
    vga_puts_at(4,banner_col,banner,BSOD_ATTR);

    /* Panic message */
    int msg_col=(VGA_COLS-str_len(msg))/2;
    vga_puts_at(6,msg_col,msg,BSOD_ATTR);

    /* Halt message */
    const char* halted="System halted. Please restart manually.";
    int halt_col=(VGA_COLS-str_len(halted))/2;
    vga_puts_at(8,halt_col,halted,BSOD_ATTR);

    /* Stack trace header */
    const char* hdr="Kernel stack trace:";
    int hdr_col=(VGA_COLS-str_len(hdr))/2;
    vga_puts_at(10,hdr_col,hdr,BSOD_ATTR);

    /* Capture ESP */
    uint32_t* esp;
    __asm__ __volatile__("mov %%esp,%0":"=r"(esp));

    /* Print 10 entries: [index] 0xXXXXXXXX */
    for (int i=0;i<10;i++) {
        int row=12+i;
        int col=4;
        VGA[row*VGA_COLS+col++]=vga_cell('[',BSOD_ATTR);
        vga_putdec_at(row,col,i,BSOD_ATTR);
        col+=2; // skip past digits
        VGA[row*VGA_COLS+col++]=vga_cell(']',BSOD_ATTR);
        vga_puthex32_at(row,col,esp[i],BSOD_ATTR);
    }

    /* Halt forever */
    for(;;) __asm__ __volatile__("hlt");
}
/* ---------- Probes written by irq.S ---------- */
volatile uint16_t isr_probe_ss = 0;
volatile uint32_t isr_probe_esp = 0;
volatile uint16_t isr_probe_cpl = 0;
volatile uint16_t tr_probe = 0;

/* Optional return-frame probe from IRQ stubs (if you add it in irq.S) */
volatile uint32_t ret_eip=0, ret_eflags=0, ret_esp=0;
volatile uint16_t ret_cs=0, ret_ss=0;

/* ---------- GDT/IDT/TSS ---------- */
struct __attribute__((packed)) gdt_entry{ uint16_t limit_lo; uint16_t base_lo; uint8_t base_mid; uint8_t access; uint8_t gran; uint8_t base_hi; };
struct __attribute__((packed)) gdt_ptr{ uint16_t limit; uint32_t base; };
struct __attribute__((packed)) idt_entry{ uint16_t base_lo; uint16_t sel; uint8_t always0; uint8_t flags; uint16_t base_hi; };
struct __attribute__((packed)) idt_ptr{ uint16_t limit; uint32_t base; };

/* Correct i386 TSS layout */
struct __attribute__((packed)) tss_entry {
    uint16_t prev_tss, __prev_pad;
    uint32_t esp0;
    uint16_t ss0, __ss0_pad;
    uint32_t esp1;
    uint16_t ss1, __ss1_pad;
    uint32_t esp2;
    uint16_t ss2, __ss2_pad;
    uint32_t cr3;
    uint32_t eip;
    uint32_t eflags;
    uint32_t eax, ecx, edx, ebx;
    uint32_t esp, ebp, esi, edi;
    uint16_t es, __es_pad;
    uint16_t cs, __cs_pad;
    uint16_t ss, __ss_pad;
    uint16_t ds, __ds_pad;
    uint16_t fs, __fs_pad;
    uint16_t gs, __gs_pad;
    uint16_t ldt, __ldt_pad;
    uint16_t trap;
    uint16_t iomap;
};
static struct gdt_entry gdt[6]; static struct gdt_ptr gp;
static struct idt_entry idt[256]; static struct idt_ptr ip;
static struct tss_entry tss;

/* Kernel ring-0 stack (global to show bounds) */
static uint8_t kstack[4096] __attribute__((aligned(16)));
static uint8_t user_stack[4096] __attribute__((aligned(16)));

#define KCS  0x08
#define KDS  0x10
#define UCS  0x1B
#define UDS  0x23
#define TSSS 0x28

static void gdt_set(int i,uint32_t base,uint32_t limit,uint8_t access,uint8_t gran){
    gdt[i].limit_lo=limit&0xFFFF; gdt[i].base_lo=base&0xFFFF; gdt[i].base_mid=(base>>16)&0xFF;
    gdt[i].access=access; gdt[i].gran=((limit>>16)&0x0F)|(gran&0xF0); gdt[i].base_hi=(base>>24)&0xFF;
}
static inline void lgdt(struct gdt_ptr* p){ __asm__ __volatile__("lgdt %0" :: "m"(*p) : "memory"); }
static inline void lidt(struct idt_ptr* p){ __asm__ __volatile__("lidt %0" :: "m"(*p) : "memory"); }
static inline void ltr(uint16_t sel){ __asm__ __volatile__(".intel_syntax noprefix\n\tltr %0\n\t.att_syntax prefix\n\t" :: "r"(sel) : "memory"); }
static inline uint16_t str_read(void){
    uint16_t tr; __asm__ __volatile__(".intel_syntax noprefix\n\tstr %0\n\t.att_syntax prefix\n\t":"=r"(tr));
    return tr;
}
static inline void load_kernel_segments(void){
    __asm__ __volatile__(".intel_syntax noprefix\n\tmov ax,0x10\n\tmov ds,ax\n\tmov es,ax\n\tmov fs,ax\n\tmov gs,ax\n\tmov ss,ax\n\t.att_syntax prefix\n\t"::: "ax");
}
static void idt_set_gate(uint8_t num,uint32_t base,uint16_t sel,uint8_t flags){
    idt[num].base_lo=base&0xFFFF; idt[num].sel=sel; idt[num].always0=0; idt[num].flags=flags; idt[num].base_hi=(base>>16)&0xFFFF;
}

/* ---------- PIC/PIT ---------- */
static void pic_remap(void){
    uint8_t a1=inb(0x21), a2=inb(0xA1);
    outb(0x20,0x11); io_wait(); outb(0xA0,0x11); io_wait();
    outb(0x21,0x20); io_wait(); outb(0xA1,0x28); io_wait();
    outb(0x21,0x04); io_wait(); outb(0xA1,0x02); io_wait();
    outb(0x21,0x01); io_wait(); outb(0xA1,0x01); io_wait();
    outb(0x21,a1); outb(0xA1,a2);
}
static void pit_init(uint32_t hz){
    uint32_t divisor = 1193180U / hz;
    outb(0x43,0x36);
    outb(0x40,(uint8_t)(divisor&0xFF));
    outb(0x40,(uint8_t)((divisor>>8)&0xFF));
}

/* ---------- Keyboard / IRQ C handlers ---------- */
#define SC_RELEASE 0x80
#define SC_LSHIFT  0x2A
#define SC_RSHIFT  0x36
#define SC_CAPS    0x3A
static int shift=0, caps=0;
static const char keymap[128]={0,27,'1','2','3','4','5','6','7','8','9','0','-','=',8,'\t',
 'q','w','e','r','t','y','u','i','o','p','[',']','\n',0,'a','s',
 'd','f','g','h','j','k','l',';','\'','`',0,'\\','z','x','c','v',
 'b','n','m',',','.','/',0,'*',0,' ',0,0,0,0,0,0};
static const char keymap_shift[128]={0,27,'!','@','#','$','%','^','&','*','(',')','_','+',8,'\t',
 'Q','W','E','R','T','Y','U','I','O','P','{','}','\n',0,'A','S',
 'D','F','G','H','J','K','L',':','"','~',0,'|','Z','X','C','V',
 'B','N','M','<','>','?',0,'*',0,' ',0,0,0,0,0,0};

#define KBUF_SIZE 256
static char kbuf[KBUF_SIZE]; static volatile unsigned khead=0, ktail=0;
static void kbuf_push(char c){ unsigned n=(khead+1)%KBUF_SIZE; if(n!=ktail){ kbuf[khead]=c; khead=n; } }
static int kbuf_pop(void){ if(ktail==khead) return -1; char c=kbuf[ktail]; ktail=(ktail+1)%KBUF_SIZE; return (int)c; }

static inline void ps2_wait_input_clear(void){ while(inb(0x64)&0x02){ io_wait(); } }
static inline void ps2_wait_output_full(void){ while(!(inb(0x64)&0x01)){ io_wait(); } }
static uint8_t ps2_read_config(void){ ps2_wait_input_clear(); outb(0x64,0x20); ps2_wait_output_full(); return inb(0x60); }
static void ps2_write_config(uint8_t cfg){ ps2_wait_input_clear(); outb(0x64,0x60); ps2_wait_input_clear(); outb(0x60,cfg); }
static void keyboard_enable(void){
    ps2_wait_input_clear(); outb(0x64,0xAE);
    uint8_t cfg=ps2_read_config(); cfg|=0x01; cfg&=~0x10; ps2_write_config(cfg);
    ps2_wait_input_clear(); outb(0x60,0xF4);
    for(int i=0;i<1000;i++){ if(inb(0x64)&0x01){ (void)inb(0x60); break; } io_wait(); }
}

/* IRQ C handlers */
void keyboard_isr_c(void){
    if(!(inb(0x64)&0x01)) goto eoi;
    uint8_t sc=inb(0x60);
    if(sc==SC_LSHIFT||sc==SC_RSHIFT){ shift=1; goto eoi; }
    if(sc==(SC_LSHIFT|SC_RELEASE)||sc==(SC_RSHIFT|SC_RELEASE)){ shift=0; goto eoi; }
    if(sc==SC_CAPS){ caps^=1; goto eoi; }
    if(sc&SC_RELEASE) goto eoi;
    const char* km=shift?keymap_shift:keymap; char ch=0;
    if(sc<128) ch=km[sc];
    if(ch){
        if(ch>='a'&&ch<='z'){ if(caps&&!shift) ch=(char)(ch-'a'+'A'); }
        else if(ch>='A'&&ch<='Z'){ if(caps&&shift) ch=(char)(ch-'A'+'a'); }
        kbuf_push(ch);
    }
eoi:
    outb(0x20,0x20); /* boss EOI */
}

void irq_unhandled_c(uint8_t vec){
    vga_write("\n[Unhandled IRQ: ",0x0C); print_hex8(vec,0x0C); vga_write("]\n",0x0C);
    if(vec>=0x28 && vec<=0x2F) outb(0xA0,0x20); /* worker EOI */
    if(vec>=0x20 && vec<=0x2F) outb(0x20,0x20); /* boss EOI */
    panic("Unhandled IRQ");
}

void irq_timer_c(void){
    static uint32_t ticks=0; (void)ticks; ticks++;
    outb(0x20,0x20); /* boss EOI */
}

/* ---------- Syscalls ---------- */
enum { SYS_write=1, SYS_readch=2, SYS_exit=3, SYS_yield=4 };

/* Single, consistent signature returning uint32_t (assembly stub writes back to saved EAX) */
uint32_t isr_syscall_c(uint32_t num, uint32_t arg){
    switch(num){
        case SYS_write:
            vga_write((const char*)arg, 0x07);
            return 0;
        case SYS_readch:
            return (uint32_t)kbuf_pop(); /* -1 if none */
        case SYS_exit:
            vga_write("\n[process exited]\n",0x07);
            for(;;){ __asm__ __volatile__("hlt"); }
        case SYS_yield:
            /* cooperative placeholder */
            return 0;
        default:
            /* Don’t panic — signal ENOSYS to userland */
            return 0xFFFFFFFFU;
    }
}

/* ---------- Exception diagnostics (extern linkage) ---------- */
void exc_common_noerr_c(uint8_t vec, uint32_t eip, uint16_t cs, uint32_t eflags){
    vga_write("\n[CPU exception: ",0x0C); print_hex8(vec,0x0C); vga_write("]\n",0x0C);
    vga_write("EIP=",0x0C); print_hex32(eip,0x0C);
    vga_write(" CS=",0x0C); print_hex16(cs,0x0C);
    vga_write(" EFLAGS=",0x0C); print_hex32(eflags,0x0C); vga_write("\n",0x0C);
    panic("Exception");
}
void exc_common_err_c(uint8_t vec, uint32_t err, uint32_t eip, uint16_t cs, uint32_t eflags){
    vga_write("\n[CPU exception: ",0x0C); print_hex8(vec,0x0C); vga_write("]\n",0x0C);
    vga_write("ERR=",0x0C); print_hex32(err,0x0C);
    vga_write(" EIP=",0x0C); print_hex32(eip,0x0C);
    vga_write(" CS=",0x0C); print_hex16(cs,0x0C);
    vga_write(" EFLAGS=",0x0C); print_hex32(eflags,0x0C); vga_write("\n",0x0C);
    panic("Exception (with error code)");
}
void exc_gp_c(uint32_t err, uint32_t eip, uint16_t cs, uint32_t eflags){
    vga_write("\n[GP fault 0x0D]\n",0x0C);
    vga_write("ERR=",0x0C); print_hex32(err,0x0C);
    vga_write(" EIP=",0x0C); print_hex32(eip,0x0C);
    vga_write(" CS=",0x0C); print_hex16(cs,0x0C);
    vga_write(" EFLAGS=",0x0C); print_hex32(eflags,0x0C); vga_write("\n",0x0C);

    uint16_t sel=(uint16_t)(err & 0xFFFC);
    uint16_t idx = sel >> 3;
    uint8_t ti = (err >> 2) & 1;
    uint8_t ext = err & 1;
    vga_write("SEL=",0x0C); print_hex16(sel,0x0C);
    vga_write(" IDX=",0x0C); print_hex16(idx,0x0C);
    vga_write(" TI=",0x0C); vga_write(ti?"1":"0",0x0C);
    vga_write(" EXT=",0x0C); vga_write(ext?"1":"0",0x0C); vga_write("\n",0x0C);

    vga_write("Probe CPL=",0x0C); print_hex16(isr_probe_cpl,0x0C);
    vga_write(" SS=",0x0C); print_hex16(isr_probe_ss,0x0C);
    vga_write(" ESP=",0x0C); print_hex32(isr_probe_esp,0x0C);
    vga_write(" TR=",0x0C); print_hex16(tr_probe,0x0C); vga_write("\n",0x0C);

    vga_write("TSS.ss0=",0x0C); print_hex16(tss.ss0,0x0C);
    vga_write(" TSS.esp0=",0x0C); print_hex32(tss.esp0,0x0C); vga_write("\n",0x0C);

    panic("General protection fault");
}
void exc_pf_c(uint32_t err, uint32_t eip, uint16_t cs, uint32_t eflags){
    uint32_t cr2; __asm__ __volatile__(".intel_syntax noprefix\n\tmov %0, cr2\n\t.att_syntax prefix\n\t":"=r"(cr2));
    vga_write("\n[Page fault 0x0E]\n",0x0C);
    vga_write("CR2=",0x0C); print_hex32(cr2,0x0C);
    vga_write(" ERR=",0x0C); print_hex32(err,0x0C);
    vga_write(" EIP=",0x0C); print_hex32(eip,0x0C);
    vga_write(" CS=",0x0C); print_hex16(cs,0x0C);
    vga_write(" EFLAGS=",0x0C); print_hex32(eflags,0x0C); vga_write("\n",0x0C);
    panic("Page fault");
}
// syscall numbers
#define SYS_WRITE 1
#define SYS_READCH 2
#define SYS_PANIC 3
// syscall dispatcher (kernel side)
int syscall_dispatch(int num, const char* arg) {
    switch (num) {
        case SYS_WRITE:
            vga_write(arg, 0x0F);   // call your existing VGA text routine
            return 0;               // success
        case SYS_READCH:
            return kbuf_pop();      // call into your keyboard buffer logic
        case SYS_PANIC:
            panic(arg); // I think the kernel might need some deep breaths after this...
        default:
            panic("Bad syscall!");
    }
}



/* ---------- User-mode helpers (COSH) ---------- */
static inline int u_readch(void) {
    return syscall_dispatch(SYS_READCH, NULL);
}

static inline int u_write(const char* s) {
    return syscall_dispatch(SYS_WRITE, s);
}

static inline int u_panic(const char* s) {
    return syscall_dispatch(SYS_PANIC,s);
}
static inline void u_yield(void){ __asm__ __volatile__(".intel_syntax noprefix\n\tmov eax,4\n\tint 0x80\n\t.att_syntax prefix\n\t"::: "eax"); }
static inline void u_exit(void){ __asm__ __volatile__(".intel_syntax noprefix\n\tmov eax,3\n\tint 0x80\n\t.att_syntax prefix\n\t"::: "eax"); }

static void cosh_banner(void){
    vga_write("CallumOS Shell (COSH)\n",0x0F);
    vga_write("----------------------\n",0x0F);
}
static void show_isr_stack_probe(void){
    vga_write("ISR CPL=",0x0E); print_hex16(isr_probe_cpl,0x0E);
    vga_write(" SS=",0x0E); print_hex16(isr_probe_ss,0x0E);
    vga_write(" ESP=",0x0E); print_hex32(isr_probe_esp,0x0E);
    vga_write(" TR=",0x0E); print_hex16(tr_probe,0x0E); vga_write("\n",0x0E);
}
static void show_stack_bounds(void){
    uint32_t base = (uint32_t)kstack;
    uint32_t top  = base + sizeof(kstack);
    vga_write("kstack base=",0x0A); print_hex32(base,0x0A);
    vga_write(" top=",0x0A); print_hex32(top,0x0A);
    vga_write(" TSS.esp0=",0x0A); print_hex32(tss.esp0,0x0A);
    vga_write(" TSS.ss0=",0x0A); print_hex16(tss.ss0,0x0A); vga_write("\n",0x0A);
}
static void show_ret_frame(void){
    vga_write("RET CS=",0x0E); print_hex16(ret_cs,0x0E);
    vga_write(" EIP=",0x0E); print_hex32(ret_eip,0x0E);
    vga_write(" EFLAGS=",0x0E); print_hex32(ret_eflags,0x0E);
    vga_write(" SS=",0x0E); print_hex16(ret_ss,0x0E);
    vga_write(" ESP=",0x0E); print_hex32(ret_esp,0x0E); vga_write("\n",0x0E);
}

/* ---------- COSH user shell ---------- */
static void user_shell(void){
    cosh_banner();
    // DID YOU KNOW? on this line, a message used to get printed, I did that to debug the hang when the shell launched!
    u_write("Type 'help' or 'echo X'.\n\n");
    char line[2048]; int len=0;
    for(;;){
        u_write("COSH> "); len=0;
        for(;;){
            int ch=u_readch();
            if(ch<0){ u_yield(); continue; }
            if(ch=='\n'){ line[len]='\0'; u_write("\n"); break; }
            if(ch==8){ if(len>0){ len--; u_write("\b \b"); } continue; }
            if(ch>=32 && ch<127){
                if(len<2047){
                    line[len++]=(char)ch;
                    char out[2]={ (char)ch, 0 };
                    u_write(out);
                }
            }
        }
        if(len==0) continue;

        if(len>=5 && line[0]=='p'&&line[1]=='r'&&line[2]=='o'&&line[3]=='b'&&line[4]=='e'){
            show_isr_stack_probe();
        } else if(len>=6 && line[0]=='s'&&line[1]=='t'&&line[2]=='a'&&line[3]=='c'&&line[4]=='k'&&line[5]=='s'){
            show_stack_bounds();
        } else if(len==3 && line[0]=='r'&&line[1]=='e'&&line[2]=='t'){
            show_ret_frame();
        } else if(len>=4 && line[0]=='h'&&line[1]=='e'&&line[2]=='l'&&line[3]=='p'){
            u_write("Commands:\n"
                    "  help   - show help\n"
                    "  echo X - print X\n"
                    "  probe  - print ISR CPL/SS/ESP/TR\n"
                    "  stacks - show kernel stack bounds\n"
                    "  ret    - show last IRQ return frame\n"
                    "  exit   - exit\n"
                    "  crash  - trigger kernel panic\n");
        } else if(len>=4 && line[0]=='e'&&line[1]=='c'&&line[2]=='h'&&line[3]=='o'){
            const char* s=line+4; while(*s==' ') s++;
            u_write(s); u_write("\n");
        } else if(len==4 && line[0]=='e'&&line[1]=='x'&&line[2]=='i'&&line[3]=='t'){
            u_write("Bye.\n");
            u_exit();
        } else if(len==5 && line[0]=='c'&&line[1]=='r'&&line[2]=='a'&&line[3]=='s'&&line[4]=='h'){
            u_write("Crashing now...\n");
            u_panic("Crash command invoked from COSH"); // this actually will cause a GPF, but hey, that still panics, so its fine :)
        } else {
            u_write("Unknown command.\n");
        }
    }
}

/* ---------- Enter userland ---------- */
__attribute__((noreturn))
static void enter_userland(void (*entry)(void)){
    vga_write("entering callumland!\n",0x0F);
    uint32_t uesp = (uint32_t)user_stack + sizeof(user_stack) - 4;
    __asm__ __volatile__(
        ".intel_syntax noprefix\n\t"
        "cli\n\t"            /* avoid IRQs while building frame */
        "push 0x23\n\t"      /* user SS */
        "push %0\n\t"        /* user ESP */
        "push 0x3202\n\t"    /* user EFLAGS: IOPL=3, IF=1, bit1=1 */
        "push 0x1B\n\t"      /* user CS */
        "push %1\n\t"        /* user EIP (entry) */
        "iret\n\t"
        ".att_syntax prefix\n\t"
        :
        : "r"(uesp), "r"(entry)
        : "memory"
    );
    panic("enter_userland returned unexpectedly");
}

/* ---------- User entry trampoline ---------- */
__attribute__((naked)) static void user_entry(void){
    __asm__ __volatile__(".intel_syntax noprefix\n\tmov ax,0x23\n\tmov ds,ax\n\tmov es,ax\n\tmov fs,ax\n\tmov gs,ax\n\tsti\n\tcall user_shell\n\t.att_syntax prefix\n\t"); // BOOOOOIINNNGG!!
    panic("user_entry returned unexpectedly");
}

/* ---------- Kernel entry ---------- */
__attribute__((noreturn)) void kernel_main(void){
    /* GDT: null, KCS, KDS, UCS, UDS, TSS */
    gdt_set(0,0,0,0,0);
    gdt_set(1,0,0xFFFFF,0x9A,0xCF); /* KCS */
    gdt_set(2,0,0xFFFFF,0x92,0xCF); /* KDS */
    gdt_set(3,0,0xFFFFF,0xFA,0xCF); /* UCS */
    gdt_set(4,0,0xFFFFF,0xF2,0xCF); /* UDS */

    /* TSS: zero then set ring0 stack */
    for(size_t i=0;i<sizeof(tss);i++) ((uint8_t*)&tss)[i]=0;
    tss.esp0 = (uint32_t)kstack + sizeof(kstack) - 4;
    tss.ss0  = KDS;
    tss.iomap = sizeof(tss);

    uint32_t tss_base=(uint32_t)&tss; uint32_t tss_limit=sizeof(tss)-1;
    gdt_set(5,tss_base,tss_limit,0x89,0x00); /* 32-bit TSS, present */

    gp.limit=sizeof(gdt)-1; gp.base=(uint32_t)&gdt; lgdt(&gp);
    load_kernel_segments();

    /* Load TR and capture it */
    ltr(TSSS);
    tr_probe = str_read();
    vga_clear(0x0c);
    vga_write("Setting up exceptions\n",0x0c);
    /* Exceptions */
    idt_set_gate(0x00,(uint32_t)isr_exc_0x00,KCS,0x8E);
    idt_set_gate(0x01,(uint32_t)isr_exc_0x01,KCS,0x8E);
    idt_set_gate(0x02,(uint32_t)isr_exc_0x02,KCS,0x8E);
    idt_set_gate(0x03,(uint32_t)isr_exc_0x03,KCS,0x8E);
    idt_set_gate(0x04,(uint32_t)isr_exc_0x04,KCS,0x8E);
    idt_set_gate(0x05,(uint32_t)isr_exc_0x05,KCS,0x8E);
    idt_set_gate(0x06,(uint32_t)isr_exc_0x06,KCS,0x8E);
    idt_set_gate(0x07,(uint32_t)isr_exc_0x07,KCS,0x8E);
    idt_set_gate(0x08,(uint32_t)isr_exc_0x08,KCS,0x8E);
    idt_set_gate(0x09,(uint32_t)isr_exc_0x09,KCS,0x8E);
    idt_set_gate(0x0A,(uint32_t)isr_exc_0x0A,KCS,0x8E);
    idt_set_gate(0x0B,(uint32_t)isr_exc_0x0B,KCS,0x8E);
    idt_set_gate(0x0C,(uint32_t)isr_exc_0x0C,KCS,0x8E);
    idt_set_gate(0x0D,(uint32_t)isr_exc_0x0D,KCS,0x8E);
    idt_set_gate(0x0E,(uint32_t)isr_exc_0x0E,KCS,0x8E);
    idt_set_gate(0x10,(uint32_t)isr_exc_0x10,KCS,0x8E);
    idt_set_gate(0x11,(uint32_t)isr_exc_0x11,KCS,0x8E);
    idt_set_gate(0x12,(uint32_t)isr_exc_0x12,KCS,0x8E);
    idt_set_gate(0x13,(uint32_t)isr_exc_0x13,KCS,0x8E);
    idt_set_gate(0x1D,(uint32_t)isr_exc_0x1D,KCS,0x8E);
    idt_set_gate(0x1E,(uint32_t)isr_exc_0x1E,KCS,0x8E);
    idt_set_gate(0x1F,(uint32_t)isr_exc_0x1F,KCS,0x8E);
    vga_write("Setting up exceptions done, setting up IRQs\n",0x0c);
    /* IRQs */
    idt_set_gate(0x20,(uint32_t)irq_timer,        KCS,0x8E); /* boss: PIT */
    idt_set_gate(0x21,(uint32_t)irq_keyboard_stub,KCS,0x8E); /* boss: keyboard */
    idt_set_gate(0x22,(uint32_t)irq_0x22,         KCS,0x8E);
    idt_set_gate(0x23,(uint32_t)irq_0x23,         KCS,0x8E);
    idt_set_gate(0x24,(uint32_t)irq_0x24,         KCS,0x8E);
    idt_set_gate(0x25,(uint32_t)irq_0x25,         KCS,0x8E);
    idt_set_gate(0x26,(uint32_t)irq_0x26,         KCS,0x8E);
    idt_set_gate(0x27,(uint32_t)irq_0x27,         KCS,0x8E);
    idt_set_gate(0x28,(uint32_t)irq_0x28,         KCS,0x8E);
    idt_set_gate(0x29,(uint32_t)irq_0x29,         KCS,0x8E);
    idt_set_gate(0x2A,(uint32_t)irq_0x2A,         KCS,0x8E);
    idt_set_gate(0x2B,(uint32_t)irq_0x2B,         KCS,0x8E);
    idt_set_gate(0x2C,(uint32_t)irq_0x2C,         KCS,0x8E);
    idt_set_gate(0x2D,(uint32_t)irq_0x2D,         KCS,0x8E);
    idt_set_gate(0x2E,(uint32_t)irq_0x2E,         KCS,0x8E);
    idt_set_gate(0x2F,(uint32_t)irq_0x2F,         KCS,0x8E);
    vga_write("Setting up IRQs done, setting up syscall gate and remapping the PIC\n",0x0c);
    /* Syscall gate (trap, DPL=3) */
    idt_set_gate(0x80,(uint32_t)isr_syscall, KCS, 0xEF);

    ip.limit=sizeof(idt)-1; ip.base=(uint32_t)&idt; lidt(&ip);

    pic_remap();
    vga_write("Initializing the PIT\n",0x0c);
    pit_init(100); // initiate the PIT at 100hz

    /* Unmask boss IRQ0+IRQ1, mask worker */
    uint8_t m=inb(0x21); m &= ~(0x03); outb(0x21,m);
    outb(0xA1,0xFF);
    keyboard_enable();


    vga_write("CallumOS kernel V0.1 is loading... \n",0x0F);
    vga_write("TR=",0x0A); print_hex16(tr_probe,0x0A);
    vga_write(" TSS.ss0=",0x0A); print_hex16(tss.ss0,0x0A);
    vga_write(" TSS.esp0=",0x0A); print_hex32(tss.esp0,0x0A); vga_write("\n",0x0A);
    vga_write("Launching COSH...\n\n",0x0F);
    show_stack_bounds();
    vga_write("Entering Callumland shortly.... \n", 0x0F);
    /* Do NOT sti here; user EFLAGS turns IF on at CPL=3 */
    enter_userland(user_entry); // You're in user space, wether you like it or not!
    panic("kernel_main returned unexpectedly");
}
