#include <stdint.h>
#include "block_device.h"

// =========================
//  PORT I/O
// =========================

static inline void outb(uint16_t port, uint8_t val) {
    asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static inline void insw(uint16_t port, void *addr, uint32_t count) {
    asm volatile ("rep insw" : "+D"(addr), "+c"(count) : "d"(port) : "memory");
}

static inline void outsw(uint16_t port, const void *addr, uint32_t count) {
    asm volatile ("rep outsw" : "+S"(addr), "+c"(count) : "d"(port));
}

// =========================
//  ATA CONSTANTS
// =========================

#define ATA_PRIMARY_IO      0x1F0
#define ATA_PRIMARY_CTRL    0x3F6

#define ATA_REG_DATA        0x00
#define ATA_REG_ERROR       0x01
#define ATA_REG_FEATURES    0x01
#define ATA_REG_SECCOUNT0   0x02
#define ATA_REG_LBA0        0x03
#define ATA_REG_LBA1        0x04
#define ATA_REG_LBA2        0x05
#define ATA_REG_HDDEVSEL    0x06
#define ATA_REG_COMMAND     0x07
#define ATA_REG_STATUS      0x07

#define ATA_CMD_READ_PIO        0x20
#define ATA_CMD_READ_PIO_EXT    0x24
#define ATA_CMD_WRITE_PIO       0x30
#define ATA_CMD_WRITE_PIO_EXT   0x34
#define ATA_CMD_CACHE_FLUSH     0xE7
#define ATA_CMD_CACHE_FLUSH_EXT 0xEA

#define ATA_SR_BSY  0x80
#define ATA_SR_DRDY 0x40
#define ATA_SR_DF   0x20
#define ATA_SR_DRQ  0x08
#define ATA_SR_ERR  0x01

// =========================
//  INTERNAL HELPERS
// =========================

static int ata_wait_busy(void) {
    uint8_t status;
    do {
        status = inb(ATA_PRIMARY_IO + ATA_REG_STATUS);
    } while (status & ATA_SR_BSY);
    return (status & ATA_SR_ERR) ? -1 : 0;
}

static int ata_wait_drq(void) {
    uint8_t status;
    do {
        status = inb(ATA_PRIMARY_IO + ATA_REG_STATUS);
        if (status & ATA_SR_ERR) return -1;
        if (status & ATA_SR_DF) return -2;
    } while (!(status & ATA_SR_DRQ));
    return 0;
}

// =========================
//  28-BIT LBA READ
// =========================

int ata_read28(uint32_t lba, void *buffer) {
    if (lba > 0x0FFFFFFF) return -1;

    ata_wait_busy();

    outb(ATA_PRIMARY_IO + ATA_REG_HDDEVSEL, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_PRIMARY_IO + ATA_REG_SECCOUNT0, 1);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA0, (uint8_t)(lba));
    outb(ATA_PRIMARY_IO + ATA_REG_LBA1, (uint8_t)(lba >> 8));
    outb(ATA_PRIMARY_IO + ATA_REG_LBA2, (uint8_t)(lba >> 16));

    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_READ_PIO);

    if (ata_wait_drq() < 0) return -1;

    insw(ATA_PRIMARY_IO + ATA_REG_DATA, buffer, 256);
    return 0;
}

// =========================
//  28-BIT LBA WRITE
// =========================

int ata_write28(uint32_t lba, const void *buffer) {
    if (lba > 0x0FFFFFFF) return -1;

    ata_wait_busy();

    outb(ATA_PRIMARY_IO + ATA_REG_HDDEVSEL, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_PRIMARY_IO + ATA_REG_SECCOUNT0, 1);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA0, (uint8_t)(lba));
    outb(ATA_PRIMARY_IO + ATA_REG_LBA1, (uint8_t)(lba >> 8));
    outb(ATA_PRIMARY_IO + ATA_REG_LBA2, (uint8_t)(lba >> 16));

    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_WRITE_PIO);

    if (ata_wait_drq() < 0) return -1;

    outsw(ATA_PRIMARY_IO + ATA_REG_DATA, buffer, 256);

    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_CACHE_FLUSH);
    ata_wait_busy();

    return 0;
}

// =========================
//  48-BIT LBA READ/WRITE
// =========================
// (Optional — I can add these if you want them.)

void ata_init(void) {
    // Could detect drives here, but QEMU works without it.
}
