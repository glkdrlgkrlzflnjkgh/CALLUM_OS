#ifndef BLOCK_DEVICE_H
#define BLOCK_DEVICE_H

#include <stdint.h>

void ata_init();
void ata_read28(uint32_t lba, uint8_t* buffer);

#endif
