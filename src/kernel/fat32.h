#ifndef FAT32_H
#define FAT32_H

#include <stdint.h>

typedef void (*fat32_print_fn)(const char *text);

int fat32_init(void);
int fat32_is_mounted(void);
int fat32_ls(const char *path, fat32_print_fn print);
int fat32_chdir(const char *path);
int fat32_mkdir(const char *path);
void fat32_pwd(fat32_print_fn print);

#endif
