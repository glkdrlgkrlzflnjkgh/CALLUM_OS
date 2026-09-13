#include "fat32.h"
#include "block_device.h"
#include "string.h"

#define FAT32_SECTOR_SIZE 512U
#define FAT32_MAX_PATH 256U
#define FAT32_MAX_COMPONENT 12U
#define FAT32_ENTRY_SIZE 32U
#define FAT32_ATTR_VOLUME 0x08U
#define FAT32_ATTR_DIRECTORY 0x10U
#define FAT32_ATTR_LFN 0x0FU
#define FAT32_EOC 0x0FFFFFF8U

struct fat32_fs {
    uint32_t partition_lba;
    uint32_t fat_lba;
    uint32_t data_lba;
    uint32_t sectors_per_fat;
    uint32_t sectors_per_cluster;
    uint32_t root_cluster;
    uint32_t total_clusters;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint8_t mounted;
};

struct fat32_dirent {
    char name[13];
    uint8_t attributes;
    uint32_t cluster;
};

static struct fat32_fs fs;
static uint8_t sector[FAT32_SECTOR_SIZE];
static uint8_t zero_sector[FAT32_SECTOR_SIZE];
static uint32_t cwd_cluster;
static char cwd_path[FAT32_MAX_PATH] = "/";

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int valid_cluster(uint32_t cluster) {
    return cluster >= 2U && cluster < 0x0FFFFFF7U;
}

static uint32_t cluster_lba(uint32_t cluster) {
    return fs.data_lba + (cluster - 2U) * fs.sectors_per_cluster;
}

static int read_sector(uint32_t lba) {
    return ata_read28(lba, sector) == 0 ? 0 : -1;
}

static int write_sector(uint32_t lba, const uint8_t *data) {
    return ata_write28(lba, data) == 0 ? 0 : -1;
}

static int fat_next(uint32_t cluster, uint32_t *next) {
    uint32_t fat_sector = fs.fat_lba + (cluster * 4U) / FAT32_SECTOR_SIZE;
    uint32_t offset = (cluster * 4U) % FAT32_SECTOR_SIZE;

    if (read_sector(fat_sector) < 0 || offset + 4U > FAT32_SECTOR_SIZE)
        return -1;

    *next = read_u32(&sector[offset]) & 0x0FFFFFFFU;
    return 0;
}

static int fat_set(uint32_t cluster, uint32_t value) {
    uint8_t fat_count;
    uint32_t fat_sector = fs.fat_lba + (cluster * 4U) / FAT32_SECTOR_SIZE;
    uint32_t offset = (cluster * 4U) % FAT32_SECTOR_SIZE;

    if (offset + 4U > FAT32_SECTOR_SIZE) return -1;
    for (fat_count = 0; fat_count < fs.fat_count; ++fat_count) {
        if (read_sector(fat_sector + fat_count * fs.sectors_per_fat) < 0)
            return -1;
        sector[offset] = (uint8_t)value;
        sector[offset + 1U] = (uint8_t)(value >> 8);
        sector[offset + 2U] = (uint8_t)(value >> 16);
        sector[offset + 3U] = (uint8_t)((sector[offset + 3U] & 0xF0U) | (value >> 24));
        if (write_sector(fat_sector + fat_count * fs.sectors_per_fat, sector) < 0)
            return -1;
    }
    return 0;
}

static int allocate_cluster(uint32_t *result) {
    uint32_t cluster;
    uint32_t next;

    for (cluster = 2U; cluster < fs.total_clusters + 2U; ++cluster) {
        if (fat_next(cluster, &next) < 0) return -1;
        if (next == 0) {
            if (fat_set(cluster, FAT32_EOC) < 0) return -1;
            *result = cluster;
            return 0;
        }
    }
    return -1;
}

static int clear_cluster(uint32_t cluster) {
    uint32_t index;
    for (index = 0; index < fs.sectors_per_cluster; ++index) {
        if (write_sector(cluster_lba(cluster) + index, zero_sector) < 0) return -1;
    }
    return 0;
}

static void make_short_name(const uint8_t *entry, char *name) {
    uint32_t out = 0;
    uint32_t i;
    int has_extension = 0;

    for (i = 0; i < 8 && entry[i] != ' '; ++i) {
        char c = (char)entry[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        name[out++] = c;
    }

    for (i = 8; i < 11; ++i) {
        if (entry[i] != ' ') {
            has_extension = 1;
            break;
        }
    }

    if (has_extension) {
        name[out++] = '.';
        for (i = 8; i < 11 && entry[i] != ' '; ++i) {
            char c = (char)entry[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            name[out++] = c;
        }
    }
    name[out] = '\0';
}

static int entry_from_bytes(const uint8_t *entry, struct fat32_dirent *result) {
    uint32_t cluster;

    if (entry[0] == 0x00 || entry[0] == 0xE5 || entry[11] == FAT32_ATTR_LFN ||
        (entry[11] & FAT32_ATTR_VOLUME))
        return 0;

    make_short_name(entry, result->name);
    result->attributes = entry[11];
    cluster = ((uint32_t)read_u16(&entry[20]) << 16) | read_u16(&entry[26]);
    result->cluster = cluster;
    return 1;
}

static int same_name(const char *left, const char *right) {
    while (*left && *right) {
        char a = *left++;
        char b = *right++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return *left == '\0' && *right == '\0';
}

static int scan_directory(uint32_t directory, int (*visitor)(const struct fat32_dirent *, void *), void *context) {
    uint32_t cluster = directory;

    while (valid_cluster(cluster)) {
        uint32_t sector_index;
        for (sector_index = 0; sector_index < fs.sectors_per_cluster; ++sector_index) {
            uint32_t offset;
            if (read_sector(cluster_lba(cluster) + sector_index) < 0) return -1;

            for (offset = 0; offset < FAT32_SECTOR_SIZE; offset += FAT32_ENTRY_SIZE) {
                struct fat32_dirent entry;
                if (sector[offset] == 0x00) return 0;
                if (entry_from_bytes(&sector[offset], &entry) && visitor(&entry, context) != 0)
                    return 1;
            }
        }

        if (fat_next(cluster, &cluster) < 0) return -1;
        if (cluster >= FAT32_EOC) return 0;
    }
    return -1;
}

struct find_context {
    const char *name;
    struct fat32_dirent *result;
};

static int find_visitor(const struct fat32_dirent *entry, void *context) {
    struct find_context *find = (struct find_context *)context;
    if (!same_name(entry->name, find->name)) return 0;
    *find->result = *entry;
    return 1;
}

static int find_entry(uint32_t directory, const char *name, struct fat32_dirent *result) {
    struct find_context context = { name, result };
    return scan_directory(directory, find_visitor, &context) == 1 ? 0 : -1;
}

static int next_component(const char **path, char *component) {
    uint32_t length = 0;
    const char *cursor = *path;

    while (*cursor == '/') ++cursor;
    if (*cursor == '\0') {
        *path = cursor;
        return 0;
    }

    while (*cursor && *cursor != '/') {
        if (length + 1U >= FAT32_MAX_COMPONENT) return -1;
        component[length++] = *cursor++;
    }
    component[length] = '\0';
    *path = cursor;
    return 1;
}

static int resolve_path(const char *path, struct fat32_dirent *result) {
    uint32_t directory = path[0] == '/' ? fs.root_cluster : cwd_cluster;
    char component[FAT32_MAX_COMPONENT];
    int component_result;

    while ((component_result = next_component(&path, component)) > 0) {
        if (same_name(component, ".")) continue;
        if (same_name(component, "..")) {
            if (directory != fs.root_cluster && find_entry(directory, "..", result) == 0)
                directory = result->cluster;
            continue;
        }
        if (find_entry(directory, component, result) < 0) return -1;
        directory = result->cluster;
        while (*path == '/') ++path;
    }

    if (component_result < 0) return -1;
    result->cluster = directory;
    result->attributes = FAT32_ATTR_DIRECTORY;
    result->name[0] = '\0';
    return 0;
}

static int append_path_component(const char *component) {
    uint32_t length = (uint32_t)strlen(cwd_path);
    uint32_t component_length = (uint32_t)strlen(component);

    if (length == 1U) {
        if (length + component_length >= FAT32_MAX_PATH) return -1;
        memcpy(&cwd_path[1], component, component_length + 1U);
    } else {
        if (length + component_length + 1U >= FAT32_MAX_PATH) return -1;
        cwd_path[length] = '/';
        memcpy(&cwd_path[length + 1U], component, component_length + 1U);
    }
    return 0;
}

static int make_directory_name(const char *name, uint8_t *entry) {
    uint32_t base_length = 0;
    uint32_t extension_length = 0;
    uint32_t index = 0;
    int extension = 0;

    memset(entry, ' ', FAT32_ENTRY_SIZE);
    while (name[index] && name[index] != '/') {
        char c = name[index++];
        if (c == '.') {
            if (extension) return -1;
            extension = 1;
            continue;
        }
        if (c <= ' ' || c == ':' || c == '*' || c == '?' || c == '"' ||
            c == '<' || c == '>' || c == '|') return -1;
        if (!extension) {
            if (base_length >= 8U) return -1;
            entry[base_length++] = (uint8_t)(c >= 'a' && c <= 'z' ? c - 32 : c);
        } else {
            if (extension_length >= 3U) return -1;
            entry[8U + extension_length++] =
                (uint8_t)(c >= 'a' && c <= 'z' ? c - 32 : c);
        }
    }
    if (!name[0] || name[index] == '/' || !base_length) return -1;
    entry[11] = FAT32_ATTR_DIRECTORY;
    return 0;
}

static int add_directory_entry(uint32_t directory, const uint8_t *new_entry) {
    uint32_t cluster = directory;

    while (valid_cluster(cluster)) {
        uint32_t sector_index;
        for (sector_index = 0; sector_index < fs.sectors_per_cluster; ++sector_index) {
            uint32_t offset;
            if (read_sector(cluster_lba(cluster) + sector_index) < 0) return -1;
            for (offset = 0; offset < FAT32_SECTOR_SIZE; offset += FAT32_ENTRY_SIZE) {
                if (sector[offset] == 0x00 || sector[offset] == 0xE5) {
                    memcpy(&sector[offset], new_entry, FAT32_ENTRY_SIZE);
                    return write_sector(cluster_lba(cluster) + sector_index, sector);
                }
            }
        }
        if (fat_next(cluster, &cluster) < 0) return -1;
        if (cluster >= FAT32_EOC) return -2;
    }
    return -1;
}

static int split_parent_path(const char *path, char *parent, char *name) {
    uint32_t length = (uint32_t)strlen(path);
    uint32_t last_slash = length;
    uint32_t index;

    while (length && path[length - 1U] == '/') --length;
    if (!length || length >= FAT32_MAX_PATH) return -1;
    for (index = length; index > 0; --index) {
        if (path[index - 1U] == '/') {
            last_slash = index - 1U;
            break;
        }
    }

    {
        uint32_t name_start = last_slash == length ? 0 : last_slash + 1U;
        uint32_t name_length = length - name_start;
        if (!name_length || name_length >= FAT32_MAX_COMPONENT) return -1;
        memcpy(name, &path[name_start], name_length);
        name[name_length] = '\0';
    }
    if (last_slash == length) {
        parent[0] = '.';
        parent[1] = '\0';
    } else if (last_slash == 0) {
        parent[0] = '/';
        parent[1] = '\0';
    } else {
        memcpy(parent, path, last_slash);
        parent[last_slash] = '\0';
    }
    return 0;
}

static void remove_path_component(void) {
    uint32_t length = (uint32_t)strlen(cwd_path);
    if (length <= 1U) return;
    while (length > 1U && cwd_path[length - 1U] != '/') --length;
    cwd_path[length > 1U ? length - 1U : 1U] = '\0';
}

static int update_path(const char *path) {
    char component[FAT32_MAX_COMPONENT];
    int component_result;

    if (path[0] == '/') {
        cwd_path[0] = '/';
        cwd_path[1] = '\0';
    }

    while ((component_result = next_component(&path, component)) > 0) {
        if (same_name(component, ".")) continue;
        if (same_name(component, "..")) {
            remove_path_component();
        } else if (append_path_component(component) < 0) {
            return -1;
        }
    }
    return component_result < 0 ? -1 : 0;
}

static int path_escapes_root(const char *path) {
    char component[FAT32_MAX_COMPONENT];
    uint32_t depth = 0U;
    const char *current = path;
    uint32_t index;
    int component_result;

    if (path[0] != '/') {
        if (cwd_path[0] != '/') return 1;
        if (cwd_path[1] != '\0') ++depth;
        for (index = 1; cwd_path[index]; ++index)
            if (cwd_path[index] == '/') ++depth;
    }

    while ((component_result = next_component(&current, component)) > 0) {
        if (same_name(component, ".")) continue;
        if (same_name(component, "..")) {
            if (depth == 0U) return 1;
            --depth;
        } else {
            ++depth;
        }
    }
    return component_result < 0 ? 1 : 0;
}

static int ls_visitor(const struct fat32_dirent *entry, void *context) {
    fat32_print_fn print = (fat32_print_fn)context;
    char line[16];
    uint32_t length = (uint32_t)strlen(entry->name);

    if (length > sizeof(line) - 2U) length = sizeof(line) - 2U;
    memcpy(line, entry->name, length);
    if (entry->attributes & FAT32_ATTR_DIRECTORY) line[length++] = '/';
    line[length++] = '\n';
    line[length] = '\0';
    print(line);
    return 0;
}

int fat32_init(void) {
    uint32_t partition_lba;
    uint32_t total_sectors;
    uint32_t data_sectors;

    memset(&fs, 0, sizeof(fs));
    if (read_sector(0) < 0 || sector[510] != 0x55 || sector[511] != 0xAA) return -1;

    partition_lba = read_u32(&sector[446 + 8]);
    if (sector[446 + 4] != 0x0B && sector[446 + 4] != 0x0C) return -1;
    if (partition_lba == 0) return -1;
    fs.partition_lba = partition_lba;

    if (read_sector(fs.partition_lba) < 0 || read_u16(&sector[11]) != FAT32_SECTOR_SIZE)
        return -1;
    fs.reserved_sectors = read_u16(&sector[14]);
    fs.fat_count = sector[16];
    fs.sectors_per_cluster = sector[13];
    fs.sectors_per_fat = read_u32(&sector[36]);
    fs.root_cluster = read_u32(&sector[44]);
    total_sectors = read_u32(&sector[32]);

    if (!fs.reserved_sectors || !fs.fat_count || !fs.sectors_per_cluster ||
        !fs.sectors_per_fat || !valid_cluster(fs.root_cluster)) return -1;

    fs.fat_lba = fs.partition_lba + fs.reserved_sectors;
    fs.data_lba = fs.fat_lba + fs.fat_count * fs.sectors_per_fat;
    data_sectors = total_sectors - fs.reserved_sectors -
                   fs.fat_count * fs.sectors_per_fat;
    if (!data_sectors || data_sectors / fs.sectors_per_cluster < 1U) return -1;
    fs.total_clusters = data_sectors / fs.sectors_per_cluster;

    fs.mounted = 1;
    cwd_cluster = fs.root_cluster;
    cwd_path[0] = '/';
    cwd_path[1] = '\0';
    return 0;
}

int fat32_is_mounted(void) {
    return fs.mounted != 0;
}

int fat32_ls(const char *path, fat32_print_fn print) {
    struct fat32_dirent directory;
    if (!fs.mounted || !print || resolve_path(path, &directory) < 0 ||
        !(directory.attributes & FAT32_ATTR_DIRECTORY)) return -1;
    return scan_directory(directory.cluster, ls_visitor, print) < 0 ? -1 : 0;
}

int fat32_chdir(const char *path) {
    struct fat32_dirent directory;
    char old_path[FAT32_MAX_PATH];

    if (!fs.mounted || path_escapes_root(path) || resolve_path(path, &directory) < 0 ||
        !(directory.attributes & FAT32_ATTR_DIRECTORY)) return -1;

    memcpy(old_path, cwd_path, sizeof(old_path));
    if (update_path(path) < 0) {
        memcpy(cwd_path, old_path, sizeof(cwd_path));
        return -1;
    }

    cwd_cluster = directory.cluster;
    return 0;
}

int fat32_mkdir(const char *path) {
    char parent_path[FAT32_MAX_PATH];
    char name[FAT32_MAX_COMPONENT];
    uint8_t entry[FAT32_ENTRY_SIZE];
    struct fat32_dirent parent;
    struct fat32_dirent existing;
    uint32_t cluster;

    if (!fs.mounted || split_parent_path(path, parent_path, name) < 0 ||
        make_directory_name(name, entry) < 0 ||
        resolve_path(parent_path, &parent) < 0 ||
        !(parent.attributes & FAT32_ATTR_DIRECTORY)) return -1;
    if (find_entry(parent.cluster, name, &existing) == 0) return -1;
    if (allocate_cluster(&cluster) < 0 || clear_cluster(cluster) < 0) return -1;

    entry[20] = (uint8_t)(cluster >> 16);
    entry[21] = (uint8_t)(cluster >> 24);
    entry[26] = (uint8_t)cluster;
    entry[27] = (uint8_t)(cluster >> 8);
    entry[28] = (uint8_t)(cluster >> 16);
    entry[29] = (uint8_t)(cluster >> 24);
    if (add_directory_entry(parent.cluster, entry) < 0) return -1;

    memset(entry, ' ', sizeof(entry));
    entry[0] = '.';
    entry[11] = FAT32_ATTR_DIRECTORY;
    entry[20] = (uint8_t)(cluster >> 16);
    entry[21] = (uint8_t)(cluster >> 24);
    entry[26] = (uint8_t)cluster;
    entry[27] = (uint8_t)(cluster >> 8);
    entry[28] = (uint8_t)(cluster >> 16);
    entry[29] = (uint8_t)(cluster >> 24);
    memcpy(sector, entry, FAT32_ENTRY_SIZE);
    memset(&sector[FAT32_ENTRY_SIZE], 0, FAT32_SECTOR_SIZE - FAT32_ENTRY_SIZE);
    if (write_sector(cluster_lba(cluster), sector) < 0) return -1;

    entry[0] = '.';
    entry[1] = '.';
    entry[20] = (uint8_t)(parent.cluster >> 16);
    entry[21] = (uint8_t)(parent.cluster >> 24);
    entry[26] = (uint8_t)parent.cluster;
    entry[27] = (uint8_t)(parent.cluster >> 8);
    entry[28] = (uint8_t)(parent.cluster >> 16);
    entry[29] = (uint8_t)(parent.cluster >> 24);
    memcpy(&sector[FAT32_ENTRY_SIZE], entry, FAT32_ENTRY_SIZE);
    return write_sector(cluster_lba(cluster), sector);
}

void fat32_pwd(fat32_print_fn print) {
    if (print && fs.mounted) print(cwd_path);
}

void fat32_prompt(fat32_print_fn print) {
    if (!print) return;
    print("COSH:");
    if (fs.mounted) print(cwd_path);
    else print("?");
    print("> ");
}
