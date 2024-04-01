#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// clang -o clear_bpf_map clear_bpf_map.c -I/usr/include -L/usr/lib -lbpf

struct key_mem {
    char data[64];
};

int bpf_map_get_next_key_and_delete(int fd, const void *key, void *next_key, int *delete)
{
    int res = bpf_map_get_next_key(fd, key, next_key);
    if (*delete) {
        bpf_map_delete_elem(fd, key);
        *delete = 0;
    }
    return res;
}

int bpf_map_clear(int fd) 
{
    int delete_previous = 1;
    struct key_mem key = {0};
    struct key_mem prev_key = {0};

    do {

        int ret = bpf_map_get_next_key_and_delete(fd, &prev_key, &key, &delete_previous);
        if (ret == 0) {
            printf("Deleted something\n");
            prev_key = key;
            delete_previous = 1;
        } else {
            return 0;
        }

    } while(1);
}

int main(int argc, char **argv) 
{
    // Check that first and only argument is path
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path to BPF map>\n", argv[0]);
        return 1;
    }

    const char *map_path = argv[1];

    printf("Clearing BPF map at path: %s\n", map_path);

    // Open the BPF map
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Error opening BPF map: %s\n", strerror(errno));
        return 1;
    }

    // Clear the map
    bpf_map_clear(map_fd);

    printf("Map cleared successfully.\n");

    close(map_fd);
    return 0;
}
