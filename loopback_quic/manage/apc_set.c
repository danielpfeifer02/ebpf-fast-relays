#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <getopt.h>

int main(int argc, char **argv) {

    int option;
    char *map_path;
    char acn_flag;

    while ((option = getopt(argc, argv, "p:v:")) != -1) {
        switch (option) {
            case 'p':
                printf("Input path: %s\n", optarg);
                map_path = optarg;
                break;
            case 'v':
                printf("Setting value to %s\n", optarg);
                acn_flag = atoi(optarg);
                break;
            default:
                printf("Unknown option: %c\n", option);
                return 1;
        }
    }

    // Process remaining non-option arguments
    for (int i = optind; i < argc; i++) {
        printf("Argument: %s\n", argv[i]);
    }

    // Open the BPF map
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        printf("Error opening BPF map");
        return 1;
    }

    // key is always 0 since assumption is that map has only one element
    int key = 0; 
    int old_value = 0;
    // Retrieve BPF map element
    if (bpf_map_lookup_elem(map_fd, &key, &old_value) != 0) {
        printf("Error looking up BPF map element");
        close(map_fd);
        return 1;
    }

    if (old_value == acn_flag) {
        printf("Value is already set to %d\n", acn_flag);
        close(map_fd);
        return 0;
    }

    // Update BPF map element
    if (bpf_map_update_elem(map_fd, &key, &acn_flag, BPF_ANY) != 0) {
        printf("Error updating BPF map element");
        close(map_fd);
        return 1;
    }

    // Close the BPF map
    close(map_fd);

    printf("Value successfully set to %d\n", acn_flag);

    return 0;

}
