#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface_name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const char *interface_name = argv[1]; 

    // Get the index of the network interface
    unsigned int interface_index = if_nametoindex(interface_name);
    if (interface_index == 0) {
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    printf("Interface %s has index: %u\n", interface_name, interface_index);

    return 0;
}
