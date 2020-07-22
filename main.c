#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "message.h"

void err_exit(char *argv){
    printf("usage: %s [-e|-d] [key] [path]\n", argv);
    printf("-e -> encrypt to file\n");
    printf("-d -> decrypt from file\n");
    printf("-key -> must contains 24 characters\n");
    printf("-path -> path to file where (store | is stored) message\n");
    exit(-1);
}

int main(int argc, char** argv) {
    if (argc != 4) err_exit(argv[0]);
    if (strlen(argv[2]) != 24) err_exit(argv[0]);

    if (!strcmp(argv[1],"-e")) enc(argv[2],argv[3]);
    else if (!strcmp(argv[1],"-d")) dec(argv[2],argv[3]);
    else err_exit(argv[0]);

    return 0;
}