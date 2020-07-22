#include <stdio.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include "message.h"
#include "algorithm.h"

void rev_txt(unsigned char * txt, unsigned char size) {
    unsigned char i, tmp[size];

    memcpy(tmp, txt, size);
    for(i = 0; i < size; i++) txt[i] = tmp[size - 1 - i];
}

void dec_to_bin(unsigned char number, unsigned char * tmp, unsigned char size) {
    unsigned char i;

    for (i = 0; i < size; i++) tmp[i] = number >> i & 1;
    rev_txt(tmp, size);
}

void dec_to_bin_msg(unsigned char *mes, unsigned char* bin_mes){
    unsigned char i, tmp[8];

    for (i = 0; i < 8; i++){
        dec_to_bin(mes[i],tmp,8);
        memcpy(&bin_mes[i * 8], tmp, 8);
    }
}

void bin_chunk(const unsigned char * txt, unsigned char * bin_mes,unsigned char len) {
    unsigned char i, tmp[4];

    for (i = 0; i < len ; i++) {
        dec_to_bin(txt[i] / 16, tmp, 4);
        memcpy(&bin_mes[i * 8], tmp, 4);
        dec_to_bin(txt[i] % 16, tmp, 4);
        memcpy(&bin_mes[i * 8 + 4], tmp, 4);
    }
}

int check_file_dec(char * path_to_file, int flags){
    int file_descriptor;

    if ((file_descriptor = open(path_to_file, flags, 0600)) == -1)
        printf("Error with file!\n");

    return file_descriptor;
}

int validate_data(int n_read){
    if(n_read != 8 * sizeof(unsigned char))
        if (n_read != EOF) {
            printf("File corrupted! Rode %d/8\n", n_read);
            return -1;
        }

    return 0;
}

void store_data(const unsigned char * message, int file_descriptor){
    unsigned char i, j, letter;

    for (i = 0; i < 64; i += 8) {
        letter = 0;
        for (j = 0; j < 8; j++) letter += (unsigned char)pow(2, 7 - j) * message[j + i];
        write(file_descriptor, &letter ,sizeof(unsigned char));
    }
}

void dec_msg(unsigned char * mes, unsigned char * key) {
    unsigned char i, bin_mes[64];

    dec_to_bin_msg(mes,bin_mes);
    alloc_keys();
    xor_key(key);

    for (i = 0; i < 3; i++) {
        crt_key16(key, 2 - i);
        decrypt(bin_mes);
    }

    store_data(bin_mes, STDOUT_FILENO);
    free_mem();
}

void dec(char * user_key, char * path_to_file) {
    int             n_read, file_descriptor;
    unsigned char   bin_mes[8];

    if ((file_descriptor = check_file_dec(path_to_file, O_RDONLY)) == -1) return;
    printf("Decrypted message:\n");

    while ((n_read = read(file_descriptor, bin_mes,  sizeof(unsigned char) * 8))){
        if (validate_data(n_read) == -1) break;
        dec_msg(bin_mes, (unsigned char *) user_key);
    }

    close(file_descriptor);
}

void enc_msg(const unsigned char * txt, unsigned char * key, int file_descriptor) {
    unsigned char i, bin_mes[64];

    alloc_keys();
    bin_chunk(txt, bin_mes, 8);
    xor_key(key);

    for (i = 0; i < 3; i++) {
        crt_key0(key, i);
        encrypt(bin_mes);
    }

    store_data(bin_mes, file_descriptor);
    free_mem();
}

void enc(char * user_key, char * path_to_file) {
    unsigned char msg[8];
    int file_descriptor;

    if ((file_descriptor = check_file_dec(path_to_file, O_WRONLY | O_CREAT | O_EXCL)) == -1) return;
    printf("Enter message to encrypt:\n");
    bzero(msg,8);

    while (read(STDIN_FILENO, msg, 8)) {
        enc_msg(msg, (unsigned char*)user_key, file_descriptor);
        if(strstr((const char*)msg, "\n")) break;
        bzero(msg,8);
    }

    close(file_descriptor);
}
