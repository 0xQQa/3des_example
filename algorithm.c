#include "get_constans.h"
#include "algorithm.h"
#include "message.h"
#include <string.h>
#include <stdlib.h>
unsigned char * l_key, * r_key, * iter_key;

void alloc_keys(){
    r_key = malloc(sizeof(unsigned char) * 28);
    l_key = malloc(sizeof(unsigned char) * 28);
    iter_key = malloc(sizeof(unsigned char) * 48);
}

void free_mem() {
    free(iter_key);
    free(r_key);
    free(l_key);
}

void s_box(unsigned char * old_key, unsigned int iter, unsigned char * s_key) {
    unsigned char tmp_xy[8], to_bin[4], x , y;

    memcpy(tmp_xy, &old_key[iter * 6], 6);
    y = tmp_xy[0] * 2 + tmp_xy[5];
    x = tmp_xy[1] * 8 + tmp_xy[2] * 4 + tmp_xy[3] * 2 + tmp_xy[4];
    dec_to_bin(get_s(iter,y,x), to_bin, 4);
    memcpy(&s_key[iter * 4], to_bin, 4);
}

void xor_key(unsigned char * key){
    unsigned char i, j;

    for (i = 0; i < 8; i++)
        for(j = 0; j < 3; j++)
            key[i + (j % 3) * 8] ^= key[i + ((j + 1) % 3) * 8];
}

void f_func(const unsigned char * sec_key, unsigned char * ret_key) {
    unsigned char tmp_e_bit[48],  s_key[32], i;

    for (i = 0; i < 48; i++) tmp_e_bit[i] = sec_key[get_e_bit(i)] ^ iter_key[i];
    for (i = 0; i < 8; i++) s_box(tmp_e_bit, i, s_key);
    for (i = 0; i < 32; i++) ret_key[i] = s_key[get_p(i) ];
}

///ENCRYPT PART

void crt_key0(unsigned char * key, int iter) {
    unsigned char key_0[64], tmp[64], key_chunk[8], i;

    memcpy(key_chunk,&key[iter * 8], 8);
    bin_chunk(key_chunk, key_0, 8);
    for (i = 0; i < 56; i++) tmp[i] = key_0[get_pc1(i)];
    memcpy(l_key, tmp, 28);
    memcpy(r_key, &tmp[28], 28);
}

void shl_key(unsigned char * key, int iter) {
    unsigned char tmp, i, j;

    for (i = 0; i < get_shifts(iter); i++) {
        tmp = key[0];
        for (j = 0; j < 27; j++) key[j] = key[j + 1];
        key[27] = tmp;
    }
}

void crt_nxt_key(int iter) {
    unsigned char i;

    shl_key(l_key, iter);
    shl_key(r_key, iter);
    for (i = 0; i < 48; i++) iter_key[i] = get_pc2(i)  > 27 ? r_key[get_pc2(i) - 28] : l_key[get_pc2(i)];
}

void encrypt(unsigned char * final_msg) {
    unsigned char l_enc[32], r_enc[32], tmp_enc[32], p_key[32], tmp_msg[64] ,tmp_lr_key[64], i, j;

    for (i = 0; i < 64; i++) tmp_lr_key[i] = final_msg[get_ip1(i)];
    memcpy(l_enc, tmp_lr_key, 32);
    memcpy(r_enc, &tmp_lr_key[32], 32);

    for (i = 0; i < 16; i++) {
        memcpy(tmp_enc, l_enc, 32);
        memcpy(l_enc, r_enc, 32);
        crt_nxt_key(i);
        f_func(r_enc, p_key);
        for (j = 0; j < 32; j++) r_enc[j] = tmp_enc[j] ^ p_key[j];
    }

    memcpy(tmp_msg, r_enc, 32);
    memcpy(&tmp_msg[32], l_enc, 32);
    for (i = 0; i < 64; i++) final_msg[i] = tmp_msg[get_ip_1(i)];
}

///DECRYPT PART

void crt_key16(unsigned char *key, int iter){
    unsigned char i;

    crt_key0(key, iter);
    for (i = 0; i < 16; i++) crt_nxt_key(i);
}

void shr_key(unsigned char *key, int iter) {
    unsigned char tmp, i, j;

    for (i = 0; i < get_shifts(iter); i++) {
        tmp = key[27];
        for (j = 27; j > 0; j--) key[j] = key[j - 1];
        key[0] = tmp;
    }
}

void crt_prev_key(int iter) {
    unsigned int i;

    shr_key(l_key, 15 - iter);
    shr_key(r_key, 15 - iter);
    for (i = 0; i < 48; i++) iter_key[i] = get_pc2(i) > 27 ? r_key[get_pc2(i) - 28] : l_key[get_pc2(i)];
}

void decrypt(unsigned char *enc_mes) {
    unsigned char rev_r[32], rev_l[32], new_tmp[64], f_ret[32], tmp_r[32], tmp_mes[64], i, j;

    for ( i = 0; i < 64; i++) new_tmp[get_ip_1(63 - i)] = enc_mes[63 - i];
    memcpy(rev_r, new_tmp, 32);
    memcpy(rev_l, &new_tmp[32], 32);

    for ( i = 0; i < 16; i++) {
        memcpy(tmp_r, rev_l, 32);
        f_func(rev_l, f_ret);
        for ( j = 0; j < 32; j++) rev_l[j] = rev_r[j] ^ f_ret[j];
        crt_prev_key(i);
        memcpy(rev_r, tmp_r, 32);
    }

    memcpy(tmp_mes, rev_l, 32);
    memcpy(&tmp_mes[32], rev_r, 32);
    for (i = 0; i < 64; i++) enc_mes[get_ip1(i)] = tmp_mes[i];
}