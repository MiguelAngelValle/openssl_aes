#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x86intrin.h"
#pragma warning(disable : 4996)

#pragma intrinsic(__rdtsc)
#define NTEST 100000

void measured_function(volatile int* var) { (*var) = 1; }

int main()
{
    unsigned char text[] = "This is so much fun!";
    unsigned char enc_out[80];
    unsigned char dec_out[80];

    unsigned char key[32];
    int rc = RAND_bytes(key, sizeof(key));
    unsigned long err = ERR_get_error();
    if (rc != 1)
        return -1;

    AES_KEY enc_key, dec_key;

    int variable = 0;
    uint64_t start, end;

    printf("Calentamiento...\n");
    for (int i = 0; i < NTEST; i++)
        measured_function(&variable);

    AES_set_encrypt_key(key, 128, &enc_key);

    AES_encrypt(text, enc_out, &enc_key);

    AES_set_decrypt_key(key, 128, &dec_key);
    AES_decrypt(enc_out, dec_out, &dec_key);

    printf("original:\t");
    int stop = sizeof(text) - 1;
    for (int i = 0; *(text + i) != 0x00; i++)
        printf("%c ", *(text + i));
    printf("\nencrypted:\t");
    for (int i = 0; *(enc_out + i) != 0x00; i++)
        printf("%.2X ", *(enc_out + i));
    printf("\ndecrypted:\t");
    for (int i = 0; i < 16; i++)
        printf("%c ", *(dec_out + i));
    printf("\n");
}
