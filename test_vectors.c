/*
 * IDEA NXT encryption algorithm test vectors
 * Issue date: 02/25/2006
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nxt64.h"
#include "nxt128.h"

static const unsigned char pt[16] = {0x01, 0x23, 0x45, 0x67,
                                     0x89, 0xab, 0xcd, 0xef,
                                     0xfe, 0xdc, 0xba, 0x98,
                                     0x76, 0x54, 0x32, 0x10};

static const unsigned char key[32] = {0x00, 0x11, 0x22, 0x33,
                                      0x44, 0x55, 0x66, 0x77,
                                      0x88, 0x99, 0xaa, 0xbb,
                                      0xcc, 0xdd, 0xee, 0xff,
                                      0xff, 0xee, 0xdd, 0xcc,
                                      0xbb, 0xaa, 0x99, 0x88,
                                      0x77, 0x66, 0x55, 0x44,
                                      0x33, 0x22, 0x11, 0x00};

static void print_block64(const char *title, const unsigned char *block)
{
    int i;

    printf("%s", title);
    for (i = 0; i < NXT64_BLOCK_SIZE; i++) {
        printf("%02x ", block[i]);
    }
    printf("\n");
}

static void print_block128(const char *title, const unsigned char *block)
{
    int i;

    printf("%s", title);
    for (i = 0; i < NXT128_BLOCK_SIZE; i++) {
        printf("%02x ", block[i]);
    }
    printf("\n");
}

static void nxt64_vect_cmp(const unsigned char *vector,
                           const unsigned char *in)
{
    unsigned char out[2 * NXT64_BLOCK_SIZE + 1];
    int i;

    out[2 * NXT64_BLOCK_SIZE] = 0;

    for (i = 0; i < NXT64_BLOCK_SIZE; i++) {
       sprintf((char *) out + 2 * i, "%02x", in[i]);
    }

    if (strcmp((char *) vector, (char *) out)) {
        fprintf(stderr, "Test failedn");
        exit(EXIT_FAILURE);
    }
}

static void nxt128_vect_cmp(const unsigned char *vector,
                            const unsigned char *in)
{
    unsigned char out[2 * NXT128_BLOCK_SIZE + 1];
    int i;

    out[2 * NXT128_BLOCK_SIZE] = 0;

    for (i = 0; i < NXT128_BLOCK_SIZE ; i++) {
       sprintf((char *) out + 2 * i, "%02x", in[i]);
    }

    if (strcmp((char *) vector, (char *) out)) {
        fprintf(stderr, "Test failedn");
        exit(EXIT_FAILURE);
    }
}

static void nxt64_64_test(unsigned char *ct)
{
    unsigned char newpt[8];

    nxt64_ctx ctx;
    nxt64_ks(&ctx, key, 64);

    nxt64_encrypt(&ctx, pt, ct);
    print_block64("Encrypted: ", ct);

    nxt64_decrypt(&ctx, ct, newpt);
    print_block64("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 8)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void nxt64_128_test(unsigned char *ct)
{
    unsigned char newpt[8];
    nxt64_ctx ctx;
    nxt64_ks(&ctx, key, 128);

    nxt64_encrypt(&ctx, pt, ct);
    print_block64("Encrypted: ", ct);

    nxt64_decrypt(&ctx, ct, newpt);
    print_block64("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 8)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void nxt64_192_test(unsigned char *ct)
{
    unsigned char newpt[8];
    nxt64_ctx ctx;
    nxt64_ks(&ctx, key, 192);

    nxt64_encrypt(&ctx, pt, ct);
    print_block64("Encrypted: ", ct);

    nxt64_decrypt(&ctx, ct, newpt);
    print_block64("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 8)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void nxt64_256_test(unsigned char *ct)
{
    unsigned char newpt[8];
    nxt64_ctx ctx;
    nxt64_ks(&ctx, key, 256);

    nxt64_encrypt(&ctx, pt, ct);
    print_block64("Encrypted: ", ct);

    nxt64_decrypt(&ctx, ct, newpt);
    print_block64("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 8)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void nxt128_64_test(unsigned char *ct)
{
    unsigned char newpt[16];
    nxt128_ctx ctx;
    nxt128_ks(&ctx, key, 64);

    nxt128_encrypt(&ctx, pt, ct);
    print_block128("Encrypted: ", ct);

    nxt128_decrypt(&ctx, ct, newpt);
    print_block128("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 16)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void nxt128_128_test(unsigned char *ct)
{
    unsigned char newpt[16];
    nxt128_ctx ctx;
    nxt128_ks(&ctx, key, 128);

    nxt128_encrypt(&ctx, pt, ct);
    print_block128("Encrypted: ", ct);

    nxt128_decrypt(&ctx, ct, newpt);
    print_block128("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 16)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void nxt128_192_test(unsigned char *ct)
{
    unsigned char newpt[16];
    nxt128_ctx ctx;
    nxt128_ks(&ctx, key, 192);

    nxt128_encrypt(&ctx, pt, ct);
    print_block128("Encrypted: ", ct);

    nxt128_decrypt(&ctx, ct, newpt);
    print_block128("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 16)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

static void nxt128_256_test(unsigned char *ct)
{
    unsigned char newpt[16];
    nxt128_ctx ctx;
    nxt128_ks(&ctx, key, 256);

    nxt128_encrypt(&ctx, pt, ct);
    print_block128("Encrypted: ", ct);

    nxt128_decrypt(&ctx, ct, newpt);
    print_block128("Decrypted: ", newpt);

    if (memcmp(pt, newpt, 16)) {
        fprintf(stderr, "Test failed\n");
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    unsigned char *vectors64[] =
    {   /* nxt64-64 */
        (unsigned char *) "200e1f5847d8a2ce",
        /* nxt64-128 */
        (unsigned char *) "b85d6b766dce952e",
        /* nxt64-192 */
        (unsigned char *) "2741d7963406daca",
        /* nxt64-256 */
        (unsigned char *) "8a4edfbc36bef7f6"
    };

    unsigned char *vectors128[] =
    {   /* nxt128-64 */
        (unsigned char *) "1eecbc7deb66e7dae1a7876d90c0b239",
        /* nxt128-128 */
        (unsigned char *) "849e0f0682f50cd588ae073006a10bee",
        /* nxt128-192 */
        (unsigned char *) "5934214ecba2d5fd58c261b28261b1bc",
        /* nxt128-256 */
        (unsigned char *) "45ccb1030f67b768247f530266bc4996"
    };

    unsigned char  ct64[ 8];
    unsigned char ct128[16];

    printf("IDEA NXT Test Vectors:\n\n");

#if 0
    nxt64_init_tables();
    nxt128_init_tables();
#endif

    printf("NXT64 64 bits key:\n");
    nxt64_64_test(ct64);
    nxt64_vect_cmp(vectors64[0], ct64);

    printf("NXT64 128 bits key:\n");
    nxt64_128_test(ct64);
    nxt64_vect_cmp(vectors64[1], ct64);

    printf("NXT64 192 bits key:\n");
    nxt64_192_test(ct64);
    nxt64_vect_cmp(vectors64[2], ct64);

    printf("NXT64 256 bits key:\n");
    nxt64_256_test(ct64);
    nxt64_vect_cmp(vectors64[3], ct64);

    printf("NXT128 64 bits key:\n");
    nxt128_64_test(ct128);
    nxt128_vect_cmp(vectors128[0], ct128);

    printf("NXT128 128 bits key:\n");
    nxt128_128_test(ct128);
    nxt128_vect_cmp(vectors128[1], ct128);

    printf("NXT128 192 bits key:\n");
    nxt128_192_test(ct128);
    nxt128_vect_cmp(vectors128[2], ct128);

    printf("NXT128 256 bits key:\n");
    nxt128_256_test(ct128);
    nxt128_vect_cmp(vectors128[3], ct128);

    printf("\nAll tests passed\n");

    return 0;
}

