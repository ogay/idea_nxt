/*
 * IDEA NXT encryption algorithm implementation
 * Issue date: 02/25/2006
 *
 * Copyright (C) 2006 Olivier Gay <olivier.gay@a3.epfl.ch>
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
#ifndef NXT64_H
#define NXT64_H

#ifdef __cplusplus
extern "C" {
#endif

#define NXT64_TOTAL_ROUNDS 16

#ifndef NXT_TYPES
#define NXT_TYPES
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
#endif

typedef struct {
    uint32 rk[NXT64_TOTAL_ROUNDS * 2];
} nxt64_ctx;

void nxt64_ks(nxt64_ctx *ctx, const uint8 *key, uint16 key_len);
void nxt64_encrypt(nxt64_ctx *ctx, const uint8 *in, uint8 *out);
void nxt64_decrypt(nxt64_ctx *ctx, const uint8 *in, uint8 *out);
void nxt64_init_tables(void);

#define NXT64_BLOCK_SIZE 8

#ifdef __cplusplus
}
#endif

#endif /* !NXT64_H */

