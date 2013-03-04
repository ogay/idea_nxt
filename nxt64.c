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
#include <assert.h>

#include "nxt_common.h"
#include "nxt64.h"
#include "nxt64_tables.h"

#ifndef USE_NXT64
#error Set USE_NXT64 in nxt_common.h to use NXT64
#endif

#if ((NXT64_TOTAL_ROUNDS <= 1) || (NXT64_TOTAL_ROUNDS > 255))
#error NXT64_TOTAL_ROUNDS must be greater than 1 and smaller than 256
#elif ((defined NXT64_UNROLL_LOOPS) && (NXT64_TOTAL_ROUNDS != 16) \
       && (NXT64_TOTAL_ROUNDS != 12))
#error NXT64_TOTAL_ROUNDS must be 12 or 16 when NXT64_UNROLL_LOOPS is set
#endif

#define SIGMA_MU4(x)                   \
      tbsm0_64[(x & 0xff000000) >> 24] \
    ^ tbsm1_64[(x & 0x00ff0000) >> 16] \
    ^ tbsm2_64[(x & 0x0000ff00) >>  8] \
    ^ tbsm3_64[(x & 0x000000ff)      ]

#define SIGMA(x)                      \
      tbs0_64[(x & 0xff000000) >> 24] \
    ^ tbs1_64[(x & 0x00ff0000) >> 16] \
    ^ tbs2_64[(x & 0x0000ff00) >>  8] \
    ^ tbs3_64[(x & 0x000000ff)      ]

#define F32(i)                    \
{                                 \
        f = x0 ^ x1 ^ rk[0];      \
        f = rk[1] ^ SIGMA_MU4(f); \
        f = rk[0] ^ SIGMA(f);     \
}

#define LMOR64(i)        \
{                        \
        F32(i);          \
        x0 ^= f;         \
        x0 = NXT_OR(x0); \
        x1 ^= f;         \
        rk += 2;         \
}

#define LMIO64(i)        \
{                        \
        F32(i);          \
        x0 ^= f;         \
        x0 = NXT_IO(x0); \
        x1 ^= f;         \
        rk -= 2;         \
}

#define LMID64(i) \
{                 \
        F32(i);   \
        x0 ^= f;  \
        x1 ^= f;  \
}

#ifdef NXT64_INIT_TABLES
void nxt64_init_tables(void)
{
    int i;
    uint8 s;

    for (i = 0; i < 256; i++) {
        s = sbox[i];

        tbsm0_64[i] =   ((uint32) s << 24)
                      ^ ((uint32) s << 16)
                      ^ ((uint32) (nxt_alpha_div(s) ^ s) << 8)
                      ^ ((uint32) nxt_alpha_mul(s));
        tbsm1_64[i] =   ((uint32) s << 24)
                      ^ ((uint32) (nxt_alpha_div(s) ^ s) << 16)
                      ^ ((uint32) nxt_alpha_mul(s) << 8)
                      ^ ((uint32) s);
        tbsm2_64[i] =   ((uint32) s << 24)
                      ^ ((uint32) nxt_alpha_mul(s) << 16)
                      ^ ((uint32) s << 8)
                      ^ ((uint32) (nxt_alpha_div(s) ^ s));
        tbsm3_64[i] =   ((uint32) nxt_alpha_mul(s) << 24)
                      ^ ((uint32) s << 16)
                      ^ ((uint32) s << 8)
                      ^ ((uint32) s);

        tbs0_64[i] = (uint32) s << 24;
        tbs1_64[i] = (uint32) s << 16;
        tbs2_64[i] = (uint16) s <<  8;
        tbs3_64[i] =          s      ;
    }
}
#endif /* NXT64_INIT_TABLES */

void nxt64_encrypt(nxt64_ctx *ctx, const uint8 *in, uint8 *out)
{
    uint32 x0, x1;
    uint32 f;
    uint32 *rk;

#ifndef NXT64_UNROLL_LOOPS
    int i;
#endif

    PACK32(in    , &x0);
    PACK32(in + 4, &x1);

    rk = ctx->rk;

#ifdef NXT64_UNROLL_LOOPS
#if NXT64_TOTAL_ROUNDS == 16
    LMOR64( 0); LMOR64( 2); LMOR64( 4); LMOR64( 6); LMOR64( 8); LMOR64(10);
    LMOR64(12); LMOR64(14); LMOR64(16); LMOR64(18); LMOR64(20); LMOR64(22);
    LMOR64(24); LMOR64(26); LMOR64(28);
    LMID64(30);
#endif
#if NXT64_TOTAL_ROUNDS == 12
    LMOR64( 0); LMOR64( 2); LMOR64( 4); LMOR64( 6); LMOR64( 8); LMOR64(10);
    LMOR64(12); LMOR64(14); LMOR64(16); LMOR64(18); LMOR64(20);
    LMID64(22);
#endif
#else /* !NXT64_UNROLL_LOOPS */
    for (i = 0; i < (NXT64_TOTAL_ROUNDS - 1); i++) {
        LMOR64(0);
    }
    LMID64(0);
#endif /* !NXT64_UNROLL_LOOPS */

    UNPACK32(x0, out    );
    UNPACK32(x1, out + 4);
}

void nxt64_decrypt(nxt64_ctx *ctx, const uint8 *in, uint8 *out)
{
    uint32 x0, x1;
    uint32 f;
    uint32 *rk;

#ifndef NXT64_UNROLL_LOOPS
    int i;
#endif

    PACK32(in    , &x0);
    PACK32(in + 4, &x1);

    rk = ctx->rk + 2 * (NXT64_TOTAL_ROUNDS - 1);

#ifdef NXT64_UNROLL_LOOPS
#if NXT64_TOTAL_ROUNDS == 16

    LMIO64(30); LMIO64(28); LMIO64(26); LMIO64(24); LMIO64(22); LMIO64(20);
    LMIO64(18); LMIO64(16); LMIO64(14); LMIO64(12); LMIO64(10); LMIO64( 8);
    LMIO64( 6); LMIO64( 4); LMIO64( 2);
    LMID64(0);
#endif
#if NXT64_TOTAL_ROUNDS == 12
    LMIO64(22); LMIO64(20); LMIO64(18); LMIO64(16); LMIO64(14); LMIO64(12);
    LMIO64(10); LMIO64( 8); LMIO64( 6); LMIO64( 4); LMIO64( 2);
    LMID64(0);
#endif
#else /* !NXT64_UNROLL_LOOPS */
    for (i = 0; i < (NXT64_TOTAL_ROUNDS - 1); i++) {
        LMIO64(0);
    }
    LMID64(0);
#endif /* !NXT64_UNROLL_LOOPS */

    UNPACK32(x0, out    );
    UNPACK32(x1, out + 4);
}

#define MIX64(x, y)                            \
{                                              \
    *(y    ) = *(x + 1) ^ *(x + 2) ^ *(x + 3); \
    *(y + 1) = *(x    ) ^ *(x + 2) ^ *(x + 3); \
    *(y + 2) = *(x    ) ^ *(x + 1) ^ *(x + 3); \
    *(y + 3) = *(x    ) ^ *(x + 1) ^ *(x + 2); \
}

#define MIX64H(x, y)                           \
{                                              \
    *(y    ) = *(x + 2) ^ *(x + 4) ^ *(x + 6); \
    *(y + 1) = *(x + 3) ^ *(x + 5) ^ *(x + 7); \
    *(y + 2) = *(x    ) ^ *(x + 4) ^ *(x + 6); \
    *(y + 3) = *(x + 1) ^ *(x + 5) ^ *(x + 7); \
    *(y + 4) = *(x    ) ^ *(x + 2) ^ *(x + 6); \
    *(y + 5) = *(x + 1) ^ *(x + 3) ^ *(x + 7); \
    *(y + 6) = *(x    ) ^ *(x + 2) ^ *(x + 4); \
    *(y + 7) = *(x + 1) ^ *(x + 3) ^ *(x + 5); \
}

static void nxt64_dnl64(const uint8 *mkey, uint32 *reg,
                        uint32 *rkey, uint8 eq)
{
    uint32 t0[4];
    uint32 t1[4];
    uint32 dkey32[4];
    uint32 x0, x1;
    uint32 f;
    uint32 *rk;
    uint32 lfsr_value;
    int i;
    uint8 dkey[16];

    /* D-part */
    for (i = 0; i < 5; i++) {
        LFSR(reg, lfsr_value);
        dkey[0 + i * 3] = mkey[0 + i * 3] ^ ((uint8) (lfsr_value >> 16));
        dkey[1 + i * 3] = mkey[1 + i * 3] ^ ((uint8) (lfsr_value >> 8));
        dkey[2 + i * 3] = mkey[2 + i * 3] ^ ((uint8) (lfsr_value));
    }

    LFSR(reg, lfsr_value);
    dkey[15] = mkey[15] ^ ((uint8) (lfsr_value >> 16));

    /* NL64-part */
    rk = dkey32;

    PACK32(dkey     , dkey32    );
    PACK32(dkey +  4, dkey32 + 1);
    PACK32(dkey +  8, dkey32 + 2);
    PACK32(dkey + 12, dkey32 + 3);

    t0[0] = SIGMA_MU4(dkey32[0]);
    t0[1] = SIGMA_MU4(dkey32[1]);
    t0[2] = SIGMA_MU4(dkey32[2]);
    t0[3] = SIGMA_MU4(dkey32[3]);

    MIX64(t0, t1);

    PACK32(pad     , t0    );
    PACK32(pad +  4, t0 + 1);
    PACK32(pad +  8, t0 + 2);
    PACK32(pad + 12, t0 + 3);

    t1[0] ^= t0[0];
    t1[1] ^= t0[1];
    t1[2] ^= t0[2];
    t1[3] ^= t0[3];

    if (eq) {
        t1[0] = ~t1[0];
        t1[1] = ~t1[1];
        t1[2] = ~t1[2];
        t1[3] = ~t1[3];
    }

    x0 = SIGMA(t1[0]) ^ SIGMA(t1[2]);
    x1 = SIGMA(t1[1]) ^ SIGMA(t1[3]);

    LMOR64(0);
    LMID64(0);

    rkey[0] = x0;
    rkey[1] = x1;
}

static void nxt64_dnl64h(const uint8 *mkey, uint32 *reg,
                         uint32 *rkey, uint8 eq)
{
    uint32 t0[8];
    uint32 t1[8];
    uint32 dkey32[8];
    uint32 x0, x1;
    uint32 f;
    uint32 *rk;
    uint32 lfsr_value;
    int i;
    uint8 dkey[32];

    /* D-part */
    for (i = 0; i < 10; i++) {
        LFSR(reg, lfsr_value);
        dkey[0 + i * 3] = mkey[0 + i * 3] ^ ((uint8) (lfsr_value >> 16));
        dkey[1 + i * 3] = mkey[1 + i * 3] ^ ((uint8) (lfsr_value >> 8));
        dkey[2 + i * 3] = mkey[2 + i * 3] ^ ((uint8) (lfsr_value));
    }

    LFSR(reg, lfsr_value);
    dkey[30] = mkey[30] ^ ((uint8) (lfsr_value >> 16));
    dkey[31] = mkey[31] ^ ((uint8) (lfsr_value >> 8));

    /* NL64h-part */
    rk = dkey32;

    PACK32(dkey     , dkey32    );
    PACK32(dkey +  4, dkey32 + 1);
    PACK32(dkey +  8, dkey32 + 2);
    PACK32(dkey + 12, dkey32 + 3);
    PACK32(dkey + 16, dkey32 + 4);
    PACK32(dkey + 20, dkey32 + 5);
    PACK32(dkey + 24, dkey32 + 6);
    PACK32(dkey + 28, dkey32 + 7);

    t0[0] = SIGMA_MU4(dkey32[0]);
    t0[1] = SIGMA_MU4(dkey32[1]);
    t0[2] = SIGMA_MU4(dkey32[2]);
    t0[3] = SIGMA_MU4(dkey32[3]);
    t0[4] = SIGMA_MU4(dkey32[4]);
    t0[5] = SIGMA_MU4(dkey32[5]);
    t0[6] = SIGMA_MU4(dkey32[6]);
    t0[7] = SIGMA_MU4(dkey32[7]);

    MIX64H(t0, t1);

    PACK32(pad     , t0    );
    PACK32(pad +  4, t0 + 1);
    PACK32(pad +  8, t0 + 2);
    PACK32(pad + 12, t0 + 3);
    PACK32(pad + 16, t0 + 4);
    PACK32(pad + 20, t0 + 5);
    PACK32(pad + 24, t0 + 6);
    PACK32(pad + 28, t0 + 7);

    t1[0] ^= t0[0];
    t1[1] ^= t0[1];
    t1[2] ^= t0[2];
    t1[3] ^= t0[3];
    t1[4] ^= t0[4];
    t1[5] ^= t0[5];
    t1[6] ^= t0[6];
    t1[7] ^= t0[7];

    if (eq) {
        t1[0] = ~t1[0];
        t1[1] = ~t1[1];
        t1[2] = ~t1[2];
        t1[3] = ~t1[3];
        t1[4] = ~t1[4];
        t1[5] = ~t1[5];
        t1[6] = ~t1[6];
        t1[7] = ~t1[7];
    }

    x0 = SIGMA(t1[0]) ^ SIGMA(t1[1]) ^ SIGMA(t1[4]) ^ SIGMA(t1[5]);
    x1 = SIGMA(t1[2]) ^ SIGMA(t1[3]) ^ SIGMA(t1[6]) ^ SIGMA(t1[7]);

    LMOR64(0);
    LMOR64(0);
    LMOR64(0);
    LMID64(0);

    rkey[0] = x0;
    rkey[1] = x1;
}

static void nxt64_ks64(nxt64_ctx *ctx, const uint8 *key, uint16 key_len)
{
    const uint16 ek = 128;
    uint8 pk[32];
    uint8 mk[32];
    uint32 reg;
    int i;
    uint8 eq;

    /* Pre-clock LFSR */
    reg = 0x006a0000 | ((NXT64_TOTAL_ROUNDS << 8) & 0x0000ff00)
          | ((~NXT64_TOTAL_ROUNDS) & 0x000000ff);
    if (reg & 0x00000001)
        reg ^= 0x100001b;

    reg >>= 1;

    eq = (key_len == ek);

    if (key_len < ek) {
        nxt_p(key, (key_len >> 3), pk, ek);
        nxt_m(pk, mk, ek);

        for (i = 0; i < NXT64_TOTAL_ROUNDS; i++) {
            nxt64_dnl64(mk, &reg, &ctx->rk[i * 2], eq);
        }
    } else {
        for (i = 0; i < NXT64_TOTAL_ROUNDS; i++) {
            nxt64_dnl64(key, &reg, &ctx->rk[i * 2], eq);
        }
    }
}

static void nxt64_ks64h(nxt64_ctx *ctx, const uint8 *key, uint16 key_len)
{
    const uint16 ek = 256;
    uint8 pk[32];
    uint8 mk[32];
    uint32 reg;
    int i;
    uint8 eq;

    /* Pre-clock LFSR */
    reg = 0x006a0000 | ((NXT64_TOTAL_ROUNDS << 8) & 0x0000ff00)
          | ((~NXT64_TOTAL_ROUNDS) & 0x000000ff);
    if (reg & 0x1)
        reg ^= 0x100001b;

    reg >>= 1;

    eq = (key_len == ek);

    if (key_len < ek) {
        nxt_p(key, (key_len >> 3), pk, ek);
        nxt_m(pk, mk, ek);

        for (i = 0; i < NXT64_TOTAL_ROUNDS; i++) {
            nxt64_dnl64h(mk, &reg, &ctx->rk[i * 2], eq);
        }
    } else {
        for (i = 0; i < NXT64_TOTAL_ROUNDS; i++) {
            nxt64_dnl64h(key, &reg, &ctx->rk[i * 2], eq);
        }
    }
}

void nxt64_ks(nxt64_ctx *ctx, const uint8 *key, uint16 key_len)
{
    assert((key_len % 8 == 0) && (key_len <= 256));

    if (key_len <= 128)
        nxt64_ks64(ctx, key, key_len);
    else
        nxt64_ks64h(ctx, key, key_len);
}

