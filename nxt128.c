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
#include "nxt128.h"
#include "nxt128_tables.h"

#ifndef USE_NXT128
#error Set USE_NXT128 in nxt_common.h to use NXT128
#endif

#if ((NXT128_TOTAL_ROUNDS <= 1) || (NXT128_TOTAL_ROUNDS > 255))
#error NXT128_TOTAL_ROUNDS must be greater than 1 and smaller than 256
#elif ((defined NXT128_UNROLL_LOOPS) && (NXT128_TOTAL_ROUNDS != 16) \
       && (NXT128_TOTAL_ROUNDS != 12))
#error NXT128_TOTAL_ROUNDS must be 12 or 16 when NXT128_UNROLL_LOOPS is set
#endif

#define SIGMA_MU8_0(x, y)                 \
      tbsm0_128[((x & 0xff000000) >> 23)] \
    ^ tbsm1_128[((x & 0x00ff0000) >> 15)] \
    ^ tbsm2_128[((x & 0x0000ff00) >>  7)] \
    ^ tbsm3_128[((x & 0x000000ff) <<  1)] \
    ^ tbsm4_128[((y & 0xff000000) >> 23)] \
    ^ tbsm5_128[((y & 0x00ff0000) >> 15)] \
    ^ tbsm6_128[((y & 0x0000ff00) >>  7)] \
    ^ tbsm7_128[((y & 0x000000ff) <<  1)]

#define SIGMA_MU8_1(x, y)                     \
      tbsm0_128[((x & 0xff000000) >> 23) + 1] \
    ^ tbsm1_128[((x & 0x00ff0000) >> 15) + 1] \
    ^ tbsm2_128[((x & 0x0000ff00) >>  7) + 1] \
    ^ tbsm3_128[((x & 0x000000ff) <<  1) + 1] \
    ^ tbsm4_128[((y & 0xff000000) >> 23) + 1] \
    ^ tbsm5_128[((y & 0x00ff0000) >> 15) + 1] \
    ^ tbsm6_128[((y & 0x0000ff00) >>  7) + 1] \
    ^ tbsm7_128[((y & 0x000000ff) <<  1) + 1]

#define SIGMA(x)                       \
      tbs0_128[(x & 0xff000000) >> 24] \
    ^ tbs1_128[(x & 0x00ff0000) >> 16] \
    ^ tbs2_128[(x & 0x0000ff00) >>  8] \
    ^ tbs3_128[(x & 0x000000ff)      ]

#define F64(i)                              \
{                                           \
    tmp0 = x0 ^ x1 ^ rk[0];                 \
    tmp1 = x2 ^ x3 ^ rk[1];                 \
                                            \
    smu0 = rk[2] ^ SIGMA_MU8_0(tmp0, tmp1); \
    smu1 = rk[3] ^ SIGMA_MU8_1(tmp0, tmp1); \
                                            \
    f0 = rk[0] ^ SIGMA(smu0);               \
    f1 = rk[1] ^ SIGMA(smu1);               \
}

#define ELMOR128(i)    \
{                      \
    F64(i);            \
                       \
    tmp0 = x0 ^ f0;    \
    x0 = NXT_OR(tmp0); \
    x1 ^= f0;          \
                       \
    tmp1 = x2 ^ f1;    \
    x2 = NXT_OR(tmp1); \
    x3 ^= f1;          \
    rk += 4;           \
}

#define ELMIO128(i)    \
{                      \
    F64(i);            \
                       \
    tmp0 = x0 ^ f0;    \
    x0 = NXT_IO(tmp0); \
    x1 ^= f0;          \
                       \
    tmp1 = x2 ^ f1;    \
    x2 = NXT_IO(tmp1); \
    x3 ^= f1;          \
    rk -= 4;           \
}

#define ELMID128(i) \
{                   \
    F64(i);         \
                    \
    x0 ^= f0;       \
    x1 ^= f0;       \
                    \
    x2 ^= f1;       \
    x3 ^= f1;       \
}

#ifdef NXT128_INIT_TABLES
void nxt128_init_tables(void)
{
    int i;
    uint8 s;

    for (i = 0; i < 256; i++) {
        s = sbox[i];

        tbsm0_128[2 * i]     =
            ((uint32) s << 24)
          ^ ((uint32) s << 16)
          ^ ((uint32) (nxt_alpha_mul(s) ^ s) << 8)
          ^ ((uint32) (nxt_alpha_div(nxt_alpha_div(s) ^ s)));

        tbsm0_128[2 * i + 1] =
            ((uint32) nxt_alpha_mul(s) << 24)
          ^ ((uint32) nxt_alpha_mul(nxt_alpha_mul(s))<< 16)
          ^ ((uint32) nxt_alpha_div(s) << 8)
          ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s)));

        tbsm1_128[2 * i] =
            ((uint32) s << 24)
          ^ ((uint32) (nxt_alpha_mul(s) ^ s) << 16)
          ^ ((uint32) (nxt_alpha_div(nxt_alpha_div(s) ^ s)) << 8)
          ^ ((uint32) nxt_alpha_mul(s));

        tbsm1_128[2 * i + 1] =
            ((uint32) nxt_alpha_mul(nxt_alpha_mul(s)) << 24)
          ^ ((uint32) nxt_alpha_div(s) << 16)
          ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s)) << 8)
          ^ ((uint32) s);

        tbsm2_128[2 * i] =
            ((uint32) s << 24)
          ^ ((uint32) (nxt_alpha_div(nxt_alpha_div(s) ^ s)) << 16)
          ^ ((uint32) nxt_alpha_mul(s) << 8)
          ^ ((uint32) nxt_alpha_mul(nxt_alpha_mul(s)));

        tbsm2_128[2 * i + 1] =
            ((uint32) nxt_alpha_div(s) << 24)
          ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s)) << 16)
          ^ ((uint32) s << 8)
          ^ ((uint32) (nxt_alpha_mul(s) ^ s));

        tbsm3_128[2 * i] =
            ((uint32) s << 24)
          ^ ((uint32) nxt_alpha_mul(s) << 16)
          ^ ((uint32) nxt_alpha_mul(nxt_alpha_mul(s))<< 8)
          ^ ((uint32) nxt_alpha_div(s));

        tbsm3_128[2 * i + 1] =
            ((uint32) nxt_alpha_div(nxt_alpha_div(s)) << 24)
          ^ ((uint32) s << 16)
          ^ ((uint32) (nxt_alpha_mul(s) ^ s) << 8)
          ^ ((uint32) (nxt_alpha_div(nxt_alpha_div(s) ^ s)));

        tbsm4_128[2 * i] =
            ((uint32) s << 24)
          ^ ((uint32) nxt_alpha_mul(nxt_alpha_mul(s))<< 16)
          ^ ((uint32) nxt_alpha_div(s) << 8)
          ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s)));

        tbsm4_128[2 * i + 1] =
             ((uint32) s << 24)
           ^ ((uint32) (nxt_alpha_mul(s) ^ s) << 16)
           ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s) ^ s) << 8)
           ^ ((uint32) nxt_alpha_mul(s));

        tbsm5_128[2 * i] = ((uint32) s << 24)
           ^ ((uint32) nxt_alpha_div(s) << 16)
           ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s)) << 8)
           ^ ((uint32) s);

       tbsm5_128[2 * i + 1] =
             ((uint32) (nxt_alpha_mul(s) ^ s) << 24)
           ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s) ^ s) << 16)
           ^ ((uint32) nxt_alpha_mul(s) << 8)
           ^ ((uint32) nxt_alpha_mul(nxt_alpha_mul(s)));

        tbsm6_128[2 * i] =
             ((uint32) s << 24)
           ^ ((uint32) nxt_alpha_div(nxt_alpha_div(s)) << 16)
           ^ ((uint32) s << 8)
           ^ ((uint32) (nxt_alpha_mul(s) ^ s));

        tbsm6_128[2 * i + 1] =
             ((uint32) nxt_alpha_div(nxt_alpha_div(s) ^ s) << 24)
           ^ ((uint32) nxt_alpha_mul(s) << 16)
           ^ ((uint32) nxt_alpha_mul(nxt_alpha_mul(s)) << 8)
           ^ ((uint32) nxt_alpha_div(s));

        tbsm7_128[2 * i] =
             ((uint32) (nxt_alpha_mul(s) ^ s) << 24)
           ^ ((uint32) s << 16)
           ^ ((uint32) s << 8)
           ^ ((uint32) s);

        tbsm7_128[2 * i + 1] =
             ((uint32) s << 24)
           ^ ((uint32) s << 16)
           ^ ((uint32) s << 8)
           ^ ((uint32) s);

        tbs0_128[i] = (uint32) s << 24;
        tbs1_128[i] = (uint32) s << 16;
        tbs2_128[i] = (uint16) s <<  8;
        tbs3_128[i] =          s      ;
    }
}
#endif /* NXT128_INIT_TABLES */

void nxt128_encrypt(nxt128_ctx *ctx, const uint8 *in, uint8 *out)
{
    uint32 x0, x1, x2, x3;
    uint32 tmp0, tmp1;
    uint32 f0, f1;
    uint32 smu0, smu1;
    uint32 *rk;

#ifndef NXT128_UNROLL_LOOPS
    int i;
#endif

    PACK32(in     , &x0);
    PACK32(in +  4, &x1);
    PACK32(in +  8, &x2);
    PACK32(in + 12, &x3);

    rk = ctx->rk;

#ifdef NXT128_UNROLL_LOOPS
#if NXT128_TOTAL_ROUNDS == 16
    ELMOR128( 0); ELMOR128( 4); ELMOR128( 8); ELMOR128(12); ELMOR128(16);
    ELMOR128(20); ELMOR128(24); ELMOR128(28); ELMOR128(32); ELMOR128(36);
    ELMOR128(40); ELMOR128(44); ELMOR128(48); ELMOR128(52); ELMOR128(56);
    ELMID128(60);
#elif NXT128_TOTAL_ROUNDS == 12
    ELMOR128( 0); ELMOR128( 4); ELMOR128( 8); ELMOR128(12); ELMOR128(16);
    ELMOR128(20); ELMOR128(24); ELMOR128(28); ELMOR128(32); ELMOR128(36);
    ELMOR128(40);
    ELMID128(44);
#endif
#else /* !NXT128_UNROLL_LOOPS */
    for (i = 0; i < (NXT128_TOTAL_ROUNDS - 1); i++) {
        ELMOR128(0);
    }
    ELMID128(0);
#endif /* !NXT128_UNROLL_LOOPS */

    UNPACK32(x0, out     );
    UNPACK32(x1, out +  4);
    UNPACK32(x2, out +  8);
    UNPACK32(x3, out + 12);
}

void nxt128_decrypt(nxt128_ctx *ctx, const uint8 *in, uint8 *out)
{
    uint32 x0, x1, x2, x3;
    uint32 tmp0, tmp1;
    uint32 f0, f1;
    uint32 smu0, smu1;
    uint32 *rk;

#ifndef NXT128_UNROLL_LOOPS
    int i;
#endif

    PACK32(in     , &x0);
    PACK32(in +  4, &x1);
    PACK32(in +  8, &x2);
    PACK32(in + 12, &x3);

    rk = ctx->rk + 4 * (NXT128_TOTAL_ROUNDS - 1);

#ifdef NXT128_UNROLL_LOOPS
#if NXT128_TOTAL_ROUNDS == 16
    ELMIO128(60); ELMIO128(56); ELMIO128(52); ELMIO128(48); ELMIO128(44);
    ELMIO128(40); ELMIO128(36); ELMIO128(32); ELMIO128(28); ELMIO128(24);
    ELMIO128(20); ELMIO128(16); ELMIO128(12); ELMIO128( 8); ELMIO128( 4);
    ELMID128(0);
#elif NXT128_TOTAL_ROUNDS == 12
    ELMIO128(44); ELMIO128(40); ELMIO128(36); ELMIO128(32); ELMIO128(28);
    ELMIO128(24); ELMIO128(20); ELMIO128(16); ELMIO128(12); ELMIO128( 8);
    ELMIO128( 4);
    ELMID128(0);
#endif
#else /* !NXT128_UNROLL_LOOPS */
    for (i = 0; i < (NXT128_TOTAL_ROUNDS - 1); i++) {
        ELMIO128(0);
    }
    ELMID128(0);
#endif /* !NXT128_UNROLL_LOOPS */

    UNPACK32(x0, out     );
    UNPACK32(x1, out +  4);
    UNPACK32(x2, out +  8);
    UNPACK32(x3, out + 12);
}

#define MIX128(x, y)                           \
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

void nxt128_dnl128(const uint8 *mkey, uint32 *reg,
                   uint32 *rkey, uint8 eq)
{
    uint32 t0[8];
    uint32 t1[8];
    uint32 dkey32[8];
    uint32 x0, x1, x2, x3;
    uint32 tmp0, tmp1;
    uint32 smu0, smu1;
    uint32 f0, f1;
    uint32 *rk;
    uint32 lfsr_value;
    uint8 dkey[32];
    int i;

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

    /* NL128-part */
    rk = dkey32;

    PACK32(dkey     , dkey32    );
    PACK32(dkey +  4, dkey32 + 1);
    PACK32(dkey +  8, dkey32 + 2);
    PACK32(dkey + 12, dkey32 + 3);
    PACK32(dkey + 16, dkey32 + 4);
    PACK32(dkey + 20, dkey32 + 5);
    PACK32(dkey + 24, dkey32 + 6);
    PACK32(dkey + 28, dkey32 + 7);

    t1[0] = SIGMA_MU8_0(dkey32[0], dkey32[1]);
    t1[1] = SIGMA_MU8_1(dkey32[0], dkey32[1]);
    t1[2] = SIGMA_MU8_0(dkey32[2], dkey32[3]);
    t1[3] = SIGMA_MU8_1(dkey32[2], dkey32[3]);
    t1[4] = SIGMA_MU8_0(dkey32[4], dkey32[5]);
    t1[5] = SIGMA_MU8_1(dkey32[4], dkey32[5]);
    t1[6] = SIGMA_MU8_0(dkey32[6], dkey32[7]);
    t1[7] = SIGMA_MU8_1(dkey32[6], dkey32[7]);

    MIX128(t1, t0);

    PACK32(pad     , t1    );
    PACK32(pad +  4, t1 + 1);
    PACK32(pad +  8, t1 + 2);
    PACK32(pad + 12, t1 + 3);
    PACK32(pad + 16, t1 + 4);
    PACK32(pad + 20, t1 + 5);
    PACK32(pad + 24, t1 + 6);
    PACK32(pad + 28, t1 + 7);

    t0[0] ^= t1[0];
    t0[1] ^= t1[1];
    t0[2] ^= t1[2];
    t0[3] ^= t1[3];
    t0[4] ^= t1[4];
    t0[5] ^= t1[5];
    t0[6] ^= t1[6];
    t0[7] ^= t1[7];

    if (eq) {
        t0[0] = ~t0[0];
        t0[1] = ~t0[1];
        t0[2] = ~t0[2];
        t0[3] = ~t0[3];
        t0[4] = ~t0[4];
        t0[5] = ~t0[5];
        t0[6] = ~t0[6];
        t0[7] = ~t0[7];
    }

    x0 = SIGMA(t0[0]) ^ SIGMA(t0[4]);
    x1 = SIGMA(t0[1]) ^ SIGMA(t0[5]);
    x2 = SIGMA(t0[2]) ^ SIGMA(t0[6]);
    x3 = SIGMA(t0[3]) ^ SIGMA(t0[7]);

    ELMOR128(0);
    ELMID128(0);

    rkey[0] = x0;
    rkey[1] = x1;
    rkey[2] = x2;
    rkey[3] = x3;
}

void nxt128_ks(nxt128_ctx *ctx, const uint8 *key, uint16 key_len)
{
    const uint16 ek = 256;
    uint8 pk[32];
    uint8 mk[32];
    uint32 reg;
    int i;
    uint8 eq;

    assert((key_len % 8 == 0) && (key_len <= 256));

    /* Initialization and LFSR Pre-clocking */
    reg = 0x006a0000 | ((NXT128_TOTAL_ROUNDS << 8) & 0x0000ff00)
          | ((~NXT128_TOTAL_ROUNDS) & 0x000000ff);
    if (reg & 0x1) {
        reg ^= 0x100001b;
    }
    reg >>= 1;

    eq = (key_len == ek);

    if (key_len < ek) {
        nxt_p(key, (key_len >> 3), pk, ek);
        nxt_m(pk, mk, ek);

        for (i = 0; i < NXT128_TOTAL_ROUNDS; i++) {
            nxt128_dnl128(mk, &reg, &ctx->rk[i * 4], eq);
        }
    } else {
        for (i = 0; i < NXT128_TOTAL_ROUNDS; i++) {
            nxt128_dnl128(key, &reg, &ctx->rk[i * 4], eq);
        }
    }
}

