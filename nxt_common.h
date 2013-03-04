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
#ifndef NXT_COMMON_H
#define NXT_COMMON_H

#include <limits.h>

/*
 * These macros define which algorithms are used. You can comment one of the
 * two macros if you don't want to use both algorithms.
 */
#define USE_NXT64
#define USE_NXT128

/*
 * For each algorithm you can set or unset two macros. If set the macros
 * NXT64_UNROLL_LOOPS and NXT128_UNROLL_LOOPS unroll the main
 * encryption / decryption loop. You need a sufficient L1 code cache size
 * (especially for NXT128) to benefit from this option otherwise you will
 * suffer some penalty.
 *
 * This implementation of IDEA NXT uses tables in order to increase the
 * processing speed. By default the tables are precalculated. With
 * NXT64_INIT_TABLES and NXT128_INIT_TABLES macros the precalculated tables
 * will not be included in the object file and you will need to init the
 * tables with the nxt64_init_tables() and nxt128_init_tables() functions
 * before using the corresponding variant of IDEA NXT.
 *
 * The default number of rounds for both NXT64 and NXT128 is 16. You can
 * change the number of rounds by modifying the macros NXT64_TOTAL_ROUNDS
 * and NXT128_TOTAL_ROUNDS in nxt64.h and nxt128.h. The values can only be
 * changed at IDEA NXT compile time.
 */

/*
 * NXT64 macros
 */
#ifdef USE_NXT64

#if 0
#define NXT64_INIT_TABLES
#endif

#if 1
#define NXT64_UNROLL_LOOPS
#endif

#endif /* USE_NXT64 */

/*
 * NXT128 macros
 */
#ifdef USE_NXT128

#if 0
#define NXT128_INIT_TABLES
#endif

#if 0
#define NXT128_UNROLL_LOOPS
#endif

#endif /* USE_NXT128 */

#ifndef NXT_TYPES
#define NXT_TYPES
typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
#endif

/*
 * NXT_TYPES types are defined in nxt64.h, nxt128.h
 * and nxt_common.h (this file).
 */
#if (UCHAR_MAX != 255)
#error Please define uint8 as 8-bit unsigned integer type
#elif (USHRT_MAX != 65535)
#error Please define uint16 as a 16-bit unsigned integer type
#elif (UINT_MAX != 4294967295u)
#error Please define uint32 as a 32-bit unsigned integer type
#endif

#define UNPACK32(x, str)                \
{                                       \
    *((str) + 3) = (uint8) ((x)      ); \
    *((str) + 2) = (uint8) ((x) >>  8); \
    *((str) + 1) = (uint8) ((x) >> 16); \
    *((str)    ) =         ((x) >> 24); \
}

#define PACK32(str, x)            \
{                                 \
    *(x) = ( *((str) + 3)      )  \
         | ( *((str) + 2) <<  8)  \
         | ( *((str) + 1) << 16)  \
         | ( *((str)    ) << 24); \
}

#define IRRED_POLY 0x1f9

#define LFSR(reg, lfsr_value) \
do {                          \
    *reg = *reg << 1;         \
    if (*reg & 0x1000000)     \
        *reg ^= 0x100001b;    \
    lfsr_value = *reg;        \
} while(0)

#define NXT_OR(x) \
(x << 16) ^ (x >> 16) ^ (x & 0x0000ffff);

#define NXT_IO(x) \
(x << 16) ^ (x >> 16) ^ (x & 0xffff0000);

const uint8 pad[32];

#if ((defined NXT64_INIT_TABLES) || (defined NXT128_INIT_TABLES))
const uint8 sbox[256];

uint8 nxt_alpha_mul(uint8 x);
uint8 nxt_alpha_div(uint8 x);
#endif

void nxt_p(const uint8 *key, uint8 l, uint8 *pkey, uint16 ek);
void nxt_m(const uint8 *pkey, uint8 *mkey, uint16 ek);

#endif /* !NXT_COMMON_H */

