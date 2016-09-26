/*
 * Copyright (c) 2016 Sean Parkinson (sparkinson@iprimus.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* This code implements the Hash_DRBG as specfied in -
 *   NIST SP 800-90A Rev. 1: Recommendation for Random Number Generation Using
 *                           Deterministic RBGs.
 */

#include "hash.h"

/** The maximum digest output length. */
#define HASH_MAX_DIGEST_LEN		64

/** The seed length for up to 256-bit hashes. */
#define RANDOM_HASH_256_SEED_LEN     (440/8)
/** The seed length for up to 512-bit hashes. */
#define RANDOM_HASH_512_SEED_LEN     (888/8)
/** The maximum seed length. */
#define RANDOM_HASH_MAX_SEED_LEN     (888/8)

/** The Hash_DRBG */
typedef struct random_hash_st
{
    /** State element v. One extra byte for data prefix when hashing. */
    uint8_t v[1 + RANDOM_HASH_MAX_SEED_LEN];
    /** State element c - constant. */
    uint8_t c[RANDOM_HASH_MAX_SEED_LEN];
    /** Temprory buffer. */
    uint8_t t[RANDOM_HASH_MAX_SEED_LEN];
    /** Count of generation operations.  */
    uint64_t reseed_cnt;
    /** Hash object.  */
    HASH *hash;
    /** Length of the digest output. */
    int hash_len;
    /** Length of seed for this implementation. */
    uint16_t seed_len;
} RANDOM_HASH;

int RANDOM_HASH_SHA1_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
#define RANDOM_HASH_SHA1_final		RANDOM_HASH_final
#define RANDOM_HASH_SHA1_reseed		RANDOM_HASH_reseed
#define RANDOM_HASH_SHA1_gen		RANDOM_HASH_gen

int RANDOM_HASH_SHA224_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
#define RANDOM_HASH_SHA224_final	RANDOM_HASH_final
#define RANDOM_HASH_SHA224_reseed	RANDOM_HASH_reseed
#define RANDOM_HASH_SHA224_gen		RANDOM_HASH_gen

int RANDOM_HASH_SHA256_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
#define RANDOM_HASH_SHA256_final	RANDOM_HASH_final
#define RANDOM_HASH_SHA256_reseed	RANDOM_HASH_reseed
#define RANDOM_HASH_SHA256_gen		RANDOM_HASH_gen

int RANDOM_HASH_SHA384_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
#define RANDOM_HASH_SHA384_final	RANDOM_HASH_final
#define RANDOM_HASH_SHA384_reseed	RANDOM_HASH_reseed
#define RANDOM_HASH_SHA384_gen		RANDOM_HASH_gen

int RANDOM_HASH_SHA512_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
#define RANDOM_HASH_SHA512_final	RANDOM_HASH_final
#define RANDOM_HASH_SHA512_reseed	RANDOM_HASH_reseed
#define RANDOM_HASH_SHA512_gen		RANDOM_HASH_gen

int RANDOM_HASH_SHA512_224_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
#define RANDOM_HASH_SHA512_224_final	RANDOM_HASH_final
#define RANDOM_HASH_SHA512_224_reseed	RANDOM_HASH_reseed
#define RANDOM_HASH_SHA512_224_gen	RANDOM_HASH_gen

int RANDOM_HASH_SHA512_256_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
#define RANDOM_HASH_SHA512_256_final	RANDOM_HASH_final
#define RANDOM_HASH_SHA512_256_reseed	RANDOM_HASH_reseed
#define RANDOM_HASH_SHA512_256_gen	RANDOM_HASH_gen

void RANDOM_HASH_final(void *ctx);
int RANDOM_HASH_reseed(void *ctx, void *entropy, uint32_t elen,
    void *ainput, uint32_t alen);
int RANDOM_HASH_gen(void *ctx, void *ainput, uint32_t alen, void *out,
    uint32_t olen, uint32_t *glen);


