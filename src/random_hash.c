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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "random.h"
#include "random_hash.h"
#include "hash.h"

/**
 * Generates a hash of optional prefix data and up to three buffers of data.
 *
 * @param [in] hash  The hash object.
 * @param [in] pre   The prefix data.
 * @param [in] plen  The length of the prefix data.
 * @param [in] data  An array of three pointers.
 * @param [in] len   The length of data in the three pointers.
 * @param [in] out   The buffer to put the digest output into.
 * @return  A hash algorithm error.<br>
 *          0 otherwise.
 */
static int hash_data(HASH *hash, uint8_t *pre, uint16_t plen, void **data,
    uint32_t *len, void *out)
{
    int ret;

    ret = HASH_init(hash);
    if (ret != 0) goto end;
    if (pre != NULL) ret = HASH_update(hash, pre, plen);
    if (ret != 0) goto end;
    ret = HASH_update(hash, data[0], len[0]);
    if (data[1] != NULL) ret = HASH_update(hash, data[1], len[1]);
    if (ret != 0) goto end;
    if (data[2] != NULL) ret = HASH_update(hash, data[2], len[2]);
    if (ret != 0) goto end;
    ret = HASH_final(hash, out);
    if (ret != 0) goto end;

end:
    return ret;
}

/**
 * Hash Derivation Function.
 * Derives arbitrary length data using a hash function.
 * There are up to three buffers of data that passed in to derive from.
 *
 * @param [in] hash  The hash object.
 * @param [in] hlen  The length of the digest output.
 * @param [in] data  An array of three pointers.
 * @param [in] len   The length of data in the three pointers.
 * @param [in] out   The buffer to put the derived output into.
 * @param [in] olen  The length of the data to derive.
 * @return  A hash algorithm error.<br>
 *          0 otherwise.
 */
static int hash_df(HASH *hash, uint16_t hlen, void **data, uint32_t *len,
    void *out, uint32_t olen)
{
    int ret = 0;
    int32_t i, ol;
    uint8_t pre[1+sizeof(uint32_t)];
    uint8_t t[HASH_MAX_DIGEST_LEN];

    /* counter + output length in bits */
    pre[0] = 1;
    for (i=0; i<(int32_t)sizeof(uint32_t); i++)
        pre[1+i] = (olen * 8) >> (24 - (i*8));
    for (i=olen; i>0; i-=hlen,pre[0]++)
    {
        ret = hash_data(hash, pre, sizeof(pre), data, len, t);
        if (ret != 0) goto end;
        ol = (hlen < i) ? hlen : i;
        memcpy(out, t, ol);
        out += ol;
    }

end:
    return ret;
}

/**
 * Initialize the Hash_DRBG context with entropy and user data.
 *
 * @param [in] ctx       The random number generator context.
 * @param [in] hash_id   The hash algorithm identifier.
 * @param [in] seed_len  The length of the seed.
 * @param [in] entropy   The entropy data to initialize with.
 * @param [in] elen      The length of the entropy data in bytes.
 * @param [in] pstring   The user data or personalization string.
 * @param [in] pslen     The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
static int random_hash_init(void *ctx, int hash_id, uint16_t seed_len,
    void *entropy, uint32_t elen, void *pstring, uint32_t pslen)
{
    int ret;
    RANDOM_HASH *h = ctx;
    void *data[3] = { entropy, pstring, NULL };
    uint32_t len[3] = { elen, pslen, 0 };

    if (h->hash == NULL)
    {
        ret = HASH_new(hash_id, 0, &h->hash);
        if (ret != 0) goto end;
    }

    ret = HASH_get_len(h->hash, &h->hash_len); 
    if (ret != 0) goto end;

    ret = hash_df(h->hash, h->hash_len, data, len, &h->v[1], seed_len);
    if (ret != 0) goto end;

    h->v[0] = 0;
    data[0] = h->v; len[0] = seed_len + 1;
    data[1] = NULL; data[2] = NULL;
    ret = hash_df(h->hash, h->hash_len, data, len, h->c, seed_len);
    if (ret != 0) goto end;

    h->reseed_cnt = 1;
    h->seed_len = seed_len;
end:
    return ret;
}

/**
 * Initialize the Hash_DRBG SHA-1 context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to initialize with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] pstring  The user data or personalization string.
 * @param [in] pslen    The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_SHA1_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen)
{
    return random_hash_init(ctx, HASH_ID_SHA1, RANDOM_HASH_256_SEED_LEN,
        entropy, elen, pstring, pslen);
}

/**
 * Initialize the Hash_DRBG SHA-224 context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to initialize with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] pstring  The user data or personalization string.
 * @param [in] pslen    The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_SHA224_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen)
{
    return random_hash_init(ctx, HASH_ID_SHA224, RANDOM_HASH_256_SEED_LEN,
        entropy, elen, pstring, pslen);
}

/**
 * Initialize the Hash_DRBG SHA-256 context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to initialize with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] pstring  The user data or personalization string.
 * @param [in] pslen    The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_SHA256_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen)
{
    return random_hash_init(ctx, HASH_ID_SHA256, RANDOM_HASH_256_SEED_LEN,
        entropy, elen, pstring, pslen);
}

/**
 * Initialize the Hash_DRBG SHA-384 context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to initialize with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] pstring  The user data or personalization string.
 * @param [in] pslen    The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_SHA384_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen)
{
    return random_hash_init(ctx, HASH_ID_SHA384, RANDOM_HASH_512_SEED_LEN,
        entropy, elen, pstring, pslen);
}

/**
 * Initialize the Hash_DRBG SHA-512 context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to initialize with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] pstring  The user data or personalization string.
 * @param [in] pslen    The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_SHA512_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen)
{
    return random_hash_init(ctx, HASH_ID_SHA512, RANDOM_HASH_512_SEED_LEN,
        entropy, elen, pstring, pslen);
}

/**
 * Initialize the Hash_DRBG SHA-512/224 context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to initialize with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] pstring  The user data or personalization string.
 * @param [in] pslen    The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_SHA512_224_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen)
{
    return random_hash_init(ctx, HASH_ID_SHA512_224, RANDOM_HASH_256_SEED_LEN,
        entropy, elen, pstring, pslen);
}

/**
 * Initialize the Hash_DRBG SHA-512/256 context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to initialize with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] pstring  The user data or personalization string.
 * @param [in] pslen    The length of the personalization string.
 * @return  RANDOM_ERR_ALLOC when dynamic memory allocation fails.<br>
 *          RANDOM_ERR_NOT_FOUND when a required algorithm implementation is not
 *          found.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_SHA512_256_init(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen)
{
    return random_hash_init(ctx, HASH_ID_SHA512_256, RANDOM_HASH_256_SEED_LEN,
        entropy, elen, pstring, pslen);
}

/**
 * Disposes of the dynamic memory associated with the Hash_DRBG context.
 * Zeroizes all state buffers.
 *
 * @param [in] ctx      The Hash_DRBG context.
 */
void RANDOM_HASH_final(void *ctx)
{
    RANDOM_HASH *h = ctx;

    HASH_free(h->hash);

    memset(h, 0, sizeof(*h));
}

/**
 * Reseed the Hash_DRBG context with entropy and user data.
 *
 * @param [in] ctx      The Hash_DRBG context.
 * @param [in] entropy  The entropy data to reseed with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] ainput   The user data or additional input.
 * @param [in] alen     The length of the additional input.
 * @return  0 when there is no error.
 */
int RANDOM_HASH_reseed(void *ctx, void *entropy, uint32_t elen, void *ainput,
    uint32_t alen)
{
    int ret;
    RANDOM_HASH *h = ctx;
    void *data[3] = { h->v, entropy, ainput };
    uint32_t len[3] = { h->seed_len + 1, elen, alen };

    h->v[0] = 1;
    ret = hash_df(h->hash, h->hash_len, data, len, &h->t, h->seed_len);
    if (ret != 0) goto end;
    memcpy(&h->v[1], h->t, h->seed_len);
    
    h->v[0] = 0;
    data[0] = h->v; len[0] = h->seed_len + 1;
    data[1] = NULL; data[2] = NULL;
    ret = hash_df(h->hash, h->hash_len, data, len, &h->c, h->seed_len);
    if (ret != 0) goto end;

    h->reseed_cnt = 1;
end:
    return ret;
}

/**
 * Generates data using a hash function.
 *
 * @param [in] hash  The hash object.
 * @param [in] hlen  The length of the digest output.
 * @param [in] v     The v state to hash.
 * @param [in] vlen  The length of v data.
 * @param [in] data  The buffer to hold the generated data.
 * @param [in] len   The length of the generated data.
 * @return  A hash algorithm error.<br>
 *          0 otherwise.
 */
static int hashgen(HASH *hash, uint16_t hlen, uint8_t *v, uint32_t vlen,
    void *data, uint32_t len)
{
    int ret = 0;
    int32_t i, j, ol;
    uint8_t t[HASH_MAX_DIGEST_LEN];

    for (i=len; i>0; i-=hlen)
    {
        ret = HASH_init(hash);
        if (ret != 0) goto end;
        ret = HASH_update(hash, v, vlen);
        if (ret != 0) goto end;
        ret = HASH_final(hash, t);
        if (ret != 0) goto end;

        ol = (hlen < i) ? hlen : i;
        memcpy(data, t, ol);
        data += hlen;

        for (j=vlen-1; j>=0 && (++v[j] == 0); j--) ;
    }

end:
    return ret;
}

/**
 * Generate random data with optional user data.
 *
 * @param [in]  ctx      The Hash_DRBG context.
 * @param [in]  ainput   The user data or additional input.
 * @param [in]  alen     The length of the additional input.
 * @param [in]  out      The output buffer for the generated data.
 * @param [in]  olen     The length of the data to generate.
 * @param [out] glen     The length of the generated data.
 * @return  RANDOM_ERR_RESEED if a reseed is required.<br>
 *          0 otherwise.
 */
int RANDOM_HASH_gen(void *ctx, void *ainput, uint32_t alen, void *out,
    uint32_t olen, uint32_t *glen)
{
    int ret;
    RANDOM_HASH *h = ctx;
    int16_t i;
    void *data[3] = { h->v, ainput, NULL };
    uint32_t len[3] = { h->seed_len + 1, alen, 0 };
    uint16_t t;
    int l = h->hash_len;

    if (h->reseed_cnt >= (1L << 48))
    {
        *glen = 0;
        ret = RANDOM_ERR_RESEED;
        goto end;
    }

    if (ainput != NULL)
    {
        h->v[0] = 2;
        memset(h->t, 0, h->seed_len-l);
        ret = hash_data(h->hash, NULL, 0, data, len, h->t+h->seed_len-l);
        if (ret != 0) goto end;
        t = 0;
        for (i=h->seed_len-1; i>=0; i--)
        {
            t += h->v[i+1];
            t += h->t[i];
            h->v[i+1] = t;
            t >>= 8;
        }
    }

    if (olen > (1 << 16))
        olen = 1 << 16;

    memcpy(h->t, h->v+1, h->seed_len);
    ret = hashgen(h->hash, h->hash_len, h->t, h->seed_len, out, olen);
    if (ret != 0) goto end;

    h->v[0] = 3;
    data[0] = h->v; len[0] = h->seed_len + 1;
    data[1] = NULL; data[2] = NULL;
    memset(h->t, 0, h->seed_len-l);
    ret = hash_data(h->hash, NULL, 0, data, len, h->t+h->seed_len-l);
    if (ret != 0) goto end;
    t = 0;
    for (i=h->seed_len-1; i>=h->seed_len-4; i--)
    {
        t += h->v[i+1];
        t += h->c[i];
        t += h->t[i];
        t += h->reseed_cnt >> ((h->seed_len-1)*8 - (i*8));
        h->v[i+1] = t;
        t >>= 8;
    }
    for (; i>=0; i--)
    {
        t += h->v[i+1];
        t += h->c[i];
        t += h->t[i];
        h->v[i+1] = t;
        t >>= 8;
    }

    h->reseed_cnt++;
    *glen = olen;
end:
    return ret;
}

