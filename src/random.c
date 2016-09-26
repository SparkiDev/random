/*
 * Copyright (c) 2016 Sean Parkinson (sparkinson@iprimus.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/oret sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies oret substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "random_lcl.h"
#include "entropy.h"

/** The implementations of random number generators. */
RANDOM_METH random_meth[] =
{
    { RANDOM_ID_HASH_DRBG_SHA1, "Hash_DRBG SHA1",
      128, 0, sizeof(RANDOM_HASH),
      &RANDOM_HASH_SHA1_init, &RANDOM_HASH_SHA1_final,
      &RANDOM_HASH_SHA1_reseed, &RANDOM_HASH_SHA1_gen },
    { RANDOM_ID_HASH_DRBG_SHA224, "Hash_DRBG SHA224",
      192, 0, sizeof(RANDOM_HASH),
      &RANDOM_HASH_SHA224_init, &RANDOM_HASH_SHA224_final,
      &RANDOM_HASH_SHA224_reseed, &RANDOM_HASH_SHA224_gen },
    { RANDOM_ID_HASH_DRBG_SHA512, "Hash_DRBG SHA512",
      256, 0, sizeof(RANDOM_HASH),
      &RANDOM_HASH_SHA512_init, &RANDOM_HASH_SHA512_final,
      &RANDOM_HASH_SHA512_reseed, &RANDOM_HASH_SHA512_gen },
    { RANDOM_ID_HASH_DRBG_SHA384, "Hash_DRBG SHA384",
      256, 0, sizeof(RANDOM_HASH),
      &RANDOM_HASH_SHA384_init, &RANDOM_HASH_SHA384_final,
      &RANDOM_HASH_SHA384_reseed, &RANDOM_HASH_SHA384_gen },
    { RANDOM_ID_HASH_DRBG_SHA256, "Hash_DRBG SHA256",
      256, 0, sizeof(RANDOM_HASH),
      &RANDOM_HASH_SHA256_init, &RANDOM_HASH_SHA256_final,
      &RANDOM_HASH_SHA256_reseed, &RANDOM_HASH_SHA256_gen },
    { RANDOM_ID_HASH_DRBG_SHA512_256, "Hash_DRBG SHA512_256",
      256, 0, sizeof(RANDOM_HASH),
      &RANDOM_HASH_SHA512_256_init, &RANDOM_HASH_SHA512_256_final,
      &RANDOM_HASH_SHA512_256_reseed, &RANDOM_HASH_SHA512_256_gen },
    { RANDOM_ID_HASH_DRBG_SHA512_224, "Hash_DRBG SHA512_224",
      192, 0, sizeof(RANDOM_HASH),
      &RANDOM_HASH_SHA512_224_init, &RANDOM_HASH_SHA512_224_final,
      &RANDOM_HASH_SHA512_224_reseed, &RANDOM_HASH_SHA512_224_gen },
};

/** The number of random number generator implementations.  */
#define RANDOM_METH_NUM	((uint8_t)(sizeof(random_meth)/sizeof(*random_meth)))

/**
 * Retrieves a random number generator implementation that meets requirements.
 *
 * @param [in]  bits   The number of bits of security required.
 * @param [in]  flags  The flags required of the implementation.
 * @param [out] meth   The random number generator implementation.
 * @return  RANDOM_ERR_NOT_FOUND when there is no matching implementation
 *          available.<br>
 *          0 otherwise.
 */
static int random_meth_get(uint16_t bits, uint16_t flags, RANDOM_METH **meth)
{
    int ret = 0;
    uint8_t i;
    RANDOM_METH *m = NULL;

    for (i=0; i<RANDOM_METH_NUM; i++)
    {
        if ((random_meth[i].bits >= bits) &&
            ((random_meth[i].flags & flags) == flags))
        {
            m = &random_meth[i];
            goto end; 
        }
    }
    ret = RANDOM_ERR_NOT_FOUND;
end:
    *meth = m;
    return ret;
}

/**
 * Retrieves a random number generator implementation by identifier.
 *
 * @param [in]  id     The random number generator ID.
 * @param [in]  flags  The flags required of the implementation.
 * @param [out] meth   The random number generator implementation.
 * @return  RANDOM_ERR_NOT_FOUND when there is no matching implementation
 *          available.<br>
 *          0 otherwise.
 */
static int random_meth_get_by_id(int id, uint16_t flags, RANDOM_METH **meth)
{
    int ret = 0;
    uint8_t i;
    RANDOM_METH *m = NULL;

    for (i=0; i<RANDOM_METH_NUM; i++)
    {
        if ((random_meth[i].id == id) &&
            ((random_meth[i].flags & flags) == flags))
        {
            m = &random_meth[i];
            goto end; 
        }
    }
    ret = RANDOM_ERR_NOT_FOUND;
end:
    *meth = m;
    return ret;
}

/**
 * Creates a random object with the entropy sources and methods provided.
 *
 * @param [in]  src     The entropy source methods.
 * @param [in]  meth    The random number generator implementation.
 * @param [out] random  The random number generator object.
 * @return  RANDOM_ERR_ALLOC on dynamic memory allocation failure.<br>
 *          0 otherwise.
 */
static int random_new(ENTROPY_METH *src, RANDOM_METH *meth, RANDOM **random)
{
    int ret = 0;
    RANDOM *rand = NULL;

    rand = malloc(sizeof(**random));
    if (rand == NULL)
    {
        ret = RANDOM_ERR_ALLOC;
        goto end;
    }
    memset(rand, 0, sizeof(**random));

    rand->meth = meth;
    rand->entropy_src = src;

    rand->ctx = malloc(meth->ctx_size);
    rand->entropy = malloc(meth->bits * 32/8);
    if ((rand->ctx == NULL) || (rand->entropy == NULL))
    {
        ret = RANDOM_ERR_ALLOC;
        goto end;
    }
    memset(rand->ctx, 0, meth->ctx_size);

    *random = rand;
    rand = NULL;

end:
    RANDOM_free(rand);
    return ret;
}

/**
 * Creates a random object with the entropy sources based on the requirements.
 *
 * @param [in]  src     The entropy source methods.
 * @param [in]  bits    The number of bits of security required.
 * @param [in]  flags   The flags required of the implementation.
 * @param [out] random  The random number generator object.
 * @return  RANDOM_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          RANDOM_ERR_NOT_FOUND when there is no matching implementation
 *          available.<br>
 *          RANDOM_ERR_ALLOC on dynamic memory allocation failure.<br>
 *          0 otherwise.
 */
int RANDOM_new(ENTROPY_METH *src, uint16_t bits, uint16_t flags,
    RANDOM **random)
{
    int ret;
    RANDOM_METH *meth;

    if ((random == NULL) || (src == NULL))
    {
        ret = RANDOM_ERR_PARAM_NULL;
        goto end;
    }

    ret = random_meth_get(bits, flags, &meth);
    if (ret != 0) goto end;

    ret = random_new(src, meth, random);
end:
    return ret;
}

/**
 * Creates a random object with the entropy sources based on the ID of a random
 * number generator.
 *
 * @param [in]  src     The entropy source methods.
 * @param [in]  id      The random number generator ID.
 * @param [out] random  The random number generator object.
 * @return  RANDOM_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          RANDOM_ERR_NOT_FOUND when there is no matching implementation
 *          available.<br>
 *          RANDOM_ERR_ALLOC on dynamic memory allocation failure.<br>
 *          0 otherwise.
 */
int RANDOM_new_by_id(ENTROPY_METH *src, int id, uint16_t flags,
    RANDOM **random)
{
    int ret;
    RANDOM_METH *meth;

    if ((random == NULL) || (src == NULL))
    {
        ret = RANDOM_ERR_PARAM_NULL;
        goto end;
    }

    ret = random_meth_get_by_id(id, flags, &meth);
    if (ret != 0) goto end;

    ret = random_new(src, meth, random);
end:
    return ret;
}

/**
 * Disposes of the dynamic memory associated with the random number generator
 * object.
 *
 * @param [in] random  A random number generator object.
 */
void RANDOM_free(RANDOM *random)
{
    if (random != NULL)
    {
        random->meth->fin(random->ctx);
        if (random->entropy != NULL) free(random->entropy);
        if (random->ctx != NULL) free(random->ctx);
        free(random);
    }
}

/**
 * Retrieves the name of the implementation of the random number generator.
 *
 * @param [in]  random  A random number generator object.
 * @param [out] name    Then name of the random number generator implementation.
 * @return  RANDOM_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          0 otherwise.
 */
int RANDOM_get_impl_name(RANDOM *random, char **name)
{
    int ret = 0;

    if ((random == NULL) || (name == NULL))
    {
        ret = RANDOM_ERR_PARAM_NULL;
        goto end;
    }

    *name = random->meth->name;
end:
    return ret;
}

/**
 * Initialize the random number generator object for generating data.
 *
 * @param [in] random  A random number generator object.
 * @param [in] data    User data to initialize with.
 * @param [in] len     The length of the user data.
 * @return  RANDOM_ERR_PARAM_NULL when a random is NULL.<br>
 *          RANDOM_ERR_ENTROPY when entropy collection fails.<br>
 *          0 otherwise.
 */
int RANDOM_init(RANDOM *random, void *data, uint32_t len)
{
    int ret = 0;
    uint16_t elen;

    if (random == NULL)
    {
        ret = RANDOM_ERR_PARAM_NULL;
        goto end;
    }

    /* Include the nonce in the entropy data. */
    if (!ENTROPY_generate(random->entropy_src, random->meth->bits * 1.5,
        random->entropy, &elen))
    {
        ret = RANDOM_ERR_ENTROPY;
        goto end;
    }

    ret = random->meth->init(random->ctx, random->entropy, elen, data, len);
    memset(random->entropy, 0, elen);
end:
    return ret;
}

/**
 * Seed the random number generator object to generate new data.
 *
 * @param [in] random  A random number generator object.
 * @param [in] data    User data to seed with.
 * @param [in] len     The length of the user data.
 * @return  RANDOM_ERR_PARAM_NULL when a random is NULL.<br>
 *          RANDOM_ERR_ENTROPY when entropy collection fails.<br>
 *          0 otherwise.
 */
int RANDOM_seed(RANDOM *random, void *data, uint32_t len)
{
    int ret = 0;
    uint16_t elen;

    if (random == NULL)
    {
        ret = RANDOM_ERR_PARAM_NULL;
        goto end;
    }

    if (!ENTROPY_generate(random->entropy_src, random->meth->bits,
        random->entropy, &elen))
    {
        ret = RANDOM_ERR_ENTROPY;
        goto end;
    }

    ret = random->meth->reseed(random->ctx, random->entropy, elen, data, len);
    memset(random->entropy, 0, elen);
end:
    return ret;
}

/**
 * Generate random data with user data.
 *
 * @param [in] random  A random number generator object.
 * @param [in] ainput  User data to generate with.
 * @param [in] alen    The length of the user data.
 * @param [in] data    The generated data.
 * @param [in] len     The length the data to generate.
 * @return  RANDOM_ERR_PARAM_NULL when random or data is NULL.<br>
 *          RANDOM_ERR_ENTROPY when entropy collection fails.<br>
 *          0 otherwise.
 */
int RANDOM_generate_with_input(RANDOM *random, void *ainput, uint32_t alen,
    void *data, uint32_t len)
{
    int ret = 0;
    uint32_t olen;

    if ((random == NULL) || (data == NULL))
    {
        ret = RANDOM_ERR_PARAM_NULL;
        goto end;
    }

    while (len > 0)
    {
        ret = random->meth->gen(random->ctx, ainput, alen, data, len, &olen);
        if (ret == RANDOM_ERR_RESEED)
            ret = RANDOM_seed(random, NULL, 0);
        if (ret != 0)
            goto end;

        data += len;
        len -= olen;
    }
end:
    return ret;
}

/**
 * Generate random data.
 *
 * @param [in] random  A random number generator object.
 * @param [in] data    The generated data.
 * @param [in] len     The length the data to generate.
 * @return  RANDOM_ERR_PARAM_NULL when random or data is NULL.<br>
 *          RANDOM_ERR_ENTROPY when entropy collection fails.<br>
 *          0 otherwise.
 */
int RANDOM_generate(RANDOM *random, void *data, uint32_t len)
{
    return RANDOM_generate_with_input(random, NULL, 0, data, len);
}

