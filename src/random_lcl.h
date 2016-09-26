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

#include "random.h"
#include "random_hash.h"

/**
 * Initialize the random number generator context with entropy and user data.
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
typedef int (RANDOM_INIT)(void *ctx, void *entropy, uint32_t elen,
    void *pstring, uint32_t pslen);
/**
 * Disposes of the dynamic memory associated with the context.
 *
 * @param [in] ctx      The random number generator context.
 */
typedef void (RANDOM_FINAL)(void *ctx);
/**
 * Reseed the random number generator context with entropy and user data.
 *
 * @param [in] ctx      The random number generator context.
 * @param [in] entropy  The entropy data to reseed with.
 * @param [in] elen     The length of the entropy data in bytes.
 * @param [in] ainput   The user data or additional input.
 * @param [in] alen     The length of the additional input.
 * @return  0 when there is no error.
 */
typedef int (RANDOM_RESEED)(void *ctx, void *entropy, uint32_t elen,
    void *ainput, uint32_t alen);
/**
 * Generate random data with optional user data.
 *
 * @param [in]  ctx      The random number generator context.
 * @param [in]  ainput   The user data or additional input.
 * @param [in]  alen     The length of the additional input.
 * @param [in]  out      The output buffer for the generated data.
 * @param [in]  olen     The length of the data to generate.
 * @param [out] glen     The length of the generated data.
 * @return  0 when there is no error.
 */
typedef int (RANDOM_GEN)(void *ctx, void *ainput, uint32_t alen, void *out,
    uint32_t olen, uint32_t *glen);

/** The structure for the random number generator implementation. */
typedef struct random_meth_st
{
    /** The random number generator identifier. */
    uint8_t id;
    /** The name of the random number generator implementation as a string. */
    char *name;
    /** The number of security bits supported by the implementation. */
    uint16_t bits;
    /** The flags of the implementation. */
    uint16_t flags;
    /** The size of the context to allocate. */
    size_t ctx_size;
    /** The initialization function. */
    RANDOM_INIT *init;
    /** The finalization function. */
    RANDOM_FINAL *fin;
    /** The reseed function. */
    RANDOM_RESEED *reseed;
    /** The generation function. */
    RANDOM_GEN *gen;
} RANDOM_METH;

/** The random number generator object.  */
struct random_st
{
    /** The random number generation implementation. */
    RANDOM_METH *meth;
    /** The context for the implementation. */
    void *ctx;
    /** The entropy sources. */
    ENTROPY_METH *entropy_src;
    /** The buffer to hold generated entropy. */
    uint8_t *entropy;
    /** The number of bytes of entropy to generate. */
    uint16_t elen;
};

