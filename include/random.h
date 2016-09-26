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

#include <stdint.h>
#include "entropy.h"

#define RANDOM_ERR_NOT_FOUND		1
#define RANDOM_ERR_PARAM_NULL		12
#define RANDOM_ERR_ALLOC		20
#define RANDOM_ERR_TIME			21
#define RANDOM_ERR_ENTROPY		30
#define RANDOM_ERR_RESEED		31

#define RANDOM_METH_FLAG_SMALL		0x01

#define RANDOM_ID_HASH_DRBG_SHA1	1
#define RANDOM_ID_HASH_DRBG_SHA224	2
#define RANDOM_ID_HASH_DRBG_SHA256	3
#define RANDOM_ID_HASH_DRBG_SHA384	4
#define RANDOM_ID_HASH_DRBG_SHA512	5
#define RANDOM_ID_HASH_DRBG_SHA512_224	6
#define RANDOM_ID_HASH_DRBG_SHA512_256	7

typedef struct random_st RANDOM;

int RANDOM_new(ENTROPY_METH *src, uint16_t bits, uint16_t flags,
    RANDOM **random);
int RANDOM_new_by_id(ENTROPY_METH *src, int id, uint16_t flags,
    RANDOM **random);
void RANDOM_free(RANDOM *random);

int RANDOM_get_impl_name(RANDOM *random, char **name);

int RANDOM_init(RANDOM *random, void *data, uint32_t len);
int RANDOM_seed(RANDOM *random, void *data, uint32_t len);
int RANDOM_generate(RANDOM *random, void *data, uint32_t len);
int RANDOM_generate_with_input(RANDOM *random, void *ainput, uint32_t alen,
    void *data, uint32_t len);

