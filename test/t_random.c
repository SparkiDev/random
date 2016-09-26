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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "random.h"

#define T_RANDOM_LEN	64

#ifdef CC_CLANG
#define PRIu64 "llu"
#else
#define PRIu64 "lu"
#endif

/* Ouput buffer to generate data into. */
static unsigned char out[16384];
/* The output lengths to test in speed test. */
static int olen[] = { 1, 32, 64, 1024, 8192, 16384 };

/* Random number generator algorithm identifiers. */
static uint8_t id[] =
{
    RANDOM_ID_HASH_DRBG_SHA1,
    RANDOM_ID_HASH_DRBG_SHA224, RANDOM_ID_HASH_DRBG_SHA256,
    RANDOM_ID_HASH_DRBG_SHA384, RANDOM_ID_HASH_DRBG_SHA512,
    RANDOM_ID_HASH_DRBG_SHA512_224, RANDOM_ID_HASH_DRBG_SHA512_256,
};

/* The number of algorithm identifiers. */
#define NUM_ID  ((uint8_t)(sizeof(id)/(sizeof(*id))))

/* Number of cycles/sec. */
uint64_t cps = 0;

/*
 * Get the current cycle count from the CPU.
 *
 * @return  Cycle counter from CPU.
 */
uint64_t get_cycles()
{
    unsigned int hi, lo;

    asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}

/*
 * Calculate the number of cycles/second.
 */
void calc_cps()
{
    uint64_t end, start = get_cycles();
    sleep(1);
    end = get_cycles();
    cps = end-start;
    printf("Cycles/sec: %"PRIu64"\n", cps);
}

/*
 * Determine the number of random number generations that can be performed per
 * second.
 *
 * @param [in] random  The random object to use.
 * @param [in] msg     The data of the message.
 * @param [in] mlen    The length of the data.
 */
void random_cycles(RANDOM *random, unsigned char *out, int olen)
{
    int i;
    uint64_t start, end, diff;
    int num_ops;

    RANDOM_init(random, NULL, 0);

    /* Prime the caches, etc */
    for (i=0; i<100000/olen; i++)
        RANDOM_generate(random, out, olen);

    /* Approximate number of ops in a second. */
    start = get_cycles();
    for (i=0; i<200; i++)
        RANDOM_generate(random, out, olen);
    end = get_cycles();
    num_ops = cps/((end-start)/200);

    /* Perform about 1 seconds worth of operations. */
    start = get_cycles();
    for (i=0; i<num_ops; i++)
        RANDOM_generate(random, out, olen);
    end = get_cycles();

    diff = end - start;

    printf("%6d: %7d %2.3f  %7"PRIu64" %7"PRIu64" %8.2f %9.0f %8.3f\n",
        olen, num_ops, diff/(cps*1.0), diff/num_ops, cps/(diff/num_ops),
        (double)diff/num_ops/olen, cps/((double)diff/num_ops)*olen,
        (cps/((double)diff/num_ops)*olen)/1000000);
}

int test_random(int id, int flags, int speed)
{
    int ret;
    RANDOM *random = NULL;
    int i;
    uint8_t rand[T_RANDOM_LEN];
    char *name;

    ret = RANDOM_new_by_id(ENTROPY_METH_defaults, id, flags, &random);
    if (ret)
    {
        fprintf(stderr, "Failed to create random object: %d\n", ret);
        goto end;
    }

    ret = RANDOM_get_impl_name(random, &name);
    if (ret)
    {
        fprintf(stderr, "Failed to get impl name: %d\n", ret);
        goto end;
    }
    printf("%s\n", name);

    ret = RANDOM_init(random, "TLS", 3);
    if (ret)
    {
        fprintf(stderr, "Failed to initialize random object: %d\n", ret);
        goto end;
    }
    ret = RANDOM_generate(random, &rand, T_RANDOM_LEN);
    if (ret)
    {
        fprintf(stderr, "Failed to generate with random object: %d\n", ret);
        goto end;
    }

    if (speed)
    {
        printf("%6s  %7s %5s  %7s %7s %8s %9s %8s\n", "Op", "ops", "secs",
            "c/op", "ops/s", "c/B", "B/s", "mB/s");
        for (i=0; i<(int)(sizeof(olen)/sizeof(*olen)); i++)
            random_cycles(random, out, olen[i]);
        goto end;
    }
    else
    {
        for (i=0; i<T_RANDOM_LEN; i++)
            fprintf(stderr, "%02x", rand[i]);
        fprintf(stderr, "\n");
    }
end:
    RANDOM_free(random);
    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int speed = 1;
    uint32_t which = 0;
    int8_t alg_id;
    uint8_t i;

    while (--argc)
    {
        argv++;
        alg_id = -1;

        if (strcmp(*argv, "-speed") == 0)
            speed = 1;
        else if (strcmp(*argv, "-sha1") == 0)
            alg_id = RANDOM_ID_HASH_DRBG_SHA1;
        else if (strcmp(*argv, "-sha224") == 0)
            alg_id = RANDOM_ID_HASH_DRBG_SHA224;
        else if (strcmp(*argv, "-sha256") == 0)
            alg_id = RANDOM_ID_HASH_DRBG_SHA256;
        else if (strcmp(*argv, "-sha384") == 0)
            alg_id = RANDOM_ID_HASH_DRBG_SHA384;
        else if (strcmp(*argv, "-sha512") == 0)
            alg_id = RANDOM_ID_HASH_DRBG_SHA512;
        else if (strcmp(*argv, "-sha512_224") == 0)
            alg_id = RANDOM_ID_HASH_DRBG_SHA512_224;
        else if (strcmp(*argv, "-sha512_256") == 0)
            alg_id = RANDOM_ID_HASH_DRBG_SHA512_256;

        if (alg_id != -1)
        {
            for (i=0; i<NUM_ID; i++)
            {
                if (id[i] == alg_id)
                    which |= 1 << i;
            }
        }
    }

    if (speed)
        calc_cps();

    for (i=0; i<NUM_ID; i++)
    {
        if ((which == 0) || (which & (1 << i)) != 0)
            ret |= test_random(id[i], 0, speed);
    }

    return ret != 0;
}

