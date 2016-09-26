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
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include "entropy.h"

#ifdef CPU_X86_64
/** The number of times to retry the RDRAND instruction.  */
#define RDRAND_RETRY	10

/**
 * Get entropy from the RDRAND instruction on x86_64 Intel processors.
 *
 * @param [in]      rd    The buffer to put the entropy data into.
 * @param [out]     len   The length of the entropy data.
 * @param [in, out] bits  The number of entropy bits in data.
 * @return  0 on failure.<br>
 *          1 on success.
 */
int ENTROPY_METH_rdrand(void *rd, uint32_t *len, uint16_t *bits)
{
    uint8_t i;
    uint8_t set = 0;

    for (i=RDRAND_RETRY; (i>0) && !set; i--)
    {
        /* RDRAND succeeded if the carry flag is set. */
        asm volatile ("rdrand %0\n\t"
                      "setc %1"
                      : "=r" (((uint16_t *)rd)[0]), "=r" (set));
    }
    *len = sizeof(uint16_t);
    if (set) *bits += 9;
    return set;
}

/**
 * Get the number of clock cycles on x86_64 Intel processors.
 *
 * @param [in]      rd    The buffer to put the entropy data into.
 * @param [out]     len   The length of the entropy data.
 * @param [in, out] bits  The number of entropy bits in data.
 * @return  1 indicating success.
 */
int ENTROPY_METH_rdtsc(void *rd, uint32_t *len, uint16_t *bits)
{
    unsigned int hi, lo;

    asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));

    ((uint16_t *)rd)[0] = lo;

    *len = sizeof(uint16_t);
    *bits += 5;
    return 1;
}
#endif

#if defined(OS_LINUX) || defined(OS_MACOSX)
/**
 * Get entropy from /dev/random on Unix OSes.
 * Reading is non-blocking as data may not be available.
 *
 * @param [in]      rd    The buffer to put the entropy data into.
 * @param [out]     len   The length of the entropy data.
 * @param [in, out] bits  The number of entropy bits in data.
 * @return  0 on failure.<br>
 *          1 on success.
 */
int ENTROPY_METH_dev_random(void *data, uint32_t *len, uint16_t *bits)
{
    uint8_t *r = data;
    uint8_t l = sizeof(uint16_t);
    int fd;
    ssize_t rl;
    int flags;

    fd = open("/dev/random", O_RDONLY);
    if (fd == -1) goto end;
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    do
    {
        rl = read(fd, r, l);
        l -= rl;
        r += rl;
    }
    while ((rl > 0) && (l > 0));
    close(fd);

    if (l == 0)
    {
        *len = sizeof(uint16_t);
        *bits += 12;
    }
end:
    return (l == 0);
}
#endif

/**
 * Get entropy from /dev/random on Unix OSes.
 * Reading is non-blocking as data may not be available.
 *
 * @param [out]     len   The length of the entropy data.
 * @param [in, out] bits  The number of entropy bits in data.
 * @return  0 on failure.<br>
 *          1 on success.
 */
int ENTROPY_METH_time(void *data, uint32_t *len, uint16_t *bits)
{
    int r = 0;
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        goto end;

    *(uint16_t *)data = tv.tv_usec;
    *len = sizeof(uint16_t);
    *bits += 4;

    r = 1;
end:
    return r;
}

/** The default entropy sources to use. */
ENTROPY_METH ENTROPY_METH_defaults[] =
{
#if defined(OS_LINUX) || defined(OS_MACOSX)
    { "/dev/random", 0, &ENTROPY_METH_dev_random },
#endif
#ifdef CPU_X86_64
    { "Intel RDRAND", ENTROPY_FLAG_NO_PREV, &ENTROPY_METH_rdrand },
    { "Intel RDTSC", 0, &ENTROPY_METH_rdtsc },
#endif
    { "usec Time", ENTROPY_FLAG_ONCE, &ENTROPY_METH_time },
    { NULL, 0, NULL }
};

/**
 * Generate entropy data.
 * The number of bytes generated will be no more than bits number of bytes.
 * That is, each source generates at least 1 bit per byte of entropy data.
 *
 * @param [in]  meth  The methods that gather entropy.<br>
 *                    Use ENTROPY_METH_defaults() for good sources.
 * @param [in]  bits  The number of bits of entropy required.
 * @param [in]  data  The buffer to put the entropy data into.
 * @param [out] olen  The number of bytes of data put into the buffer.
 * @return  0 on failure.<br>
 *          1 on success.
 */
int ENTROPY_generate(ENTROPY_METH *meth, uint16_t bits, void *data,
    uint16_t *olen)
{
    uint8_t i;
    uint8_t gathered = 1;
    uint16_t b = 0;
    uint8_t l = 0;
    uint8_t *p = data;
    uint32_t len;
    uint32_t once = 0;

    /* Keep gathering entropy while more bits are required and a source
     * succeeded.
     */
    while ((b < bits) && gathered)
    {
        gathered = 0;
        /* Try each entrppy source. */
        for (i=0; meth[i].func != NULL; i++)
        {
            /* Do not retry source that have succeeded that are flagged as once
             * only.
             */
            if ((once & (1 << i)) != 0)
                continue;

            /* Do not try source if previous sources worked and flagged as only
             * when no previous source succeeded.
             */
            if ((meth[i].flags & ENTROPY_FLAG_NO_PREV) && gathered)
                continue;

            /* Try source - may not be able to return entropy data at this
             * time.
             */
            if ((*meth[i].func)(p, &len, &b))
            {
                if (meth[i].flags & ENTROPY_FLAG_ONCE)
                    once |= 1 << i;
                gathered = 1;
                p += len;
                l += len;
            }
        }
    }

    *olen = l;
    return (b >= bits);
}

