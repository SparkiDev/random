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

#ifndef ENTROPY_H
#define ENTROPY_H

#define ENTROPY_FLAG_ONCE       0x01
#define ENTROPY_FLAG_NO_PREV    0x02

typedef int(ENTROPY_FUNC)(void *data, uint32_t *len, uint16_t *bits);
typedef struct entropy_meth_st
{
    char *name;
    uint16_t flags;
    ENTROPY_FUNC *func;
} ENTROPY_METH;

extern ENTROPY_METH ENTROPY_METH_defaults[];

int ENTROPY_METH_rdrand(void *rd, uint32_t *len, uint16_t *bits);
int ENTROPY_METH_rdtsc(void *rd, uint32_t *len, uint16_t *bits);
int ENTROPY_METH_dev_random(void *rd, uint32_t *len, uint16_t *bits);
int ENTROPY_METH_time(void *rd, uint32_t *len, uint16_t *bits);
int ENTROPY_generate(ENTROPY_METH *meth, uint16_t bits, void *data,
    uint16_t *olen);

#endif

