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
#include <math.h>

#include "entropy.h"

#ifdef CC_CLANG
#define PRIu64 "llu"
#else
#define PRIu64 "lu"
#endif

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

typedef void (COALESCE_FUNC)(void *);

/* The structure for entropy sources. */
typedef struct entropy_src_st
{
    char *name;
    ENTROPY_FUNC *func;
    COALESCE_FUNC *coalesce;
    uint16_t bits;
    uint32_t samples;
    uint16_t len;
} ENTROPY_SRC;


void coalesce_dev_random(void *data)
{
    uint16_t *d = data;
    d[0] &= 0x3;
}
void coalesce_rdrand_lo(void *data)
{
    uint16_t *d = data;
    d[0] &= 0xff;
}
void coalesce_rdrand_hi(void *data)
{
    uint16_t *d = data;
    d[0] >>= 8;
}
void coalesce_rdtsc_lo(void *data)
{
    uint16_t *d = data;
    d[0] &= 0xf;
}
void coalesce_rdtsc_hi(void *data)
{
    uint16_t *d = data;
    d[0] = (d[0] >> 4) & 0xf;
}
void coalesce_time(void *data)
{
    uint16_t *d = data;
    d[0] &= 0xff;
}

/* Entropy sources to test. */
ENTROPY_SRC entropy_src[] =
{
#if 1
    { "/dev/random", ENTROPY_METH_dev_random, coalesce_dev_random, 2, 1<<4, 2 },
#endif
    { "RDRAND Hi 8", ENTROPY_METH_rdrand, coalesce_rdrand_hi, 8, 1<<24, 2 },
    { "RDRAND Lo 8", ENTROPY_METH_rdrand, coalesce_rdrand_lo, 8, 1<<24, 2 },
    { "RDTSC Hi 4", ENTROPY_METH_rdtsc, coalesce_rdtsc_hi, 4, 1<<16, 2 },
    { "RDTSC Lo 4", ENTROPY_METH_rdtsc, coalesce_rdtsc_lo, 4, 1<<16, 2 },
    { "usec Time", ENTROPY_METH_time, coalesce_time, 8, 1<<16, 2 },
};

/* The number of entropy sources to test. */
#define ENTROPY_SRC_NUM ((uint8_t)(sizeof(entropy_src)/sizeof(*entropy_src)))

int most_common_value(void *buffer, ENTROPY_SRC *src, double *entropy)
{
    uint16_t *b = buffer;
    uint32_t i;
    uint32_t *cnt, max = 0;
    uint32_t s = 1 << src->bits;
    double p, pu;

    cnt = malloc(s * sizeof(*cnt));
    memset(cnt, 0, s * sizeof(*cnt));
    for (i=0; i<src->samples; i++)
        cnt[b[i]]++;
    for (i=0; i<s; i++)
        max = (max > cnt[i]) ? max : cnt[i];

    p = max; p /= src->samples;
    pu = p + 2.576 * sqrt((p*(1-p))/src->samples);
    if (pu > 1) pu = 1;

    *entropy = -log2(pu);
    free(cnt);
    return 0;
}

double f(double q, double n)
{
    int i;
    double z = 1 / q;
    double r = q;

    for (i=n; i>=1; i--)
        r = 1.0 / (z + ((i-1-n) / (1 + i * r)));

    return r;
}
double collision_func(double p, double q, double k)
{
    double t1 = p/q;
    double t2 = (1/p-1/q)/k;
    return (t1/q)*(1+t2)*f(q,k+1) - t1*t2;
}

int collision_estimate(void *buffer, ENTROPY_SRC *src, double *entropy)
{
    int ret = 0;
    uint16_t *b = buffer;
    uint32_t v, index, i, c;
    uint32_t *pos;
    uint16_t *t;
    uint32_t s = 1 << src->bits;
    double x, o, n, x1;
    double p, q, k = s;

    pos = malloc(s * sizeof(*pos));
    t = malloc(src->samples * sizeof(*t));
    memset(t, 0, src->samples * sizeof(*t));
    v = 0;
    index = 0;

    for (index=0,v=0; index<src->samples; )
    {
        memset(pos, -1, s * sizeof(*pos));
        for (i=index; i<src->samples; i++)
        {
            if (pos[b[i]] != (uint32_t)-1)
            {
                t[v++] = i - index;
                break;
            }
            pos[b[i]] = i;
        }
        index = i+1;
    }
    if (v < 1000)
    {
        ret = 1;
        goto end;
    }

    for (i=0,c=0; i<v; i++)
        c += t[i];
    x = c; x /= v;
    for (i=0,c=0,o=0; i<v; i++)
    {
        n = t[i] - x;
        o += n*n;
    }
    o /= v;
    o = sqrt(o);

#ifdef DEBUG_COLLISION
    fprintf(stderr, "mean:%lf std:%lf v=%d\n", x, o, v);
#endif

    x1 = x - 2.576*o/sqrt(v);

    p = 0;
    for (i=1; i<48; i++)
    {
        p += (double)1.0 / (1L << i);
        q = (1 - p) / (k - 1);
        x = collision_func(p, q, k);
#ifdef DEBUG_COLLISION
fprintf(stderr, "%d: %14.12lf %14.12lf %14.12lf\n", i, p, x, x1);
#endif
        if (x < x1)
            p -= (double)1.0 / (1L << i);
    }

    if (x1 - 0.001 < x)
        *entropy = -log2(p);
    else
        *entropy = src->bits;

end:
    free(t);
    free(pos);
    return ret;
}

int markov_estimate(void *buffer, ENTROPY_SRC *src, double *entropy)
{
    uint16_t *b = buffer;
    uint32_t i, j, c, d = 128;
    double alpha = 0.99;
    double epsilon;
    uint32_t k = 1<<src->bits;
    uint16_t *cnt;
    uint16_t *trans;
    double *prob, *h, *p, pmax;
    double *t;

    cnt = malloc(k * sizeof(*cnt));
    trans = malloc(k * k * sizeof(*trans));
    prob = malloc(k * sizeof(*prob));
    t = malloc(k * k * sizeof(*t));
    p = malloc(k * sizeof(*p));
    h = malloc(k * sizeof(*h));

    for (i=1; (i<k*k) && (i<d); i++)
        alpha *= 0.99;

    epsilon = sqrt(log2(1/(1-alpha))/(2*k*k));

    memset(cnt, 0, k * sizeof(*cnt));
    for (i=0; i<k*k; i++)
        cnt[b[i]]++;
    for (i=0; i<k; i++)
        prob[i] = cnt[i]/(k*k) + epsilon;
    pmax = 0;
    for (i=0; i<k; i++)
        pmax = (pmax > prob[i]) ? pmax : prob[i];

    memset(trans, 0, k * k * sizeof(*trans));
    for (i=0; i<k*k-1; i++)
        trans[b[i]*k+b[i+1]]++;

    for (i=0; i<k; i++)
    {
        epsilon = sqrt(log2(1/(1-alpha))/(2*cnt[i]));
        for (j=0; j<k; j++)
            t[i*k+j] = (cnt[i] == 0) ? 1 : (trans[i*k+j] / cnt[i]) + epsilon;
    }

    for (j=1; j<d; j++)
    {
        fprintf(stderr, "%3d/128\r", j);
        for (c=0; c<k; c++)
        {
            for (i=0; i<k; i++)
                p[i] = prob[i] * t[i*k+c];

            h[c] = 0;
            for (i=0; i<k; i++)
                h[c] = (h[c] > p[i]) ? h[c] : p[i];
        }
        for (i=0; i<k; i++)
            prob[i] = h[i];
    }
    fprintf(stderr, "       \r");
    pmax = 0;
    for (i=0; i<k; i++)
        pmax = (pmax > p[i]) ? pmax : p[i];

    *entropy = -log2(pmax) / d;
    free(h);
    free(p);
    free(t);
    free(prob);
    free(trans);
    free(cnt);
    return 0;
}

double compression_func_f(double z, uint32_t t, uint32_t u)
{
    uint32_t i;
    double r;

    r = z;
    for (i=0; i<u-1; i++)
        r *= (1-z);
    if (u < t)
        r = z;

    return r;
}
double compression_func_g(double z, uint32_t l, uint32_t v, uint32_t d)
{
    uint32_t t, u;
    double r;

    r = 0;
    for (t=d; t<l; t++)
    {
        fprintf(stderr, "%d/%d\r", t, l);
        for (u=0; u<t; u++)
            r += log2(u) * compression_func_f(z, t, u);
    }

    return r / v;
}
double compression_func(double p, double q, uint32_t n, uint32_t l, uint32_t v,
    uint32_t d)
{
    return compression_func_g(p, l, v, d) +
        (n-1) * compression_func_g(q, l, v, d);
}

int compression_estimate(void *buffer, ENTROPY_SRC *src, double *entropy)
{
    uint16_t *s = buffer;
    uint32_t i;
    uint32_t v, d, l;
    uint32_t b = src->bits;
    uint32_t k = 1 << src->bits;
    double p, q, x, t, x1;
    double c, rho;
    uint32_t *dict;
    uint32_t *di;

    l = 1002;
    d = 1000;
    v = l - d;

    if (src->samples < d)
        return 1;

    dict = malloc(k * sizeof(*dict));
    memset(dict, 0, k * sizeof(*dict));
    di = malloc(v * sizeof(*di));

    for (i=0; i<d; i++)
        dict[s[i]] = i;

    for (; i<l; i++)
    {
        di[i-d] = i - dict[s[i]];
        dict[s[i]] = i;
    }

    for (x=0,x1=0,i=0; i<v; i++)
    {
        t = log2(di[i]);
        x += t;
        x1 += t*t;
    }
    x /= v;
    x1 /= v;

    c = 0.7 - (0.8 / b) + ((4 + 32 / b) * pow(v, -3.0/b)) / 15;

    rho = c * sqrt(x1 - x*x);

    x1 = x - (2.576 * rho / sqrt(v));

    p = 0;
    for (i=1; i<48; i++)
    {
        fprintf(stderr, "%3d/48\r", i);
        p += (double)1.0 / (1L << i);
        q = (1 - p) / (k - 1);

        x = compression_func(p, q, k, l, v, d);
#define DEBUG_COMPRESSION
#ifdef DEBUG_COMPRESSION
fprintf(stderr, "%d: %14.12lf %14.12lf %14.12lf\n", i, p, x, x1);
#endif
        if (x < x1)
            p -= (double)1.0 / (1L << i);
    }
    fprintf(stderr, "       \r");

    if (x1 - 0.001 < x)
        *entropy = -log2(p);
    else
        *entropy = src->bits;

    free(di);
    free(dict);
    return 0;
}

typedef int (ESTIMATOR_FUNC)(void *buffer, ENTROPY_SRC *src, double *entropy);
typedef struct estimator_st
{
    char *name;
    ESTIMATOR_FUNC *func;
} ESTIMATOR;

ESTIMATOR estimator[] =
{
    { "Most Common Value", &most_common_value },
    { "Collision", &collision_estimate },
    { "Markov", &markov_estimate },
    { "Compression", &compression_estimate },
};

#define ESTIMATOR_NUM  ((uint8_t)(sizeof(estimator)/sizeof(*estimator)))

/*
 * Analyze the samples of an entropy source.
 *
 * @param [in] src     The entropy source.
 * @param [in] len     The length of each sample.
 * @return  0 to indicate success.
 */
int analyze(ENTROPY_SRC *src, void *buffer)
{
    int r;
    uint8_t i;
    double entropy, least;

    printf("%s:\n", src->name);

    least = src->bits;
    for (i=0; i<ESTIMATOR_NUM; i++)
    {
        r = (estimator[i].func)(buffer, src, &entropy);
        if (r == 1)
        {
            printf("%-17s: Too few samples\n", estimator[i].name);
        }
        else
        {
            if (least > entropy) least = entropy;
            printf("%-17s: %9.6lf %9.6lf\n", estimator[i].name, entropy, least);
        }
    }

    return 0;
}

/*
 * Collect samples from an entropy source to analyze.
 *
 * @param [in] src     The entropy source.
 * @param [in] buffer  The buffer to hold the samples.
 * @return  0 to indicate success.
 */
int collect(ENTROPY_SRC *src, void *buffer)
{
    uint32_t i;
    uint32_t len;
    uint16_t bits;
    uint8_t *b8 = buffer;
    uint16_t *b16 = buffer;
    uint32_t *b32 = buffer;

    for (i=0; i<src->samples; )
    {
        if ((*src->func)(b8, &len, &bits))
        {
#ifdef DEBUG_OUTPUT
            fprintf(stderr, "%02x%02x ", b8[0], b8[1]);
#endif
            b8 += len;
            i++;
        }
    }
#ifdef DEBUG_OUTPUT
fprintf(stderr, "\n");
#endif

    if (src->len == 2)
    {
        for (i=0; i<src->samples; i++,b16++)
        {
            src->coalesce(b16);
#ifdef DEBUG
            fprintf(stderr, "%04x ", b16[0]);
#endif
        }
    }
    else if (src->len == 4)
    {
        for (i=0; i<src->samples; i++,b32++)
            src->coalesce(b32);
    }

    fprintf(stderr, "\n");

    return 0;
}

/*
 * Determine the number of entropy gathering operations that can be performed
 * per second.
 */
void entropy_cycles(uint16_t bits)
{
    int i;
    uint64_t start, end, diff;
    int num_ops;
    uint8_t data[256];
    uint16_t olen;

    /* Prime the caches, etc */
    for (i=0; i<1000; i++)
        ENTROPY_generate(ENTROPY_METH_defaults, bits, data, &olen);

    /* Approximate number of ops in a second. */
    start = get_cycles();
    for (i=0; i<200; i++)
        ENTROPY_generate(ENTROPY_METH_defaults, bits, data, &olen);
    end = get_cycles();
    num_ops = cps/((end-start)/200);

    /* Perform about 1 seconds worth of operations. */
    start = get_cycles();
    for (i=0; i<num_ops; i++)
        ENTROPY_generate(ENTROPY_METH_defaults, bits, data, &olen);
    end = get_cycles();

    diff = end - start;

    printf("%4d: %7d %2.3f  %7"PRIu64" %7"PRIu64"\n", bits, num_ops,
        diff/(cps*1.0), diff/num_ops, cps/(diff/num_ops));
}


int main(int argc, char *argv[])
{
    int r = 1;
    uint8_t i;
    uint8_t *buffer = NULL;
    int speed = 0;
    uint32_t len;

    while (--argc)
    {
        argv++;
        if (strcmp(*argv, "-speed") == 0)
            speed = 1;
        else
        {
            fprintf(stderr, "Option not supported: %s\n", *argv);
            goto end;
        }
    }

    if (speed)
    {
        calc_cps();

        printf("\n");
        printf("%4s  %7s %5s  %7s %7s\n", "bits", "ops", "secs", "c/op",
            "ops/s");
        entropy_cycles(128);
        entropy_cycles(256);

        r = 0;
        goto end;
    }

    for (i=0,len=0; i<ENTROPY_SRC_NUM; i++)
        len = (len > entropy_src[i].samples) ? len : entropy_src[i].samples;

    buffer = malloc(sizeof(uint16_t) * len);

    for (i=0; i<ENTROPY_SRC_NUM; i++)
    {
        collect(&entropy_src[i], buffer);
        analyze(&entropy_src[i], buffer);
    }

    r = 0;
end:
    free(buffer);
    return r;
}

