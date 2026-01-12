/* Minimal single-header test harness. Each tests/test_*.c compiles to
 * its own binary; `make test` runs them all and fails on any non-zero
 * exit. */
#ifndef VIGIL_TEST_H
#define VIGIL_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int t_failures = 0;
static int t_checks = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        t_checks++;                                                        \
        if (!(cond)) {                                                     \
            t_failures++;                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);\
        }                                                                  \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                 \
    do {                                                                   \
        t_checks++;                                                        \
        long long _a = (long long)(a), _b = (long long)(b);                \
        if (_a != _b) {                                                    \
            t_failures++;                                                  \
            fprintf(stderr, "FAIL %s:%d: %s == %s (%lld != %lld)\n",       \
                    __FILE__, __LINE__, #a, #b, _a, _b);                   \
        }                                                                  \
    } while (0)

#define CHECK_EQ_STR(a, b)                                                 \
    do {                                                                   \
        t_checks++;                                                        \
        const char *_a = (a), *_b = (b);                                   \
        if (strcmp(_a, _b) != 0) {                                         \
            t_failures++;                                                  \
            fprintf(stderr, "FAIL %s:%d: %s == %s (\"%s\" != \"%s\")\n",   \
                    __FILE__, __LINE__, #a, #b, _a, _b);                   \
        }                                                                  \
    } while (0)

#define TEST_MAIN_END()                                                    \
    do {                                                                   \
        if (t_failures) {                                                  \
            fprintf(stderr, "%d/%d checks failed\n", t_failures, t_checks);\
            return 1;                                                      \
        }                                                                  \
        printf("ok (%d checks)\n", t_checks);                              \
        return 0;                                                          \
    } while (0)

#endif
