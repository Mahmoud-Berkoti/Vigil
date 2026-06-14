#include "sbuf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ensure(vg_sbuf_t *b, size_t extra) {
    if (b->oom) return -1;
    if (b->len + extra + 1 <= b->cap) return 0;
    size_t ncap = b->cap ? b->cap : 1024;
    while (ncap < b->len + extra + 1) ncap *= 2;
    char *nd = realloc(b->data, ncap);
    if (!nd) {
        b->oom = 1;
        return -1;
    }
    b->data = nd;
    b->cap = ncap;
    return 0;
}

void vg_sbuf_init(vg_sbuf_t *b) { memset(b, 0, sizeof(*b)); }

void vg_sbuf_free(vg_sbuf_t *b) {
    free(b->data);
    memset(b, 0, sizeof(*b));
}

void vg_sbuf_puts(vg_sbuf_t *b, const char *s) {
    size_t n = strlen(s);
    if (ensure(b, n) != 0) return;
    memcpy(b->data + b->len, s, n + 1);
    b->len += n;
}

void vg_sbuf_printf(vg_sbuf_t *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0 || ensure(b, (size_t)need) != 0) {
        va_end(ap2);
        return;
    }
    vsnprintf(b->data + b->len, (size_t)need + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)need;
}

void vg_sbuf_json(vg_sbuf_t *b, const char *s) {
    for (const char *c = s; *c; c++) {
        if (*c == '"' || *c == '\\') {
            if (ensure(b, 2) != 0) return;
            b->data[b->len++] = '\\';
            b->data[b->len++] = *c;
        } else if ((unsigned char)*c < 0x20) {
            vg_sbuf_printf(b, "\\u%04x", *c);
        } else {
            if (ensure(b, 1) != 0) return;
            b->data[b->len++] = *c;
        }
    }
    if (!b->oom) b->data[b->len] = '\0';
}
