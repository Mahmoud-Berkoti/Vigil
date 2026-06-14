/* Growable string buffer for building HTTP/JSON responses. */
#ifndef VIGIL_SBUF_H
#define VIGIL_SBUF_H

#include <stdarg.h>
#include <stddef.h>

typedef struct {
    char  *data;
    size_t len, cap;
    int    oom; /* sticky allocation-failure flag */
} vg_sbuf_t;

void vg_sbuf_init(vg_sbuf_t *b);
void vg_sbuf_free(vg_sbuf_t *b);
void vg_sbuf_puts(vg_sbuf_t *b, const char *s);
void vg_sbuf_printf(vg_sbuf_t *b, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
/* JSON-escaped string append (no surrounding quotes). */
void vg_sbuf_json(vg_sbuf_t *b, const char *s);

#endif
