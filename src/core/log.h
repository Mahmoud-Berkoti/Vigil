#ifndef VIGIL_LOG_H
#define VIGIL_LOG_H

/* Structured (logfmt-style) logging to stderr:
 *   ts=2026-07-06T12:00:00Z level=info comp=rib msg="..." */

typedef enum {
    VG_LOG_DEBUG = 0,
    VG_LOG_INFO  = 1,
    VG_LOG_WARN  = 2,
    VG_LOG_ERROR = 3,
} vg_log_level_t;

void vg_log_set_level(vg_log_level_t level);
void vg_log(vg_log_level_t level, const char *component, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#endif
