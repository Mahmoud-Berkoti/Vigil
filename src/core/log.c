#include "log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static vg_log_level_t g_level = VG_LOG_INFO;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static const char *level_str(vg_log_level_t l) {
    switch (l) {
    case VG_LOG_DEBUG: return "debug";
    case VG_LOG_INFO:  return "info";
    case VG_LOG_WARN:  return "warn";
    case VG_LOG_ERROR: return "error";
    }
    return "?";
}

void vg_log_set_level(vg_log_level_t level) { g_level = level; }

void vg_log(vg_log_level_t level, const char *component, const char *fmt, ...) {
    if (level < g_level) return;

    char ts[32];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_mu);
    fprintf(stderr, "ts=%s level=%s comp=%s msg=\"%s\"\n", ts, level_str(level),
            component, msg);
    pthread_mutex_unlock(&g_mu);
}
