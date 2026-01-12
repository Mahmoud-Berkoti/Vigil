#include "../vigil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t vg_aspath_origin(const vg_aspath_t *p) {
    if (p->count == 0) return 0;
    return p->as[p->count - 1];
}

int vg_aspath_format(const vg_aspath_t *p, char *buf, size_t n) {
    size_t off = 0;
    if (n == 0) return -1;
    buf[0] = '\0';
    for (uint16_t i = 0; i < p->count; i++) {
        int w = snprintf(buf + off, n - off, i == 0 ? "%u" : " %u", p->as[i]);
        if (w < 0 || (size_t)w >= n - off) return -1;
        off += (size_t)w;
    }
    return (int)off;
}

int vg_aspath_parse(const char *s, vg_aspath_t *out) {
    memset(out, 0, sizeof(*out));
    if (!s) return -1;
    const char *c = s;
    while (*c) {
        while (*c == ' ') c++;
        if (!*c) break;
        if (*c < '0' || *c > '9') return -1;
        char *end;
        unsigned long v = strtoul(c, &end, 10);
        if (v > 0xFFFFFFFFUL || out->count >= VG_ASPATH_MAX) return -1;
        out->as[out->count++] = (uint32_t)v;
        c = end;
        if (*c && *c != ' ') return -1;
    }
    return 0;
}

uint32_t vg_event_origin(const vg_event_t *e) {
    if (e->kind != VG_EV_ANNOUNCE) return 0;
    return vg_aspath_origin(&e->path);
}

const char *vg_alert_type_str(vg_alert_type_t t) {
    switch (t) {
    case VG_ALERT_HIJACK:       return "hijack";
    case VG_ALERT_SUBPREFIX:    return "subprefix";
    case VG_ALERT_LEAK:         return "leak";
    case VG_ALERT_RPKI_INVALID: return "rpki_invalid";
    case VG_ALERT_SPIKE:        return "spike";
    }
    return "unknown";
}

const char *vg_severity_str(vg_severity_t s) {
    switch (s) {
    case VG_SEV_INFO:     return "info";
    case VG_SEV_WARNING:  return "warning";
    case VG_SEV_CRITICAL: return "critical";
    }
    return "unknown";
}
