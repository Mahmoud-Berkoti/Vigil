#include "../vigil.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int addr_bytes(const vg_prefix_t *p) {
    return p->family == VG_AF_INET ? 4 : 16;
}

void vg_prefix_normalize(vg_prefix_t *p) {
    for (int i = 0; i < 16; i++) {
        int bit_start = i * 8;
        if (bit_start >= p->len) {
            p->addr[i] = 0;
        } else if (bit_start + 8 > p->len) {
            uint8_t mask = (uint8_t)(0xFF << (8 - (p->len - bit_start)));
            p->addr[i] &= mask;
        }
    }
}

int vg_prefix_parse(const char *s, vg_prefix_t *out) {
    if (!s || !out) return -1;
    const char *slash = strchr(s, '/');
    if (!slash) return -1;

    char addr[64];
    size_t alen = (size_t)(slash - s);
    if (alen == 0 || alen >= sizeof(addr)) return -1;
    memcpy(addr, s, alen);
    addr[alen] = '\0';

    /* prefix length: digits only, no sign/whitespace */
    const char *lp = slash + 1;
    if (*lp == '\0') return -1;
    for (const char *c = lp; *c; c++)
        if (*c < '0' || *c > '9') return -1;
    long len = strtol(lp, NULL, 10);

    memset(out, 0, sizeof(*out));
    if (strchr(addr, ':')) {
        if (len < 0 || len > 128) return -1;
        if (inet_pton(AF_INET6, addr, out->addr) != 1) return -1;
        out->family = VG_AF_INET6;
    } else {
        if (len < 0 || len > 32) return -1;
        if (inet_pton(AF_INET, addr, out->addr) != 1) return -1;
        out->family = VG_AF_INET;
    }
    out->len = (uint8_t)len;
    vg_prefix_normalize(out);
    return 0;
}

int vg_prefix_format(const vg_prefix_t *p, char *buf, size_t n) {
    char addr[INET6_ADDRSTRLEN];
    int af = p->family == VG_AF_INET ? AF_INET : AF_INET6;
    if (!inet_ntop(af, p->addr, addr, sizeof(addr))) return -1;
    int w = snprintf(buf, n, "%s/%u", addr, p->len);
    if (w < 0 || (size_t)w >= n) return -1;
    return w;
}

bool vg_prefix_equal(const vg_prefix_t *a, const vg_prefix_t *b) {
    return a->family == b->family && a->len == b->len &&
           memcmp(a->addr, b->addr, (size_t)addr_bytes(a)) == 0;
}

bool vg_prefix_covers(const vg_prefix_t *outer, const vg_prefix_t *inner) {
    if (outer->family != inner->family || outer->len > inner->len) return false;
    int full = outer->len / 8;
    if (full > 0 && memcmp(outer->addr, inner->addr, (size_t)full) != 0) return false;
    int rem = outer->len % 8;
    if (rem == 0) return true;
    uint8_t mask = (uint8_t)(0xFF << (8 - rem));
    return (outer->addr[full] & mask) == (inner->addr[full] & mask);
}
