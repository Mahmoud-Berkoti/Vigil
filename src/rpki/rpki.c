/*
 * RFC 6811 Route Origin Validation against a VRP set loaded from the
 * JSON export of Routinator / rpki-client / Cloudflare's rpki.json:
 *   {"roas":[{"asn":"AS13335","prefix":"1.1.1.0/24","maxLength":24},...]}
 *
 * VRPs live in a binary trie per family; validating (prefix, origin)
 * walks root -> prefix collecting VRPs at every covering node:
 *   no covering VRP                                  -> NOTFOUND
 *   some covering VRP with asn==origin and len<=max  -> VALID
 *   covering VRPs exist but none match               -> INVALID
 */
#include "rpki.h"

#include "../core/log.h"
#include "../util/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct vrp {
    uint32_t    asn;
    uint8_t     max_len;
    struct vrp *next; /* same trie node (same ROA prefix) */
} vrp_t;

typedef struct node {
    struct node *child[2];
    vrp_t       *vrps;
} node_t;

struct vg_rpki {
    node_t *root4, *root6;
    size_t  count;
};

static int prefix_bit(const vg_prefix_t *p, int i) {
    return (p->addr[i / 8] >> (7 - (i % 8))) & 1;
}

static int insert_vrp(vg_rpki_t *r, const vg_prefix_t *p, uint32_t asn,
                      uint8_t max_len) {
    node_t **slot = p->family == VG_AF_INET ? &r->root4 : &r->root6;
    if (!*slot) *slot = calloc(1, sizeof(node_t));
    node_t *n = *slot;
    if (!n) return -1;
    for (int i = 0; i < p->len; i++) {
        int b = prefix_bit(p, i);
        if (!n->child[b]) n->child[b] = calloc(1, sizeof(node_t));
        n = n->child[b];
        if (!n) return -1;
    }
    /* de-dup identical VRPs (dumps contain duplicates across TAs) */
    for (vrp_t *v = n->vrps; v; v = v->next)
        if (v->asn == asn && v->max_len == max_len) return 0;
    vrp_t *v = malloc(sizeof(vrp_t));
    if (!v) return -1;
    v->asn = asn;
    v->max_len = max_len;
    v->next = n->vrps;
    n->vrps = v;
    r->count++;
    return 0;
}

static void free_node(node_t *n) {
    if (!n) return;
    free_node(n->child[0]);
    free_node(n->child[1]);
    vrp_t *v = n->vrps;
    while (v) {
        vrp_t *next = v->next;
        free(v);
        v = next;
    }
    free(n);
}

/* "AS13335" or 13335 (number) or "13335" */
static bool parse_asn(const vg_json_t *roa, uint32_t *out) {
    const vg_json_t *a = vg_json_get(roa, "asn");
    if (!a) return false;
    if (a->type == VG_JSON_NUMBER) {
        *out = (uint32_t)a->num;
        return true;
    }
    if (a->type == VG_JSON_STRING) {
        const char *s = a->str;
        if ((s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's')) s += 2;
        char *end;
        unsigned long v = strtoul(s, &end, 10);
        if (end != s && *end == '\0' && v <= 0xFFFFFFFFUL) {
            *out = (uint32_t)v;
            return true;
        }
    }
    return false;
}

vg_rpki_t *vg_rpki_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        vg_log(VG_LOG_ERROR, "rpki", "cannot open %s", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > (1L << 30)) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)size);
    if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);

    /* Global VRP dumps run to ~100MB / ~700k ROAs, far past the DoS
     * limits our DOM parser enforces for network input. Instead of one
     * huge parse, locate the "roas" array and brace-match one ROA
     * object at a time (quote/escape aware), parsing each tiny object
     * with the normal JSON parser. */
    /* find "roas" whose value is an array (metadata blocks contain a
     * numeric "roas" counter — skip those) */
    const char *roas = NULL;
    for (const char *s0 = buf; s0 + 6 < buf + size && !roas; s0++) {
        if (memcmp(s0, "\"roas\"", 6) != 0) continue;
        const char *v = s0 + 6;
        while (v < buf + size && (*v == ' ' || *v == '\t' || *v == '\n' ||
                                  *v == '\r'))
            v++;
        if (v >= buf + size || *v != ':') continue;
        v++;
        while (v < buf + size && (*v == ' ' || *v == '\t' || *v == '\n' ||
                                  *v == '\r'))
            v++;
        if (v < buf + size && *v == '[') roas = v;
    }
    if (!roas) {
        vg_log(VG_LOG_ERROR, "rpki", "%s: no \"roas\" array", path);
        free(buf);
        return NULL;
    }

    vg_rpki_t *r = calloc(1, sizeof(*r));
    if (!r) {
        free(buf);
        return NULL;
    }
    size_t skipped = 0;
    bool malformed = false;
    const char *s = roas + 1;
    const char *end = buf + size;
    for (;;) {
        while (s < end && (*s == ' ' || *s == '\t' || *s == '\n' ||
                           *s == '\r' || *s == ','))
            s++;
        if (s >= end || *s == ']') break;
        if (*s != '{') {
            malformed = true;
            break;
        }
        /* find the matching close brace */
        const char *obj = s;
        int depth = 0;
        bool in_str = false, esc = false;
        for (; s < end; s++) {
            char c = *s;
            if (esc) { esc = false; continue; }
            if (in_str) {
                if (c == '\\') esc = true;
                else if (c == '"') in_str = false;
                continue;
            }
            if (c == '"') in_str = true;
            else if (c == '{') depth++;
            else if (c == '}' && --depth == 0) {
                s++;
                break;
            }
        }
        if (depth != 0) {
            malformed = true;
            break;
        }

        vg_json_t *roa = vg_json_parse(obj, (size_t)(s - obj));
        if (!roa) {
            skipped++;
            continue;
        }
        uint32_t asn;
        vg_prefix_t p;
        const char *pfx = vg_json_str(roa, "prefix", NULL);
        if (!pfx || !parse_asn(roa, &asn) || vg_prefix_parse(pfx, &p) != 0) {
            skipped++;
            vg_json_free(roa);
            continue;
        }
        double ml = vg_json_num(roa, "maxLength", p.len);
        uint8_t max = p.family == VG_AF_INET ? 32 : 128;
        if (ml < p.len || ml > max) {
            skipped++;
            vg_json_free(roa);
            continue;
        }
        int rc = insert_vrp(r, &p, asn, (uint8_t)ml);
        vg_json_free(roa);
        if (rc != 0) {
            vg_rpki_free(r);
            free(buf);
            return NULL;
        }
    }
    free(buf);
    if (malformed) {
        vg_log(VG_LOG_ERROR, "rpki", "%s: malformed roas array", path);
        vg_rpki_free(r);
        return NULL;
    }
    vg_log(VG_LOG_INFO, "rpki", "loaded %zu VRPs from %s (%zu skipped)",
           r->count, path, skipped);
    return r;
}

void vg_rpki_free(vg_rpki_t *r) {
    if (!r) return;
    free_node(r->root4);
    free_node(r->root6);
    free(r);
}

size_t vg_rpki_count(const vg_rpki_t *r) { return r ? r->count : 0; }

vg_rov_state_t vg_rpki_validate(const vg_rpki_t *r, const vg_prefix_t *p,
                                uint32_t origin_asn) {
    if (!r) return VG_ROV_NOTFOUND;
    bool covered = false;
    node_t *n = p->family == VG_AF_INET ? r->root4 : r->root6;
    for (int i = 0; n; i++) {
        for (vrp_t *v = n->vrps; v; v = v->next) {
            covered = true;
            /* RFC 6811: match requires origin equality AND the route
             * being no more specific than maxLength. AS0 VRPs
             * (RFC 7607) can never match, so they force INVALID. */
            if (v->asn == origin_asn && v->asn != 0 && p->len <= v->max_len)
                return VG_ROV_VALID;
        }
        if (i >= p->len) break;
        n = n->child[prefix_bit(p, i)];
    }
    return covered ? VG_ROV_INVALID : VG_ROV_NOTFOUND;
}

const char *vg_rov_str(vg_rov_state_t s) {
    switch (s) {
    case VG_ROV_VALID:    return "valid";
    case VG_ROV_INVALID:  return "invalid";
    case VG_ROV_NOTFOUND: return "notfound";
    }
    return "unknown";
}
