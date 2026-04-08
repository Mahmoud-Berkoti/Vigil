/*
 * Minimal JSON parser (RFC 8259 subset) for RIS Live messages and RPKI
 * VRP dumps. Parses a byte buffer into an arena-allocated node tree;
 * one vg_json_free releases everything. No streaming: callers feed one
 * complete document (RIS Live is newline-delimited JSON).
 *
 * Limits (attacker-controlled input): max depth 64, max nodes 1M.
 */
#ifndef VIGIL_JSON_H
#define VIGIL_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    VG_JSON_NULL = 0,
    VG_JSON_BOOL,
    VG_JSON_NUMBER,
    VG_JSON_STRING,
    VG_JSON_ARRAY,
    VG_JSON_OBJECT,
} vg_json_type_t;

typedef struct vg_json {
    vg_json_type_t type;
    const char    *key;   /* member name when parent is an object */
    /* scalars */
    double         num;
    bool           boolean;
    const char    *str;   /* NUL-terminated, unescaped */
    /* containers */
    struct vg_json *child; /* first element/member */
    struct vg_json *next;  /* next sibling */
    size_t          len;   /* element/member count */
} vg_json_t;

/* Parse; returns root or NULL on malformed input. */
vg_json_t *vg_json_parse(const char *buf, size_t n);
void       vg_json_free(vg_json_t *root);

/* Object member lookup (NULL if absent or not an object). */
const vg_json_t *vg_json_get(const vg_json_t *obj, const char *key);
/* Convenience accessors: return fallback when missing/mistyped. */
const char *vg_json_str(const vg_json_t *obj, const char *key, const char *fb);
double      vg_json_num(const vg_json_t *obj, const char *key, double fb);

#endif
