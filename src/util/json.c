#include "json.h"

#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 64
#define MAX_NODES (1u << 20)

/* Arena: nodes and unescaped strings share block-chained storage so
 * freeing the root frees the entire parse. */
typedef struct block {
    struct block *next;
    size_t        used, cap;
    /* data follows */
} block_t;

typedef struct {
    const char *p, *end;
    block_t    *blocks;
    uint32_t    nodes;
    int         depth;
} parser_t;

static void *arena_alloc(parser_t *ps, size_t n) {
    n = (n + 15) & ~(size_t)15;
    block_t *b = ps->blocks;
    if (!b || b->cap - b->used < n) {
        size_t cap = n > 65536 ? n : 65536;
        b = malloc(sizeof(block_t) + cap);
        if (!b) return NULL;
        b->next = ps->blocks;
        b->used = 0;
        b->cap = cap;
        ps->blocks = b;
    }
    void *out = (char *)(b + 1) + b->used;
    b->used += n;
    return out;
}

static void skip_ws(parser_t *ps) {
    while (ps->p < ps->end &&
           (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
        ps->p++;
}

static vg_json_t *new_node(parser_t *ps, vg_json_type_t t) {
    if (++ps->nodes > MAX_NODES) return NULL;
    vg_json_t *n = arena_alloc(ps, sizeof(vg_json_t));
    if (n) {
        memset(n, 0, sizeof(*n));
        n->type = t;
    }
    return n;
}

static int hex4(const char *p) {
    int v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return -1;
    }
    return v;
}

/* Parse a JSON string literal (at '"'), return unescaped copy. */
static const char *parse_string(parser_t *ps) {
    if (ps->p >= ps->end || *ps->p != '"') return NULL;
    ps->p++;
    const char *start = ps->p;
    /* first pass: find end, measure worst-case size */
    size_t maxlen = 0;
    const char *q = start;
    while (q < ps->end && *q != '"') {
        if (*q == '\\') {
            q++;
            if (q >= ps->end) return NULL;
        }
        q++;
        maxlen += 4; /* utf-8 escape can expand to at most 4 bytes */
    }
    if (q >= ps->end) return NULL;

    char *out = arena_alloc(ps, maxlen + 1);
    if (!out) return NULL;
    char *w = out;
    const char *r = start;
    while (r < q) {
        if (*r != '\\') {
            *w++ = *r++;
            continue;
        }
        r++;
        switch (*r++) {
        case '"':  *w++ = '"'; break;
        case '\\': *w++ = '\\'; break;
        case '/':  *w++ = '/'; break;
        case 'b':  *w++ = '\b'; break;
        case 'f':  *w++ = '\f'; break;
        case 'n':  *w++ = '\n'; break;
        case 'r':  *w++ = '\r'; break;
        case 't':  *w++ = '\t'; break;
        case 'u': {
            if (q - r < 4) return NULL;
            int cp = hex4(r);
            if (cp < 0) return NULL;
            r += 4;
            /* surrogate pair */
            if (cp >= 0xD800 && cp <= 0xDBFF && q - r >= 6 && r[0] == '\\' &&
                r[1] == 'u') {
                int lo = hex4(r + 2);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    r += 6;
                }
            }
            /* utf-8 encode */
            if (cp < 0x80) *w++ = (char)cp;
            else if (cp < 0x800) {
                *w++ = (char)(0xC0 | (cp >> 6));
                *w++ = (char)(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                *w++ = (char)(0xE0 | (cp >> 12));
                *w++ = (char)(0x80 | ((cp >> 6) & 0x3F));
                *w++ = (char)(0x80 | (cp & 0x3F));
            } else {
                *w++ = (char)(0xF0 | (cp >> 18));
                *w++ = (char)(0x80 | ((cp >> 12) & 0x3F));
                *w++ = (char)(0x80 | ((cp >> 6) & 0x3F));
                *w++ = (char)(0x80 | (cp & 0x3F));
            }
            break;
        }
        default:
            return NULL;
        }
    }
    *w = '\0';
    ps->p = q + 1;
    return out;
}

static vg_json_t *parse_value(parser_t *ps);

static vg_json_t *parse_container(parser_t *ps, bool is_object) {
    if (++ps->depth > MAX_DEPTH) return NULL;
    char close = is_object ? '}' : ']';
    vg_json_t *node = new_node(ps, is_object ? VG_JSON_OBJECT : VG_JSON_ARRAY);
    if (!node) return NULL;
    ps->p++; /* consume { or [ */
    skip_ws(ps);
    if (ps->p < ps->end && *ps->p == close) {
        ps->p++;
        ps->depth--;
        return node;
    }
    vg_json_t *tail = NULL;
    for (;;) {
        const char *key = NULL;
        if (is_object) {
            skip_ws(ps);
            key = parse_string(ps);
            if (!key) return NULL;
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') return NULL;
            ps->p++;
        }
        vg_json_t *v = parse_value(ps);
        if (!v) return NULL;
        v->key = key;
        if (tail) tail->next = v;
        else node->child = v;
        tail = v;
        node->len++;

        skip_ws(ps);
        if (ps->p >= ps->end) return NULL;
        if (*ps->p == ',') {
            ps->p++;
            continue;
        }
        if (*ps->p == close) {
            ps->p++;
            ps->depth--;
            return node;
        }
        return NULL;
    }
}

static vg_json_t *parse_value(parser_t *ps) {
    skip_ws(ps);
    if (ps->p >= ps->end) return NULL;
    char c = *ps->p;

    if (c == '{' || c == '[') return parse_container(ps, c == '{');
    if (c == '"') {
        const char *s = parse_string(ps);
        if (!s) return NULL;
        vg_json_t *n = new_node(ps, VG_JSON_STRING);
        if (n) n->str = s;
        return n;
    }
    if (c == 't' && ps->end - ps->p >= 4 && memcmp(ps->p, "true", 4) == 0) {
        ps->p += 4;
        vg_json_t *n = new_node(ps, VG_JSON_BOOL);
        if (n) n->boolean = true;
        return n;
    }
    if (c == 'f' && ps->end - ps->p >= 5 && memcmp(ps->p, "false", 5) == 0) {
        ps->p += 5;
        return new_node(ps, VG_JSON_BOOL);
    }
    if (c == 'n' && ps->end - ps->p >= 4 && memcmp(ps->p, "null", 4) == 0) {
        ps->p += 4;
        return new_node(ps, VG_JSON_NULL);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        char tmp[64];
        size_t i = 0;
        while (ps->p < ps->end && i < sizeof(tmp) - 1 &&
               (strchr("+-.eE", *ps->p) || (*ps->p >= '0' && *ps->p <= '9')))
            tmp[i++] = *ps->p++;
        tmp[i] = '\0';
        char *end;
        double d = strtod(tmp, &end);
        if (end == tmp || *end != '\0') return NULL;
        vg_json_t *n = new_node(ps, VG_JSON_NUMBER);
        if (n) n->num = d;
        return n;
    }
    return NULL;
}

vg_json_t *vg_json_parse(const char *buf, size_t n) {
    parser_t ps = {buf, buf + n, NULL, 0, 0};
    vg_json_t *root = parse_value(&ps);
    if (root) {
        skip_ws(&ps);
        if (ps.p != ps.end) root = NULL; /* trailing garbage */
    }
    if (!root) {
        block_t *b = ps.blocks;
        while (b) {
            block_t *next = b->next;
            free(b);
            b = next;
        }
        return NULL;
    }
    /* stash the block chain in a wrapper node so free can find it */
    vg_json_t *wrapper = arena_alloc(&ps, sizeof(vg_json_t));
    if (!wrapper) {
        block_t *b = ps.blocks;
        while (b) {
            block_t *next = b->next;
            free(b);
            b = next;
        }
        return NULL;
    }
    *wrapper = *root;
    /* store the chain head pointer right after the wrapper */
    block_t **chain = arena_alloc(&ps, sizeof(block_t *));
    if (!chain) { /* extremely unlikely; leak-safe fallback */
        block_t *b = ps.blocks;
        while (b) {
            block_t *next = b->next;
            free(b);
            b = next;
        }
        return NULL;
    }
    *chain = ps.blocks;
    wrapper->key = (const char *)chain; /* private: chain pointer */
    return wrapper;
}

void vg_json_free(vg_json_t *root) {
    if (!root) return;
    block_t *b = *(block_t **)(void *)root->key;
    while (b) {
        block_t *next = b->next;
        free(b);
        b = next;
    }
}

const vg_json_t *vg_json_get(const vg_json_t *obj, const char *key) {
    if (!obj || obj->type != VG_JSON_OBJECT) return NULL;
    for (const vg_json_t *c = obj->child; c; c = c->next)
        if (c->key && strcmp(c->key, key) == 0) return c;
    return NULL;
}

const char *vg_json_str(const vg_json_t *obj, const char *key, const char *fb) {
    const vg_json_t *v = vg_json_get(obj, key);
    return v && v->type == VG_JSON_STRING ? v->str : fb;
}

double vg_json_num(const vg_json_t *obj, const char *key, double fb) {
    const vg_json_t *v = vg_json_get(obj, key);
    if (!v) return fb;
    if (v->type == VG_JSON_NUMBER) return v->num;
    if (v->type == VG_JSON_STRING) { /* RIS Live sends ASNs as strings */
        char *end;
        double d = strtod(v->str, &end);
        if (end != v->str && *end == '\0') return d;
    }
    return fb;
}
