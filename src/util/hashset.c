#include "hashset.h"

#include <stdlib.h>
#include <string.h>

/* FNV-1a */
static uint64_t hash_bytes(const void *key, size_t n) {
    const uint8_t *p = key;
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

int vg_hashset_init(vg_hashset_t *s, size_t key_size) {
    memset(s, 0, sizeof(*s));
    s->key_size = key_size;
    s->cap = 64;
    s->slots = malloc(s->cap * key_size);
    s->used = calloc(s->cap, 1);
    if (!s->slots || !s->used) {
        free(s->slots);
        free(s->used);
        return -1;
    }
    return 0;
}

void vg_hashset_free(vg_hashset_t *s) {
    free(s->slots);
    free(s->used);
    memset(s, 0, sizeof(*s));
}

static int grow(vg_hashset_t *s) {
    vg_hashset_t bigger;
    memset(&bigger, 0, sizeof(bigger));
    bigger.key_size = s->key_size;
    bigger.cap = s->cap * 2;
    bigger.slots = malloc(bigger.cap * bigger.key_size);
    bigger.used = calloc(bigger.cap, 1);
    if (!bigger.slots || !bigger.used) {
        free(bigger.slots);
        free(bigger.used);
        return -1;
    }
    for (size_t i = 0; i < s->cap; i++) {
        if (!s->used[i]) continue;
        const uint8_t *key = s->slots + i * s->key_size;
        size_t j = hash_bytes(key, s->key_size) & (bigger.cap - 1);
        while (bigger.used[j]) j = (j + 1) & (bigger.cap - 1);
        memcpy(bigger.slots + j * bigger.key_size, key, bigger.key_size);
        bigger.used[j] = 1;
    }
    bigger.count = s->count;
    free(s->slots);
    free(s->used);
    *s = bigger;
    return 0;
}

int vg_hashset_add(vg_hashset_t *s, const void *key) {
    if (s->count * 4 >= s->cap * 3 && grow(s) != 0) return -1;
    size_t i = hash_bytes(key, s->key_size) & (s->cap - 1);
    while (s->used[i]) {
        if (memcmp(s->slots + i * s->key_size, key, s->key_size) == 0)
            return 0;
        i = (i + 1) & (s->cap - 1);
    }
    memcpy(s->slots + i * s->key_size, key, s->key_size);
    s->used[i] = 1;
    s->count++;
    return 1;
}

bool vg_hashset_has(const vg_hashset_t *s, const void *key) {
    if (s->cap == 0) return false;
    size_t i = hash_bytes(key, s->key_size) & (s->cap - 1);
    while (s->used[i]) {
        if (memcmp(s->slots + i * s->key_size, key, s->key_size) == 0)
            return true;
        i = (i + 1) & (s->cap - 1);
    }
    return false;
}

size_t vg_hashset_count(const vg_hashset_t *s) { return s->count; }
