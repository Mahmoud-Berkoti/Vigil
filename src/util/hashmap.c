#include "hashmap.h"

#include <stdlib.h>
#include <string.h>

static uint64_t hash_bytes(const void *key, size_t n) {
    const uint8_t *p = key;
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

int vg_hashmap_init(vg_hashmap_t *m, size_t key_size, size_t val_size) {
    memset(m, 0, sizeof(*m));
    m->key_size = key_size;
    m->val_size = val_size;
    m->cap = 64;
    m->keys = malloc(m->cap * key_size);
    m->vals = calloc(m->cap, val_size);
    m->used = calloc(m->cap, 1);
    if (!m->keys || !m->vals || !m->used) {
        vg_hashmap_free(m);
        return -1;
    }
    return 0;
}

void vg_hashmap_free(vg_hashmap_t *m) {
    free(m->keys);
    free(m->vals);
    free(m->used);
    memset(m, 0, sizeof(*m));
}

static int grow(vg_hashmap_t *m) {
    vg_hashmap_t big;
    memset(&big, 0, sizeof(big));
    big.key_size = m->key_size;
    big.val_size = m->val_size;
    big.cap = m->cap * 2;
    big.keys = malloc(big.cap * big.key_size);
    big.vals = calloc(big.cap, big.val_size);
    big.used = calloc(big.cap, 1);
    if (!big.keys || !big.vals || !big.used) {
        free(big.keys);
        free(big.vals);
        free(big.used);
        return -1;
    }
    for (size_t i = 0; i < m->cap; i++) {
        if (!m->used[i]) continue;
        const uint8_t *key = m->keys + i * m->key_size;
        size_t j = hash_bytes(key, m->key_size) & (big.cap - 1);
        while (big.used[j]) j = (j + 1) & (big.cap - 1);
        memcpy(big.keys + j * big.key_size, key, big.key_size);
        memcpy(big.vals + j * big.val_size, m->vals + i * m->val_size,
               big.val_size);
        big.used[j] = 1;
    }
    big.count = m->count;
    free(m->keys);
    free(m->vals);
    free(m->used);
    *m = big;
    return 0;
}

void *vg_hashmap_upsert(vg_hashmap_t *m, const void *key, bool *created) {
    if (m->count * 4 >= m->cap * 3 && grow(m) != 0) return NULL;
    size_t i = hash_bytes(key, m->key_size) & (m->cap - 1);
    while (m->used[i]) {
        if (memcmp(m->keys + i * m->key_size, key, m->key_size) == 0) {
            if (created) *created = false;
            return m->vals + i * m->val_size;
        }
        i = (i + 1) & (m->cap - 1);
    }
    memcpy(m->keys + i * m->key_size, key, m->key_size);
    memset(m->vals + i * m->val_size, 0, m->val_size);
    m->used[i] = 1;
    m->count++;
    if (created) *created = true;
    return m->vals + i * m->val_size;
}

void *vg_hashmap_get(const vg_hashmap_t *m, const void *key) {
    if (m->cap == 0) return NULL;
    size_t i = hash_bytes(key, m->key_size) & (m->cap - 1);
    while (m->used[i]) {
        if (memcmp(m->keys + i * m->key_size, key, m->key_size) == 0)
            return m->vals + i * m->val_size;
        i = (i + 1) & (m->cap - 1);
    }
    return NULL;
}

size_t vg_hashmap_count(const vg_hashmap_t *m) { return m->count; }
