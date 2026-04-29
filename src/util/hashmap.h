/* Open-addressing hash map: fixed-size byte keys -> fixed-size values. */
#ifndef VIGIL_HASHMAP_H
#define VIGIL_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *keys, *vals, *used;
    size_t   key_size, val_size;
    size_t   cap; /* power of two */
    size_t   count;
} vg_hashmap_t;

int   vg_hashmap_init(vg_hashmap_t *m, size_t key_size, size_t val_size);
void  vg_hashmap_free(vg_hashmap_t *m);
/* Returns pointer to the value slot for key, inserting a zeroed value
 * if absent (created set accordingly). NULL on OOM. Pointers are
 * invalidated by the next upsert. */
void *vg_hashmap_upsert(vg_hashmap_t *m, const void *key, bool *created);
/* NULL if absent. */
void *vg_hashmap_get(const vg_hashmap_t *m, const void *key);
size_t vg_hashmap_count(const vg_hashmap_t *m);

#endif
