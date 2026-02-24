/* Open-addressing hash set over fixed-size byte keys. */
#ifndef VIGIL_HASHSET_H
#define VIGIL_HASHSET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *slots;   /* key_size bytes per slot */
    uint8_t *used;
    size_t   key_size;
    size_t   cap;     /* power of two */
    size_t   count;
} vg_hashset_t;

int    vg_hashset_init(vg_hashset_t *s, size_t key_size);
void   vg_hashset_free(vg_hashset_t *s);
/* Returns 1 if newly inserted, 0 if already present, -1 on OOM. */
int    vg_hashset_add(vg_hashset_t *s, const void *key);
bool   vg_hashset_has(const vg_hashset_t *s, const void *key);
size_t vg_hashset_count(const vg_hashset_t *s);

#endif
