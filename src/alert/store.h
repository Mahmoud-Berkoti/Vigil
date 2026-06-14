/* SQLite-backed alert history. All calls are serialized internally. */
#ifndef VIGIL_ALERT_STORE_H
#define VIGIL_ALERT_STORE_H

#include "../vigil.h"

typedef struct vg_store vg_store_t;

/* path ":memory:" gives an ephemeral store (tests). */
vg_store_t *vg_store_open(const char *path);
void        vg_store_close(vg_store_t *s);

/* Inserts and assigns a->id. Returns 0 ok. */
int vg_store_insert(vg_store_t *s, vg_alert_t *a);

typedef struct {
    int         type;       /* -1 = any, else vg_alert_type_t */
    int         severity;   /* -1 = any minimum, else >= this */
    double      since;      /* 0 = any */
    const char *prefix;     /* NULL = any (exact string match) */
    int         limit;      /* <=0 -> 100 */
} vg_store_filter_t;

typedef void (*vg_store_alert_cb)(const vg_alert_t *a, void *user);
/* Newest first. Returns row count or -1. */
int vg_store_query(vg_store_t *s, const vg_store_filter_t *f,
                   vg_store_alert_cb cb, void *user);

/* Total alerts by type (array of 5). */
int vg_store_counts(vg_store_t *s, uint64_t out[5]);

#endif
