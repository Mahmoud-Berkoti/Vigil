#include "rib.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct route_node {
    vg_rib_route_t     r;
    struct route_node *next;
} route_node_t;

typedef struct entry {
    vg_prefix_t     prefix;
    route_node_t   *routes;
    vg_rib_change_t hist[VG_RIB_HISTORY];
    int             hist_len, hist_head;
    struct entry   *hnext; /* hash chain */
} entry_t;

typedef struct trie_node {
    struct trie_node *child[2];
    entry_t          *entry; /* set when a prefix terminates here */
} trie_node_t;

struct vg_rib {
    pthread_rwlock_t lock;
    entry_t        **buckets;
    size_t           n_buckets; /* power of two */
    uint64_t         n_entries;
    uint64_t         n_routes;
    uint64_t         events_applied;
    trie_node_t     *root4, *root6;
    uint64_t         trie_nodes;
};

/* ---- hashing ------------------------------------------------------ */

static uint64_t hash_prefix(const vg_prefix_t *p) {
    uint64_t h = 0xCBF29CE484222325ULL;
    h = (h ^ p->family) * 0x100000001B3ULL;
    h = (h ^ p->len) * 0x100000001B3ULL;
    for (int i = 0; i < 16; i++) h = (h ^ p->addr[i]) * 0x100000001B3ULL;
    return h;
}

/* ---- trie --------------------------------------------------------- */

static int prefix_bit(const vg_prefix_t *p, int i) {
    return (p->addr[i / 8] >> (7 - (i % 8))) & 1;
}

static trie_node_t *trie_insert(vg_rib_t *rib, const vg_prefix_t *p) {
    trie_node_t **slot = p->family == VG_AF_INET ? &rib->root4 : &rib->root6;
    if (!*slot) {
        *slot = calloc(1, sizeof(trie_node_t));
        if (!*slot) return NULL;
        rib->trie_nodes++;
    }
    trie_node_t *n = *slot;
    for (int i = 0; i < p->len; i++) {
        int b = prefix_bit(p, i);
        if (!n->child[b]) {
            n->child[b] = calloc(1, sizeof(trie_node_t));
            if (!n->child[b]) return NULL;
            rib->trie_nodes++;
        }
        n = n->child[b];
    }
    return n;
}

/* Walk to the node for p without inserting; NULL if path absent. */
static trie_node_t *trie_find(vg_rib_t *rib, const vg_prefix_t *p) {
    trie_node_t *n = p->family == VG_AF_INET ? rib->root4 : rib->root6;
    for (int i = 0; n && i < p->len; i++) n = n->child[prefix_bit(p, i)];
    return n;
}

static void trie_free(trie_node_t *n) {
    if (!n) return;
    trie_free(n->child[0]);
    trie_free(n->child[1]);
    free(n);
}

/* ---- entries ------------------------------------------------------ */

static entry_t *find_entry(vg_rib_t *rib, const vg_prefix_t *p) {
    uint64_t h = hash_prefix(p) & (rib->n_buckets - 1);
    for (entry_t *e = rib->buckets[h]; e; e = e->hnext)
        if (vg_prefix_equal(&e->prefix, p)) return e;
    return NULL;
}

static void rehash(vg_rib_t *rib) {
    size_t ncap = rib->n_buckets * 2;
    entry_t **nb = calloc(ncap, sizeof(entry_t *));
    if (!nb) return; /* keep the old table; chains just get longer */
    for (size_t i = 0; i < rib->n_buckets; i++) {
        entry_t *e = rib->buckets[i];
        while (e) {
            entry_t *next = e->hnext;
            uint64_t h = hash_prefix(&e->prefix) & (ncap - 1);
            e->hnext = nb[h];
            nb[h] = e;
            e = next;
        }
    }
    free(rib->buckets);
    rib->buckets = nb;
    rib->n_buckets = ncap;
}

static entry_t *find_or_create_entry(vg_rib_t *rib, const vg_prefix_t *p) {
    entry_t *e = find_entry(rib, p);
    if (e) return e;

    if (rib->n_entries >= rib->n_buckets) rehash(rib);
    e = calloc(1, sizeof(entry_t));
    if (!e) return NULL;
    e->prefix = *p;
    uint64_t h = hash_prefix(p) & (rib->n_buckets - 1);
    e->hnext = rib->buckets[h];
    rib->buckets[h] = e;
    rib->n_entries++;

    trie_node_t *tn = trie_insert(rib, p);
    if (tn) tn->entry = e;
    return e;
}

static void push_history(entry_t *e, const vg_event_t *ev) {
    vg_rib_change_t *c = &e->hist[e->hist_head];
    memset(c, 0, sizeof(*c));
    c->ts = ev->timestamp;
    c->kind = ev->kind;
    c->origin_asn = vg_event_origin(ev);
    c->peer_asn = ev->peer_asn;
    memcpy(c->peer, ev->peer, VG_PEER_STRLEN);
    e->hist_head = (e->hist_head + 1) % VG_RIB_HISTORY;
    if (e->hist_len < VG_RIB_HISTORY) e->hist_len++;
}

/* ---- public API ---------------------------------------------------- */

vg_rib_t *vg_rib_new(void) {
    vg_rib_t *rib = calloc(1, sizeof(*rib));
    if (!rib) return NULL;
    rib->n_buckets = 1024;
    rib->buckets = calloc(rib->n_buckets, sizeof(entry_t *));
    if (!rib->buckets) {
        free(rib);
        return NULL;
    }
    pthread_rwlock_init(&rib->lock, NULL);
    return rib;
}

void vg_rib_free(vg_rib_t *rib) {
    if (!rib) return;
    for (size_t i = 0; i < rib->n_buckets; i++) {
        entry_t *e = rib->buckets[i];
        while (e) {
            entry_t *next = e->hnext;
            route_node_t *r = e->routes;
            while (r) {
                route_node_t *rn = r->next;
                free(r);
                r = rn;
            }
            free(e);
            e = next;
        }
    }
    trie_free(rib->root4);
    trie_free(rib->root6);
    free(rib->buckets);
    pthread_rwlock_destroy(&rib->lock);
    free(rib);
}

void vg_rib_apply(vg_rib_t *rib, const vg_event_t *ev) {
    pthread_rwlock_wrlock(&rib->lock);
    rib->events_applied++;

    entry_t *e;
    if (ev->kind == VG_EV_ANNOUNCE) {
        e = find_or_create_entry(rib, &ev->prefix);
        if (!e) goto out;

        route_node_t *r;
        for (r = e->routes; r; r = r->next)
            if (strncmp(r->r.peer, ev->peer, VG_PEER_STRLEN) == 0) break;
        if (!r) {
            r = calloc(1, sizeof(route_node_t));
            if (!r) goto out;
            memcpy(r->r.peer, ev->peer, VG_PEER_STRLEN);
            r->r.first_seen = ev->timestamp;
            r->next = e->routes;
            e->routes = r;
            rib->n_routes++;
        }
        r->r.peer_asn = ev->peer_asn;
        r->r.path = ev->path;
        r->r.origin_attr = ev->origin_attr;
        r->r.next_hop_family = ev->next_hop_family;
        memcpy(r->r.next_hop, ev->next_hop, 16);
        r->r.last_updated = ev->timestamp;
        push_history(e, ev);
    } else {
        /* withdraw: only meaningful if we hold a route from that peer */
        e = find_entry(rib, &ev->prefix);
        if (!e) goto out;
        route_node_t **pp = &e->routes;
        bool removed = false;
        while (*pp) {
            if (strncmp((*pp)->r.peer, ev->peer, VG_PEER_STRLEN) == 0) {
                route_node_t *dead = *pp;
                *pp = dead->next;
                free(dead);
                rib->n_routes--;
                removed = true;
                break;
            }
            pp = &(*pp)->next;
        }
        if (removed) push_history(e, ev);
    }
out:
    pthread_rwlock_unlock(&rib->lock);
}

void vg_rib_sink(const vg_event_t *ev, void *user) {
    vg_rib_apply((vg_rib_t *)user, ev);
}

int vg_rib_lookup(vg_rib_t *rib, const vg_prefix_t *p, vg_rib_route_cb cb,
                  void *user) {
    pthread_rwlock_rdlock(&rib->lock);
    int count = 0;
    entry_t *e = find_entry(rib, p);
    if (e)
        for (route_node_t *r = e->routes; r; r = r->next) {
            if (cb) cb(&e->prefix, &r->r, user);
            count++;
        }
    pthread_rwlock_unlock(&rib->lock);
    return count;
}

int vg_rib_history(vg_rib_t *rib, const vg_prefix_t *p, vg_rib_change_cb cb,
                   void *user) {
    pthread_rwlock_rdlock(&rib->lock);
    int count = 0;
    entry_t *e = find_entry(rib, p);
    if (e) {
        int start = (e->hist_head - e->hist_len + VG_RIB_HISTORY) % VG_RIB_HISTORY;
        for (int i = 0; i < e->hist_len; i++) {
            if (cb) cb(&e->hist[(start + i) % VG_RIB_HISTORY], user);
            count++;
        }
    }
    pthread_rwlock_unlock(&rib->lock);
    return count;
}

static int walk_entries(trie_node_t *n, vg_rib_route_cb cb, void *user,
                        bool skip_self) {
    if (!n) return 0;
    int count = 0;
    if (!skip_self && n->entry)
        for (route_node_t *r = n->entry->routes; r; r = r->next) {
            if (cb) cb(&n->entry->prefix, &r->r, user);
            count++;
        }
    count += walk_entries(n->child[0], cb, user, false);
    count += walk_entries(n->child[1], cb, user, false);
    return count;
}

int vg_rib_more_specifics(vg_rib_t *rib, const vg_prefix_t *p,
                          vg_rib_route_cb cb, void *user) {
    pthread_rwlock_rdlock(&rib->lock);
    trie_node_t *n = trie_find(rib, p);
    int count = walk_entries(n, cb, user, true); /* strictly more specific */
    pthread_rwlock_unlock(&rib->lock);
    return count;
}

int vg_rib_covering(vg_rib_t *rib, const vg_prefix_t *p, vg_rib_route_cb cb,
                    void *user) {
    pthread_rwlock_rdlock(&rib->lock);
    int count = 0;
    trie_node_t *n = p->family == VG_AF_INET ? rib->root4 : rib->root6;
    for (int i = 0; n; i++) {
        if (n->entry)
            for (route_node_t *r = n->entry->routes; r; r = r->next) {
                if (cb) cb(&n->entry->prefix, &r->r, user);
                count++;
            }
        if (i >= p->len) break;
        n = n->child[prefix_bit(p, i)];
    }
    pthread_rwlock_unlock(&rib->lock);
    return count;
}

int vg_rib_by_origin(vg_rib_t *rib, uint32_t asn, vg_rib_route_cb cb,
                     void *user) {
    pthread_rwlock_rdlock(&rib->lock);
    int count = 0;
    for (size_t i = 0; i < rib->n_buckets; i++)
        for (entry_t *e = rib->buckets[i]; e; e = e->hnext)
            for (route_node_t *r = e->routes; r; r = r->next)
                if (vg_aspath_origin(&r->r.path) == asn) {
                    if (cb) cb(&e->prefix, &r->r, user);
                    count++;
                }
    pthread_rwlock_unlock(&rib->lock);
    return count;
}

uint32_t vg_rib_origin_of(vg_rib_t *rib, const vg_prefix_t *p) {
    pthread_rwlock_rdlock(&rib->lock);
    uint32_t best = 0;
    int best_votes = 0;
    entry_t *e = find_entry(rib, p);
    if (e) {
        /* count votes per distinct origin among live routes */
        for (route_node_t *r = e->routes; r; r = r->next) {
            uint32_t o = vg_aspath_origin(&r->r.path);
            if (o == 0) continue;
            int votes = 0;
            for (route_node_t *s = e->routes; s; s = s->next)
                if (vg_aspath_origin(&s->r.path) == o) votes++;
            if (votes > best_votes || (votes == best_votes && (best == 0 || o < best))) {
                best = o;
                best_votes = votes;
            }
        }
    }
    pthread_rwlock_unlock(&rib->lock);
    return best;
}

void vg_rib_stats(vg_rib_t *rib, vg_rib_stats_t *out) {
    pthread_rwlock_rdlock(&rib->lock);
    out->prefixes = rib->n_entries;
    out->routes = rib->n_routes;
    out->events_applied = rib->events_applied;
    out->mem_bytes = rib->n_entries * sizeof(entry_t) +
                     rib->n_routes * sizeof(route_node_t) +
                     rib->trie_nodes * sizeof(trie_node_t) +
                     rib->n_buckets * sizeof(entry_t *);
    pthread_rwlock_unlock(&rib->lock);
}
