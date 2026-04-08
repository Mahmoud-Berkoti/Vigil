#ifndef VIGIL_INGEST_RISLIVE_H
#define VIGIL_INGEST_RISLIVE_H

#include "../vigil.h"

#include <stdbool.h>

typedef struct {
    char host[128];                    /* collector filter, "" = all */
    char prefix[VG_PREFIX_STRLEN];     /* prefix filter, "" = all */
} vg_rislive_opts_t;

typedef struct {
    uint64_t messages;     /* ris_message lines processed */
    uint64_t events;       /* normalized events emitted */
    uint64_t parse_errors; /* undecodable lines */
    uint64_t reconnects;
    bool     connected;
} vg_rislive_stats_t;

typedef struct vg_rislive vg_rislive_t;

/* Start the client on its own thread; events flow into `sink` from
 * that thread. Returns NULL on setup failure. */
vg_rislive_t *vg_rislive_start(const vg_rislive_opts_t *opts,
                               vg_event_sink_fn sink, void *user);
void vg_rislive_stats(vg_rislive_t *c, vg_rislive_stats_t *out);
/* Signal shutdown, join the thread, free. */
void vg_rislive_stop(vg_rislive_t *c);

/* Normalize one RIS Live JSON line into events (exposed for tests).
 * Returns number of events emitted, or -1 on parse failure. Non-UPDATE
 * messages (ris_error, keepalives, RIS peer state) return 0. */
int vg_rislive_handle_line(const char *line, size_t len,
                           vg_event_sink_fn sink, void *user);

#endif
