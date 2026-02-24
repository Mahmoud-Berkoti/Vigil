#ifndef VIGIL_INGEST_MRTFILE_H
#define VIGIL_INGEST_MRTFILE_H

#include "../vigil.h"

typedef struct {
    uint64_t records;         /* MRT records read */
    uint64_t bgp_updates;     /* BGP UPDATE messages seen (BGP4MP) */
    uint64_t rib_entries;     /* TABLE_DUMP_V2 RIB entries */
    uint64_t announces;       /* announce events emitted */
    uint64_t withdraws;       /* withdraw events emitted */
    uint64_t parse_errors;    /* malformed records/messages skipped */
    uint64_t skipped_records; /* record types we don't ingest */
    uint64_t unique_prefixes;
    uint64_t unique_origins;
} vg_mrt_stats_t;

/* Replay an MRT file (TABLE_DUMP_V2 or BGP4MP) into `sink`.
 * speed: 0 = as fast as possible, otherwise a multiple of real time
 * based on record timestamps (1.0 = realtime; BGP4MP only).
 * Returns 0 on success (malformed records are counted and skipped;
 * only I/O-level corruption aborts), -1 on open failure/corrupt file.
 */
int vg_mrt_replay(const char *path, double speed, vg_event_sink_fn sink,
                  void *user, vg_mrt_stats_t *stats_out);

#endif
