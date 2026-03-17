/* vigil — BGP route monitor & anomaly detector.
 *
 * Phase 0: config + stub adapter flowing into a logging sink. Real
 * adapters, RIB, detectors, and the API are added phase by phase.
 */
#include "core/config.h"
#include "core/log.h"
#include "ingest/mrtfile.h"
#include "ingest/stub.h"
#include "rib/rib.h"
#include "vigil.h"

#include <stdio.h>
#include <string.h>

static void log_sink(const vg_event_t *ev, void *user) {
    (void)user;
    char pfx[VG_PREFIX_STRLEN], path[1024];
    vg_prefix_format(&ev->prefix, pfx, sizeof(pfx));
    if (ev->kind == VG_EV_ANNOUNCE) {
        vg_aspath_format(&ev->path, path, sizeof(path));
        vg_log(VG_LOG_INFO, "pipeline", "announce %s path=[%s] origin=AS%u peer=%s src=%s",
               pfx, path, vg_event_origin(ev), ev->peer, ev->source);
    } else {
        vg_log(VG_LOG_INFO, "pipeline", "withdraw %s peer=%s src=%s", pfx,
               ev->peer, ev->source);
    }
}

static void usage(void) {
    fprintf(stderr,
            "usage: vigil [-c config] [-r file.mrt [-q prefix]] [-v]\n"
            "  -c FILE   config file (key=value)\n"
            "  -r FILE   replay an MRT file into the RIB, print stats, exit\n"
            "  -q PFX    after -r replay, print current origin(s) for PFX\n"
            "  -v        debug logging\n");
}

static void print_route(const vg_prefix_t *p, const vg_rib_route_t *r,
                        void *user) {
    (void)user;
    char pfx[VG_PREFIX_STRLEN], path[1024];
    vg_prefix_format(p, pfx, sizeof(pfx));
    vg_aspath_format(&r->path, path, sizeof(path));
    printf("%s via peer %s (AS%u): path [%s] origin AS%u\n", pfx, r->peer,
           r->peer_asn, path, vg_aspath_origin(&r->path));
}

int main(int argc, char **argv) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);

    const char *config_path = NULL, *replay_path = NULL, *query_prefix = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            replay_path = argv[++i];
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            query_prefix = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            vg_log_set_level(VG_LOG_DEBUG);
        } else {
            usage();
            return 2;
        }
    }
    if (config_path && vg_config_load(&cfg, config_path) != 0) return 1;

    if (replay_path) {
        vg_rib_t *rib = vg_rib_new();
        if (!rib) return 1;
        vg_mrt_stats_t st;
        if (vg_mrt_replay(replay_path, cfg.replay_speed, vg_rib_sink, rib, &st) != 0)
            return 1;
        printf("records=%llu updates=%llu rib_entries=%llu announces=%llu "
               "withdraws=%llu prefixes=%llu origins=%llu errors=%llu skipped=%llu\n",
               (unsigned long long)st.records, (unsigned long long)st.bgp_updates,
               (unsigned long long)st.rib_entries, (unsigned long long)st.announces,
               (unsigned long long)st.withdraws, (unsigned long long)st.unique_prefixes,
               (unsigned long long)st.unique_origins, (unsigned long long)st.parse_errors,
               (unsigned long long)st.skipped_records);

        vg_rib_stats_t rs;
        vg_rib_stats(rib, &rs);
        printf("rib: prefixes=%llu routes=%llu events=%llu mem=%.1fMB\n",
               (unsigned long long)rs.prefixes, (unsigned long long)rs.routes,
               (unsigned long long)rs.events_applied,
               (double)rs.mem_bytes / (1024 * 1024));

        if (query_prefix) {
            vg_prefix_t qp;
            if (vg_prefix_parse(query_prefix, &qp) != 0) {
                fprintf(stderr, "bad prefix: %s\n", query_prefix);
                return 2;
            }
            int nr = vg_rib_lookup(rib, &qp, print_route, NULL);
            printf("%d route(s); dominant origin: AS%u\n", nr,
                   vg_rib_origin_of(rib, &qp));
        }
        vg_rib_free(rib);
        return 0;
    }

    vg_log(VG_LOG_INFO, "main", "vigil starting (api_port=%d watch=%d)",
           cfg.api_port, cfg.n_watch);

    vg_stub_run(log_sink, NULL);

    vg_log(VG_LOG_INFO, "main", "stub pipeline complete");
    return 0;
}
