/* vigil — BGP route monitor & anomaly detector.
 *
 * Phase 0: config + stub adapter flowing into a logging sink. Real
 * adapters, RIB, detectors, and the API are added phase by phase.
 */
#include "core/config.h"
#include "core/log.h"
#include "ingest/stub.h"
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
            "usage: vigil [-c config] [-v]\n"
            "  -c FILE   config file (key=value)\n"
            "  -v        debug logging\n");
}

int main(int argc, char **argv) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);

    const char *config_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0) {
            vg_log_set_level(VG_LOG_DEBUG);
        } else {
            usage();
            return 2;
        }
    }
    if (config_path && vg_config_load(&cfg, config_path) != 0) return 1;

    vg_log(VG_LOG_INFO, "main", "vigil starting (api_port=%d watch=%d)",
           cfg.api_port, cfg.n_watch);

    vg_stub_run(log_sink, NULL);

    vg_log(VG_LOG_INFO, "main", "stub pipeline complete");
    return 0;
}
