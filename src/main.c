/* vigil — BGP route monitor & anomaly detector.
 *
 * Serve mode wires ingestion (RIS Live or MRT replay, per config) into
 * the RIB and detection engine, persists alerts to SQLite, optionally
 * posts them to a webhook, and exposes the REST API + dashboard +
 * Prometheus metrics on one HTTP port.
 */
#include "alert/notify.h"
#include "alert/store.h"
#include "api/api.h"
#include "core/config.h"
#include "core/log.h"
#include "detect/detect.h"
#include "ingest/mrtfile.h"
#include "ingest/rislive.h"
#include "ingest/stub.h"
#include "rib/rib.h"
#include "rpki/rpki.h"
#include "vigil.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_shutdown = 0;
static void on_signal(int sig) {
    (void)sig;
    g_shutdown = 1;
}

/* ---- one-shot tools: `vigil rov` and `vigil -r` replay stats -------- */

static void usage(void) {
    fprintf(stderr,
            "usage: vigil [-c config] [-v]           serve (API + dashboard + ingest)\n"
            "       vigil -r file.mrt [-q prefix]     replay stats, then exit\n"
            "       vigil rov VRP.json PREFIX ASN     classify one route\n"
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

static int cmd_rov(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: vigil rov VRP.json PREFIX ASN\n");
        return 2;
    }
    vg_rpki_t *r = vg_rpki_load(argv[2]);
    if (!r) return 1;
    vg_prefix_t p;
    if (vg_prefix_parse(argv[3], &p) != 0) {
        fprintf(stderr, "bad prefix: %s\n", argv[3]);
        return 2;
    }
    uint32_t asn = (uint32_t)strtoul(argv[4], NULL, 10);
    printf("%s\n", vg_rov_str(vg_rpki_validate(r, &p, asn)));
    vg_rpki_free(r);
    return 0;
}

static int cmd_replay_stats(const char *replay_path, const char *query_prefix,
                            const vg_config_t *cfg) {
    vg_rib_t *rib = vg_rib_new();
    if (!rib) return 1;
    vg_mrt_stats_t st;
    if (vg_mrt_replay(replay_path, cfg->replay_speed, vg_rib_sink, rib, &st) != 0)
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

/* ---- serve mode ------------------------------------------------------ */

typedef struct {
    vg_store_t    *store;
    vg_notifier_t *notifier;
} alert_ctx_t;

static void on_alert(const vg_alert_t *alert, void *user) {
    alert_ctx_t *ctx = user;
    vg_alert_t a = *alert;
    vg_store_insert(ctx->store, &a); /* assigns a.id */
    vg_notifier_send(ctx->notifier, &a);
}

typedef struct {
    const char  *path;
    double       speed;
    vg_engine_t *engine;
} replay_thread_ctx_t;

static void *replay_thread(void *arg) {
    replay_thread_ctx_t *c = arg;
    vg_mrt_stats_t st;
    vg_mrt_replay(c->path, c->speed, vg_engine_sink, c->engine, &st);
    vg_log(VG_LOG_INFO, "main", "replay of %s complete", c->path);
    return NULL;
}

static int cmd_serve(const vg_config_t *cfg) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    vg_rib_t *rib = vg_rib_new();
    vg_store_t *store = vg_store_open(cfg->alert_db);
    if (!rib || !store) return 1;

    vg_notifier_t *notifier = vg_notifier_start(cfg->webhook_url);
    alert_ctx_t actx = {store, notifier};
    vg_engine_t *engine = vg_engine_new(cfg, rib, on_alert, &actx);
    if (!engine) return 1;

    vg_rpki_t *rpki = NULL;
    if (cfg->vrp_file[0]) {
        rpki = vg_rpki_load(cfg->vrp_file);
        if (rpki) vg_engine_set_rpki(engine, rpki);
    }

    vg_rislive_t *live = NULL;
    pthread_t replay_tid;
    bool replay_running = false;

    if (cfg->rislive_enabled) {
        vg_rislive_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        snprintf(opts.host, sizeof(opts.host), "%s", cfg->rislive_host);
        snprintf(opts.prefix, sizeof(opts.prefix), "%s", cfg->rislive_prefix);
        live = vg_rislive_start(&opts, vg_engine_sink, engine);
        if (!live) return 1;
    } else if (cfg->mrt_file[0]) {
        static replay_thread_ctx_t rc;
        rc.path = cfg->mrt_file;
        rc.speed = cfg->replay_speed;
        rc.engine = engine;
        if (pthread_create(&replay_tid, NULL, replay_thread, &rc) == 0)
            replay_running = true;
    } else {
        vg_stub_run(vg_engine_sink, engine);
    }

    vg_api_t *api = vg_api_start(cfg->api_port, rib, engine, store, live, "web");
    if (!api) {
        vg_log(VG_LOG_ERROR, "main", "failed to start API on :%d", cfg->api_port);
        return 1;
    }
    vg_log(VG_LOG_INFO, "main",
          "vigil serving on :%d (watch=%d rpki=%s rislive=%s mrt=%s)",
          cfg->api_port, cfg->n_watch, rpki ? "yes" : "no",
          cfg->rislive_enabled ? "yes" : "no", cfg->mrt_file[0] ? cfg->mrt_file : "-");

    while (!g_shutdown) sleep(1);

    vg_log(VG_LOG_INFO, "main", "shutting down");
    vg_api_stop(api);
    if (live) vg_rislive_stop(live);
    if (replay_running) pthread_cancel(replay_tid); /* best-effort on shutdown */
    vg_notifier_stop(notifier);
    if (rpki) vg_rpki_free(rpki);
    vg_engine_free(engine);
    vg_store_close(store);
    vg_rib_free(rib);
    return 0;
}

int main(int argc, char **argv) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);

    if (argc >= 2 && strcmp(argv[1], "rov") == 0) return cmd_rov(argc, argv);

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

    if (replay_path) return cmd_replay_stats(replay_path, query_prefix, &cfg);

    return cmd_serve(&cfg);
}
