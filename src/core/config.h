#ifndef VIGIL_CONFIG_H
#define VIGIL_CONFIG_H

#include "../vigil.h"

#define VG_MAX_WATCH 256
#define VG_PATH_MAX  512

typedef struct {
    int  api_port;            /* REST + dashboard + /metrics, default 8080 */

    char mrt_file[VG_PATH_MAX];   /* replay source ("" = disabled) */
    double replay_speed;          /* 0 = full speed, 1 = realtime, 2 = 2x... */

    bool rislive_enabled;         /* opt-in live feed */
    char rislive_host[128];       /* RRC/collector filter, "" = all */
    char rislive_prefix[VG_PREFIX_STRLEN]; /* prefix filter, "" = all */

    char vrp_file[VG_PATH_MAX];   /* RPKI VRP JSON ("" = disabled) */
    char alert_db[VG_PATH_MAX];   /* SQLite path, default vigil.db */
    char webhook_url[VG_PATH_MAX];/* alert webhook ("" = disabled) */

    /* Watchlist: prefixes we care most about + their expected origins.
     * expected_origin 0 means "learn from baseline window". */
    int         n_watch;
    vg_prefix_t watch_prefix[VG_MAX_WATCH];
    uint32_t    watch_origin[VG_MAX_WATCH];

    double baseline_window; /* secs of observation before hijack alerts fire */
    double spike_window;    /* rolling window for rate detection, secs */
    double spike_factor;    /* burst multiple over baseline that alerts */
} vg_config_t;

void vg_config_defaults(vg_config_t *c);
/* Parse key=value config file. Returns 0 ok, -1 on I/O or parse error
 * (logs the offending line). */
int vg_config_load(vg_config_t *c, const char *path);

#endif
