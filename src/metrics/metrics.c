#include "metrics.h"

#include "../util/sbuf.h"

#include <string.h>

size_t vg_metrics_render(vg_rib_t *rib, vg_engine_t *engine,
                         vg_rislive_t *live, char *buf, size_t n) {
    vg_sbuf_t b;
    vg_sbuf_init(&b);

    vg_rib_stats_t rs;
    vg_rib_stats(rib, &rs);
    vg_sbuf_puts(&b, "# HELP vigil_rib_prefixes Prefixes currently held in the RIB\n"
                     "# TYPE vigil_rib_prefixes gauge\n");
    vg_sbuf_printf(&b, "vigil_rib_prefixes %llu\n", (unsigned long long)rs.prefixes);
    vg_sbuf_puts(&b, "# HELP vigil_rib_routes Live (prefix,peer) routes in the RIB\n"
                     "# TYPE vigil_rib_routes gauge\n");
    vg_sbuf_printf(&b, "vigil_rib_routes %llu\n", (unsigned long long)rs.routes);
    vg_sbuf_puts(&b, "# HELP vigil_rib_events_total Events applied to the RIB\n"
                     "# TYPE vigil_rib_events_total counter\n");
    vg_sbuf_printf(&b, "vigil_rib_events_total %llu\n",
                  (unsigned long long)rs.events_applied);
    vg_sbuf_puts(&b, "# HELP vigil_rib_memory_bytes Approximate RIB heap usage\n"
                     "# TYPE vigil_rib_memory_bytes gauge\n");
    vg_sbuf_printf(&b, "vigil_rib_memory_bytes %llu\n",
                  (unsigned long long)rs.mem_bytes);

    vg_engine_stats_t es;
    vg_engine_stats(engine, &es);
    vg_sbuf_puts(&b, "# HELP vigil_events_processed_total Events processed by the detection engine\n"
                     "# TYPE vigil_events_processed_total counter\n");
    vg_sbuf_printf(&b, "vigil_events_processed_total %llu\n",
                  (unsigned long long)es.events);
    vg_sbuf_puts(&b, "# HELP vigil_alerts_total Alerts emitted, by type\n"
                     "# TYPE vigil_alerts_total counter\n");
    static const vg_alert_type_t types[] = {
        VG_ALERT_HIJACK, VG_ALERT_SUBPREFIX, VG_ALERT_LEAK,
        VG_ALERT_RPKI_INVALID, VG_ALERT_SPIKE,
    };
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        vg_sbuf_printf(&b, "vigil_alerts_total{type=\"%s\"} %llu\n",
                      vg_alert_type_str(types[i]),
                      (unsigned long long)es.alerts[types[i]]);
    vg_sbuf_puts(&b, "# HELP vigil_alerts_suppressed_total Alerts suppressed by cooldown\n"
                     "# TYPE vigil_alerts_suppressed_total counter\n");
    vg_sbuf_printf(&b, "vigil_alerts_suppressed_total %llu\n",
                  (unsigned long long)es.suppressed);

    if (live) {
        vg_rislive_stats_t ls;
        vg_rislive_stats(live, &ls);
        vg_sbuf_puts(&b, "# HELP vigil_rislive_connected RIS Live connection state (1=connected)\n"
                         "# TYPE vigil_rislive_connected gauge\n");
        vg_sbuf_printf(&b, "vigil_rislive_connected %d\n", ls.connected ? 1 : 0);
        vg_sbuf_puts(&b, "# HELP vigil_rislive_messages_total RIS Live messages received\n"
                         "# TYPE vigil_rislive_messages_total counter\n");
        vg_sbuf_printf(&b, "vigil_rislive_messages_total %llu\n",
                      (unsigned long long)ls.messages);
        vg_sbuf_puts(&b, "# HELP vigil_rislive_parse_errors_total RIS Live lines that failed to parse\n"
                         "# TYPE vigil_rislive_parse_errors_total counter\n");
        vg_sbuf_printf(&b, "vigil_rislive_parse_errors_total %llu\n",
                      (unsigned long long)ls.parse_errors);
        vg_sbuf_puts(&b, "# HELP vigil_rislive_reconnects_total RIS Live reconnection attempts\n"
                         "# TYPE vigil_rislive_reconnects_total counter\n");
        vg_sbuf_printf(&b, "vigil_rislive_reconnects_total %llu\n",
                      (unsigned long long)ls.reconnects);
    }

    size_t w = b.len < n ? b.len : n - 1;
    memcpy(buf, b.data ? b.data : "", w);
    buf[w] = '\0';
    vg_sbuf_free(&b);
    return w;
}
