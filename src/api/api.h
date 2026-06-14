/*
 * REST API + dashboard + /metrics, all served from one HTTP server.
 *
 *   GET /api/v1/prefixes/{prefix}       current routes + change history
 *   GET /api/v1/asns/{asn}/prefixes     prefixes currently originated by asn
 *   GET /api/v1/alerts?type=&since=&limit=   alert history (filterable)
 *   GET /api/v1/stats                   RIB + engine + feed counters
 *   GET /metrics                        Prometheus text exposition
 *   GET /                               dashboard (web/index.html)
 */
#ifndef VIGIL_API_H
#define VIGIL_API_H

#include "../alert/store.h"
#include "../detect/detect.h"
#include "../ingest/rislive.h"
#include "../rib/rib.h"

typedef struct vg_api vg_api_t;

vg_api_t *vg_api_start(int port, vg_rib_t *rib, vg_engine_t *engine,
                       vg_store_t *store, vg_rislive_t *live /* nullable */,
                       const char *web_dir);
void vg_api_stop(vg_api_t *api);

#endif
