/* Prometheus text-format exposition (served at /metrics). */
#ifndef VIGIL_METRICS_H
#define VIGIL_METRICS_H

#include "../detect/detect.h"
#include "../ingest/rislive.h"
#include "../rib/rib.h"

#include <stddef.h>

/* Renders current metrics into buf (bounded). Returns bytes written. */
size_t vg_metrics_render(vg_rib_t *rib, vg_engine_t *engine,
                         vg_rislive_t *live /* nullable */, char *buf, size_t n);

#endif
