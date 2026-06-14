/* Alert fan-out: structured log always; optional webhook POST (JSON)
 * delivered from a background thread so ingest never blocks on HTTP. */
#ifndef VIGIL_ALERT_NOTIFY_H
#define VIGIL_ALERT_NOTIFY_H

#include "../vigil.h"

typedef struct vg_notifier vg_notifier_t;

/* webhook_url may be "" (log-only). */
vg_notifier_t *vg_notifier_start(const char *webhook_url);
void           vg_notifier_stop(vg_notifier_t *n);
void           vg_notifier_send(vg_notifier_t *n, const vg_alert_t *a);

/* Serialize an alert as JSON (shared with the API). Returns chars
 * written (truncated if needed). */
int vg_alert_to_json(const vg_alert_t *a, char *buf, size_t n);

#endif
