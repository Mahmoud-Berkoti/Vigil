#ifndef VIGIL_INGEST_STUB_H
#define VIGIL_INGEST_STUB_H

#include "../vigil.h"

/* Emits a small hardcoded sequence of UpdateEvents into the sink.
 * Used to prove the pipeline end-to-end before real adapters exist. */
void vg_stub_run(vg_event_sink_fn sink, void *user);

#endif
