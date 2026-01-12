#include "stub.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

void vg_stub_run(vg_event_sink_fn sink, void *user) {
    double now = (double)time(NULL);

    vg_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = VG_EV_ANNOUNCE;
    vg_prefix_parse("192.0.2.0/24", &ev.prefix);
    vg_aspath_parse("64500 64510 64520", &ev.path);
    ev.origin_attr = VG_ORIGIN_IGP;
    ev.next_hop_family = VG_AF_INET;
    ev.next_hop[0] = 203; ev.next_hop[1] = 0; ev.next_hop[2] = 113; ev.next_hop[3] = 1;
    ev.timestamp = now;
    snprintf(ev.peer, sizeof(ev.peer), "203.0.113.1");
    ev.peer_asn = 64500;
    snprintf(ev.source, sizeof(ev.source), "stub");
    sink(&ev, user);

    memset(&ev, 0, sizeof(ev));
    ev.kind = VG_EV_WITHDRAW;
    vg_prefix_parse("198.51.100.0/24", &ev.prefix);
    ev.timestamp = now;
    snprintf(ev.peer, sizeof(ev.peer), "203.0.113.1");
    ev.peer_asn = 64500;
    snprintf(ev.source, sizeof(ev.source), "stub");
    sink(&ev, user);
}
