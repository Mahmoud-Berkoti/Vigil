#include "store.h"

#include "../core/log.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct vg_store {
    sqlite3        *db;
    sqlite3_stmt   *insert;
    pthread_mutex_t mu;
};

static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS alerts ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  ts REAL NOT NULL,"
    "  type TEXT NOT NULL,"
    "  severity TEXT NOT NULL,"
    "  prefix TEXT NOT NULL,"
    "  expected_asn INTEGER,"
    "  observed_asn INTEGER,"
    "  peer TEXT,"
    "  summary TEXT NOT NULL,"
    "  evidence TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);"
    "CREATE INDEX IF NOT EXISTS alerts_type ON alerts(type);";

vg_store_t *vg_store_open(const char *path) {
    vg_store_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    if (sqlite3_open(path, &s->db) != SQLITE_OK) {
        vg_log(VG_LOG_ERROR, "store", "cannot open %s: %s", path,
               s->db ? sqlite3_errmsg(s->db) : "?");
        sqlite3_close(s->db);
        free(s);
        return NULL;
    }
    char *err = NULL;
    if (sqlite3_exec(s->db, SCHEMA, NULL, NULL, &err) != SQLITE_OK) {
        vg_log(VG_LOG_ERROR, "store", "schema: %s", err ? err : "?");
        sqlite3_free(err);
        sqlite3_close(s->db);
        free(s);
        return NULL;
    }
    if (sqlite3_prepare_v2(s->db,
                           "INSERT INTO alerts (ts,type,severity,prefix,"
                           "expected_asn,observed_asn,peer,summary,evidence) "
                           "VALUES (?,?,?,?,?,?,?,?,?)",
                           -1, &s->insert, NULL) != SQLITE_OK) {
        sqlite3_close(s->db);
        free(s);
        return NULL;
    }
    pthread_mutex_init(&s->mu, NULL);
    return s;
}

void vg_store_close(vg_store_t *s) {
    if (!s) return;
    sqlite3_finalize(s->insert);
    sqlite3_close(s->db);
    pthread_mutex_destroy(&s->mu);
    free(s);
}

int vg_store_insert(vg_store_t *s, vg_alert_t *a) {
    char pfx[VG_PREFIX_STRLEN] = "";
    if (a->prefix.family != 0) vg_prefix_format(&a->prefix, pfx, sizeof(pfx));

    pthread_mutex_lock(&s->mu);
    sqlite3_reset(s->insert);
    sqlite3_bind_double(s->insert, 1, a->timestamp);
    sqlite3_bind_text(s->insert, 2, vg_alert_type_str(a->type), -1, SQLITE_STATIC);
    sqlite3_bind_text(s->insert, 3, vg_severity_str(a->severity), -1, SQLITE_STATIC);
    sqlite3_bind_text(s->insert, 4, pfx, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s->insert, 5, a->expected_asn);
    sqlite3_bind_int64(s->insert, 6, a->observed_asn);
    sqlite3_bind_text(s->insert, 7, a->peer, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s->insert, 8, a->summary, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s->insert, 9, a->evidence, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s->insert);
    if (rc == SQLITE_DONE) a->id = sqlite3_last_insert_rowid(s->db);
    pthread_mutex_unlock(&s->mu);

    if (rc != SQLITE_DONE) {
        vg_log(VG_LOG_ERROR, "store", "insert failed: %s", sqlite3_errmsg(s->db));
        return -1;
    }
    return 0;
}

static int type_from_str(const char *t) {
    for (int i = 0; i <= VG_ALERT_SPIKE; i++)
        if (strcmp(vg_alert_type_str((vg_alert_type_t)i), t) == 0) return i;
    return -1;
}

static int severity_from_str(const char *t) {
    for (int i = 0; i <= VG_SEV_CRITICAL; i++)
        if (strcmp(vg_severity_str((vg_severity_t)i), t) == 0) return i;
    return -1;
}

int vg_store_query(vg_store_t *s, const vg_store_filter_t *f,
                   vg_store_alert_cb cb, void *user) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT id,ts,type,severity,prefix,expected_asn,observed_asn,"
             "peer,summary,evidence FROM alerts WHERE ts >= ?"
             "%s%s ORDER BY id DESC LIMIT ?",
             f->type >= 0 ? " AND type = ?" : "",
             f->prefix ? " AND prefix = ?" : "");

    pthread_mutex_lock(&s->mu);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->mu);
        return -1;
    }
    int bind = 1;
    sqlite3_bind_double(st, bind++, f->since);
    if (f->type >= 0)
        sqlite3_bind_text(st, bind++, vg_alert_type_str((vg_alert_type_t)f->type),
                          -1, SQLITE_STATIC);
    if (f->prefix) sqlite3_bind_text(st, bind++, f->prefix, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, bind++, f->limit > 0 ? f->limit : 100);

    int count = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        vg_alert_t a;
        memset(&a, 0, sizeof(a));
        a.id = sqlite3_column_int64(st, 0);
        a.timestamp = sqlite3_column_double(st, 1);
        int t = type_from_str((const char *)sqlite3_column_text(st, 2));
        a.type = t >= 0 ? (vg_alert_type_t)t : VG_ALERT_HIJACK;
        int sev = severity_from_str((const char *)sqlite3_column_text(st, 3));
        a.severity = sev >= 0 ? (vg_severity_t)sev : VG_SEV_INFO;
        const char *pfx = (const char *)sqlite3_column_text(st, 4);
        if (pfx && pfx[0]) vg_prefix_parse(pfx, &a.prefix);
        a.expected_asn = (uint32_t)sqlite3_column_int64(st, 5);
        a.observed_asn = (uint32_t)sqlite3_column_int64(st, 6);
        snprintf(a.peer, sizeof(a.peer), "%.*s", (int)sizeof(a.peer) - 1,
                 (const char *)sqlite3_column_text(st, 7));
        snprintf(a.summary, sizeof(a.summary), "%.*s", (int)sizeof(a.summary) - 1,
                 (const char *)sqlite3_column_text(st, 8));
        snprintf(a.evidence, sizeof(a.evidence), "%.*s", (int)sizeof(a.evidence) - 1,
                 (const char *)sqlite3_column_text(st, 9));

        /* severity filter applied post-decode (>= minimum) */
        if (f->severity >= 0 && (int)a.severity < f->severity) continue;
        if (cb) cb(&a, user);
        count++;
    }
    sqlite3_finalize(st);
    pthread_mutex_unlock(&s->mu);
    return count;
}

int vg_store_counts(vg_store_t *s, uint64_t out[5]) {
    memset(out, 0, 5 * sizeof(uint64_t));
    pthread_mutex_lock(&s->mu);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT type, COUNT(*) FROM alerts GROUP BY type",
                           -1, &st, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s->mu);
        return -1;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        int t = type_from_str((const char *)sqlite3_column_text(st, 0));
        if (t >= 0 && t < 5) out[t] = (uint64_t)sqlite3_column_int64(st, 1);
    }
    sqlite3_finalize(st);
    pthread_mutex_unlock(&s->mu);
    return 0;
}
