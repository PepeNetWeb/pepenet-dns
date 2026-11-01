/* dns_chain.c — see dns_chain.h. Plain sqlite over the indexer's tables (no
 * indexer symbols), so the standalone tests and the tls embed link light. */
#include "dns_chain.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct DnsChain {
    sqlite3      *db;
    sqlite3_stmt *q_owner;    /* SELECT owner, lease_expiry FROM names WHERE name=? */
    sqlite3_stmt *q_hash;     /* SELECT hash FROM blocks WHERE height=? */
    sqlite3_stmt *q_tip;      /* SELECT v FROM meta WHERE k='height' */
    sqlite3_stmt *q_peer;     /* SELECT v FROM meta WHERE k='peer_height' */
    sqlite3_stmt *q_times;    /* SELECT time FROM blocks WHERE height<=? (MTP) */
};

/* Statements prepare LAZILY: on a first boot the indexer may not have created
 * the db/schema yet, and an embedder's resolver must tolerate that (answer
 * unowned/tip-0) rather than die — exactly what the old carrier view did.
 * Once a prepare succeeds it is cached for the connection's lifetime. */
static sqlite3_stmt *ensure(DnsChain *c, sqlite3_stmt **slot, const char *sql) {
    if (!*slot) sqlite3_prepare_v2(c->db, sql, -1, slot, NULL);
    return *slot;
}

DnsChain *dns_chain_open(const char *path) {
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        db = NULL;
        /* first boot: the file may not exist yet — create an empty shell; the
         * lazy prepares above start answering once the indexer lays schema. */
        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
            fprintf(stderr, "dns_chain: open %s: %s\n", path, db ? sqlite3_errmsg(db) : "?");
            if (db) sqlite3_close(db);
            return NULL;
        }
    }
    sqlite3_busy_timeout(db, 2000);
    DnsChain *c = calloc(1, sizeof *c);
    c->db = db;
    return c;
}

void dns_chain_close(DnsChain *c) {
    if (!c) return;
    if (c->q_owner) sqlite3_finalize(c->q_owner);
    if (c->q_hash)  sqlite3_finalize(c->q_hash);
    if (c->q_tip)   sqlite3_finalize(c->q_tip);
    if (c->q_peer)  sqlite3_finalize(c->q_peer);
    if (c->q_times) sqlite3_finalize(c->q_times);
    if (c->db)      sqlite3_close(c->db);
    free(c);
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}
static uint32_t oc_tip(void *u);
/* MTP for the block after the tip: median of the <=11 timestamps at heights
 * <= tip (same as sm_mtp(ts, n) = sorted[n/2]). 1 ok, 0 no block times. */
static int oc_mtp(DnsChain *c, int64_t *out) {
    uint32_t tip = oc_tip(c);
    if (!ensure(c, &c->q_times,
                "SELECT time FROM blocks WHERE height<=?1 ORDER BY height DESC LIMIT 11")) return 0;
    int64_t ts[11]; int n = 0;
    sqlite3_reset(c->q_times);
    sqlite3_bind_int64(c->q_times, 1, (int64_t)tip);
    while (n < 11 && sqlite3_step(c->q_times) == SQLITE_ROW)
        ts[n++] = sqlite3_column_int64(c->q_times, 0);
    sqlite3_reset(c->q_times);   /* release the read txn */
    if (n == 0) return 0;
    qsort(ts, (size_t)n, sizeof ts[0], cmp_i64);
    *out = ts[n / 2];
    return 1;
}

static int oc_owner(void *u, const char *name, uint8_t owner[20]) {
    DnsChain *c = u;
    int ok = 0;
    if (!ensure(c, &c->q_owner, "SELECT owner, lease_expiry FROM names WHERE name=?1")) return 0;
    sqlite3_reset(c->q_owner);
    sqlite3_bind_text(c->q_owner, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(c->q_owner) == SQLITE_ROW &&
        sqlite3_column_bytes(c->q_owner, 0) == 20) {
        int64_t expiry = sqlite3_column_int64(c->q_owner, 1);
        /* the lease gate, on CHAIN time: owned iff MTP < lease_expiry, where
         * MTP is the median of the <=11 block timestamps at heights <= tip,
         * i.e. the MTP the indexer's fold uses for the next block (tip+1,
         * namespace-indexer oracle_for_height/sm_mtp). Never wall clock.
         * No block times known => unowned (fail closed, like a first boot). */
        int64_t mtp;
        if (oc_mtp(c, &mtp) && expiry > mtp) {
            memcpy(owner, sqlite3_column_blob(c->q_owner, 0), 20);
            ok = 1;
        }
    }
    sqlite3_reset(c->q_owner);   /* release the read txn — never pin the WAL snapshot */
    return ok;
}

static uint32_t oc_tip(void *u) {
    DnsChain *c = u;
    uint32_t tip = 0;
    if (!ensure(c, &c->q_tip, "SELECT v FROM meta WHERE k='height'")) return 0;
    sqlite3_reset(c->q_tip);
    if (sqlite3_step(c->q_tip) == SQLITE_ROW)
        tip = (uint32_t)strtoll((const char *)sqlite3_column_text(c->q_tip, 0), NULL, 10);
    sqlite3_reset(c->q_tip);     /* release the read txn — never pin the WAL snapshot */
    return tip;
}

static int oc_header(void *u, uint32_t height, uint8_t out[32]) {
    DnsChain *c = u;
    if (height > oc_tip(u)) return 0;                /* ahead of our sync → hold */
    if (!ensure(c, &c->q_hash, "SELECT hash FROM blocks WHERE height=?1")) return -1;
    sqlite3_reset(c->q_hash);
    sqlite3_bind_int64(c->q_hash, 1, (int64_t)height);
    if (sqlite3_step(c->q_hash) == SQLITE_ROW && sqlite3_column_bytes(c->q_hash, 0) == 32) {
        memcpy(out, sqlite3_column_blob(c->q_hash, 0), 32);
        sqlite3_reset(c->q_hash);
        return 1;
    }
    sqlite3_reset(c->q_hash);    /* release the read txn — never pin the WAL snapshot */
    return -1;                                       /* below our checkpoint horizon */
}

SpChainOracle dns_chain_oracle(DnsChain *c) {
    SpChainOracle o = { c, oc_owner, oc_header, oc_tip };
    return o;
}

static int64_t meta_i64(DnsChain *c, sqlite3_stmt **slot, const char *sql) {
    int64_t v = 0;
    if (!ensure(c, slot, sql)) return 0;
    sqlite3_reset(*slot);
    if (sqlite3_step(*slot) == SQLITE_ROW) {
        const char *s = (const char *)sqlite3_column_text(*slot, 0);
        if (s) v = strtoll(s, NULL, 10);
    }
    sqlite3_reset(*slot);
    return v;
}

void dns_chain_sync(DnsChain *c, int64_t *height, int64_t *peer_height) {
    if (height)      *height = 0;
    if (peer_height) *peer_height = 0;
    if (!c) return;
    if (height)      *height = meta_i64(c, &c->q_tip,  "SELECT v FROM meta WHERE k='height'");
    if (peer_height) *peer_height = meta_i64(c, &c->q_peer, "SELECT v FROM meta WHERE k='peer_height'");
}
