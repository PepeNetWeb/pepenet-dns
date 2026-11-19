/* a81_dns_test.c — A8-1 through the REAL dns_chain oracle (indexer-schema
 * sqlite: meta/blocks/names/epochs) and the shipping DNS_A81_FROM constant.
 *
 * A late first op from a new owner: the publisher's chain view is at the
 * transfer block E, the receiver's is E+3 when the op arrives. With E at the
 * activation height the receiver admits it; with E one block below activation
 * the legacy rule rejects it "anchor below floor" (exactly the pre-A8-1
 * behaviour). Also pins oc_epoch's guards (lapse row, lagging epochs row,
 * unknown name => -1 => legacy floor) and that the previous owner's ops stay
 * rejected. */
#include "dns_chain.h"
#include "dns_state.h"
#include "zone.h"
#include "pepenet/crypto.h"
#include "pepenet/state.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails, oks;
#define CK(c, m) do { if (c) { printf("ok   %s\n", m); oks++; } else { printf("FAIL %s\n", m); fails++; } } while (0)
static void ex(sqlite3 *db, const char *q) { char *e = 0; if (sqlite3_exec(db, q, 0, 0, &e) != SQLITE_OK) { fprintf(stderr, "%s: %s\n", q, e); exit(2); } }

typedef struct { uint8_t priv[32], pub[33], h160[20]; } Key;
static Key mk(const char *s) {
    Key k; sp_sha256((const uint8_t *)s, strlen(s), k.priv);
    while (!sp_pubkey(k.priv, k.pub)) sp_sha256(k.priv, 32, k.priv);
    sp_hash160(k.pub, 33, k.h160);
    return k;
}

static void chain_make(const char *path, uint32_t lo, uint32_t tip) {
    unlink(path);
    sqlite3 *db; sqlite3_open(path, &db);
    ex(db, "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);"
           "CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash BLOB, time INTEGER);"
           "CREATE TABLE names(name TEXT PRIMARY KEY, owner BLOB, lease_expiry INT);"
           "CREATE TABLE epochs(name TEXT, start_height INTEGER, owner BLOB, owner_type INT, PRIMARY KEY(name, start_height));");
    sqlite3_stmt *st; sqlite3_prepare_v2(db, "INSERT INTO blocks VALUES(?,?,?)", -1, &st, 0);
    for (uint32_t h = lo; h <= tip + 10; h++) {          /* rows above tip exist but are ignored */
        uint8_t seed[12], hh[32]; memcpy(seed, "blk:", 4); memcpy(seed + 4, &h, 4); memset(seed + 8, 0, 4);
        sp_sha256(seed, sizeof seed, hh);
        sqlite3_bind_int64(st, 1, h); sqlite3_bind_blob(st, 2, hh, 32, SQLITE_TRANSIENT); sqlite3_bind_int64(st, 3, 1700000000LL + 60LL * h);
        sqlite3_step(st); sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    char q[96]; snprintf(q, sizeof q, "INSERT INTO meta VALUES('height','%u')", tip); ex(db, q);
    sqlite3_close(db);
}
static void chain_tip(const char *path, uint32_t tip) {
    sqlite3 *db; sqlite3_open(path, &db); char q[96];
    snprintf(q, sizeof q, "UPDATE meta SET v='%u' WHERE k='height'", tip); ex(db, q); sqlite3_close(db);
}
/* owner change at height h: names row + epochs row (what the indexer's fold writes) */
static void chain_owner(const char *path, const char *name, const uint8_t h160[20], uint32_t h, int epochs_row) {
    sqlite3 *db; sqlite3_open(path, &db); sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO names VALUES(?,?,9999999999)", -1, &st, 0);
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC); sqlite3_bind_blob(st, 2, h160, 20, SQLITE_STATIC);
    sqlite3_step(st); sqlite3_finalize(st);
    if (epochs_row) {
        sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO epochs VALUES(?,?,?,0)", -1, &st, 0);
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC); sqlite3_bind_int64(st, 2, h);
        if (h160) sqlite3_bind_blob(st, 3, h160, 20, SQLITE_STATIC); else sqlite3_bind_null(st, 3);
        sqlite3_step(st); sqlite3_finalize(st);
    }
    sqlite3_close(db);
}
/* the one op a fresh origin store holds for `name` (its blob, as gossip carries it) */
static int origin_op(const char *store, uint8_t *out) {
    sqlite3 *db; sqlite3_open_v2(store, &db, SQLITE_OPEN_READONLY, NULL); sqlite3_stmt *q; int n = -1;
    sqlite3_prepare_v2(db, "SELECT blob FROM st_rows ORDER BY anchor DESC LIMIT 1", -1, &q, 0);
    if (sqlite3_step(q) == SQLITE_ROW) { n = sqlite3_column_bytes(q, 0); memcpy(out, sqlite3_column_blob(q, 0), (size_t)n); }
    sqlite3_finalize(q); sqlite3_close(db); return n;
}

/* one scenario: alice owns `zone`, the receiver holds her record; transfer to
 * bob at E; bob publishes on a node at tip E; the op reaches the receiver at
 * tip E + lag. Returns the receiver's admit rc (err filled). */
static int scenario(uint32_t E, uint32_t lag, char *err, int *alice_rc) {
    Key A = mk("a81dns-alice"), B = mk("a81dns-bob");
    const char *pc = "/tmp/a81dns_pub_chain.db", *rc_ = "/tmp/a81dns_rcv_chain.db";
    const char *ps_a = "/tmp/a81dns_alice_store.db", *ps_b = "/tmp/a81dns_bob_store.db", *rs = "/tmp/a81dns_rcv_store.db";
    unlink(ps_a); unlink(ps_b); unlink(rs);
    chain_make(pc, E - 60, E - 1); chain_make(rc_, E - 60, E - 1);
    chain_owner(pc, "zone", A.h160, E - 50, 1); chain_owner(rc_, "zone", A.h160, E - 50, 1);
    zone_rec rec; char e2[128];
    zone_build_rec("www", "A", 300, "192.0.2.1", &rec);
    DnsChain *cp = dns_chain_open(pc), *cr = dns_chain_open(rc_);
    SpChainOracle op_ = dns_chain_oracle(cp), orc = dns_chain_oracle(cr);
    SpState *sa = sp_state_open(ps_a), *sr = sp_state_open(rs);
    dns_state_put(sa, &op_, "zone", &rec, A.priv, A.pub, SP_CERT_NONE, NULL, 0, e2, sizeof e2);
    uint8_t blob[SP_STATE_OP_MAX]; sp_state_close(sa);
    int n = origin_op(ps_a, blob);
    sp_state_admit(sr, &orc, DNS_BUDGET, DNS_SCOPE, blob, n, e2, sizeof e2);        /* receiver holds alice's row */
    /* transfer at E (both chain views), the receiver then moves on `lag` blocks */
    chain_owner(pc, "zone", B.h160, E, 1); chain_tip(pc, E);
    chain_owner(rc_, "zone", B.h160, E, 1); chain_tip(rc_, E + lag);
    SpState *sb = sp_state_open(ps_b);
    zone_build_rec("www", "A", 300, "192.0.2.2", &rec);
    int pr = dns_state_put(sb, &op_, "zone", &rec, B.priv, B.pub, SP_CERT_NONE, NULL, 0, e2, sizeof e2);
    sp_state_close(sb);
    n = origin_op(ps_b, blob);
    int r = pr == 1 && n > 0 ? sp_state_admit(sr, &orc, DNS_BUDGET, DNS_SCOPE, blob, n, err, 128) : -9;
    if (alice_rc) {          /* the previous owner signs a fresh op against the receiver's view */
        zone_build_rec("evil", "A", 300, "203.0.113.66", &rec);
        *alice_rc = dns_state_put(sr, &orc, "zone", &rec, A.priv, A.pub, SP_CERT_NONE, NULL, 0, e2, sizeof e2);
    }
    sp_state_close(sr); dns_chain_close(cp); dns_chain_close(cr);
    unlink(ps_a); unlink(ps_b); unlink(rs); unlink(pc); unlink(rc_);
    return r;
}

int main(void) {
    char err[128], m[256];
    const uint32_t F = DNS_A81_FROM;
    printf("-- shipping DNS_A81_FROM = %u --\n", F);
    if (F == 0) { printf("ok   rule disabled at build time; nothing to check\n"); return 0; }
    int arc = 0;
    for (uint32_t lag = 0; lag <= 3; lag++) {
        int r = scenario(F, lag, err, lag == 3 ? &arc : NULL);
        snprintf(m, sizeof m, "transfer AT activation (E=%u), op arrives %u block(s) late -> admitted (%d %s)", F, lag, r, r == 1 ? "" : err);
        CK(r == 1, m);
    }
    snprintf(m, sizeof m, "previous owner's fresh op after the transfer -> rejected (%d)", arc);
    CK(arc == 0, m);
    {
        int r = scenario(F - 1, 0, err, NULL);
        snprintf(m, sizeof m, "transfer one block BELOW activation (E=%u), on time -> admitted (%d)", F - 1, r);
        CK(r == 1, m);
        r = scenario(F - 1, 1, err, NULL);
        snprintf(m, sizeof m, "transfer one block BELOW activation, 1 block late -> legacy reject (%d %s)", r, err);
        CK(r == 0 && !strcmp(err, "anchor below floor"), m);
    }
    /* oc_epoch guards */
    {
        Key A = mk("g-a"), B = mk("g-b");
        const char *p = "/tmp/a81dns_guard.db";
        chain_make(p, F - 20, F + 5);
        chain_owner(p, "zone", A.h160, F - 10, 1);
        chain_owner(p, "zone", B.h160, F + 1, 0);                 /* names moved, epochs row not yet */
        DnsChain *c = dns_chain_open(p); SpChainOracle o = dns_chain_oracle(c);
        CK(o.epoch_start && o.epoch_floor_from == F, "dns_chain_oracle fills epoch_start + DNS_A81_FROM");
        CK(o.epoch_start(o.u, "zone") == -1, "epochs row lags names (owner mismatch) -> -1 (legacy floor)");
        CK(sp_state_epoch_floor(&o, "zone") == F + 5 - SP_STATE_REORG, "... and the pin uses tip - REORG");
        dns_chain_close(c);
        chain_owner(p, "zone", B.h160, F + 1, 1);
        c = dns_chain_open(p); o = dns_chain_oracle(c);
        CK(o.epoch_start(o.u, "zone") == (int64_t)F + 1, "epochs row matches owner_now -> its start height");
        CK(sp_state_epoch_floor(&o, "zone") == F + 1 - SP_STATE_REORG - 1, "... floor = E - REORG - 1");
        CK(o.epoch_start(o.u, "nobody") == -1, "unknown name -> -1");
        dns_chain_close(c);
        sqlite3 *db; sqlite3_open(p, &db);
        char q[160]; snprintf(q, sizeof q, "INSERT INTO epochs VALUES('zone',%u,NULL,0)", F + 3); ex(db, q); sqlite3_close(db);
        c = dns_chain_open(p); o = dns_chain_oracle(c);
        CK(o.epoch_start(o.u, "zone") == -1, "latest epochs row is a lapse (owner NULL) while names says owned -> -1");
        dns_chain_close(c);
        unlink(p);
    }
    printf("a81_dns_test: %d ok, %d failed\n", oks, fails);
    return fails != 0;
}
