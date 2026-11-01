/* dns_chain_test.c — the lease gate runs on chain MTP, never wall clock. */
#include "dns_chain.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CK(c, m) do { if (c) printf("ok   %s\n", m); else { printf("FAIL %s\n", m); fails++; } } while (0)

static void ex(sqlite3 *db, const char *q) { char *e = 0; if (sqlite3_exec(db, q, 0, 0, &e) != SQLITE_OK) { fprintf(stderr, "%s: %s\n", q, e); exit(2); } }

int main(void) {
    char path[] = "/tmp/dns_chain_testXXXXXX"; int fd = mkstemp(path); close(fd);
    sqlite3 *db; sqlite3_open(path, &db);
    ex(db, "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);"
           "CREATE TABLE blocks(height INTEGER PRIMARY KEY, hash BLOB, time INTEGER);"
           "CREATE TABLE names(name TEXT PRIMARY KEY, owner BLOB, lease_expiry INT);");
    uint8_t own[20]; memset(own, 7, 20);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "INSERT INTO names VALUES(?,?,?)", -1, &st, 0);
    const char *nm[3] = { "past", "edge", "future" };
    /* block times 1000..1100 step 10 at heights 1..11 (not monotone at h=11) */
    long long ex_[3] = { 1040, 1050, 1061 };
    for (int i = 0; i < 3; i++) { sqlite3_bind_text(st, 1, nm[i], -1, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, own, 20, SQLITE_STATIC); sqlite3_bind_int64(st, 3, ex_[i]);
        sqlite3_step(st); sqlite3_reset(st); }
    sqlite3_finalize(st);
    /* heights 1..11, times: 1000,1010,...,1090 then 1001 at h=11 → sorted median */
    for (int h = 1; h <= 11; h++) { char q[128];
        snprintf(q, sizeof q, "INSERT INTO blocks VALUES(%d, zeroblob(32), %d)", h, h == 11 ? 1001 : 1000 + 10 * (h - 1)); ex(db, q); }
    ex(db, "INSERT INTO meta VALUES('height','11')");
    /* 12th block far in the future but ABOVE tip: must be ignored */
    ex(db, "INSERT INTO blocks VALUES(12, zeroblob(32), 99999999)");
    sqlite3_close(db);

    /* times<=tip sorted: 1000,1001,1010,...,1090 → n=11, median idx5 = 1040 */
    DnsChain *c = dns_chain_open(path); SpChainOracle o = dns_chain_oracle(c);
    uint8_t out[20];
    CK(!o.owner_now(o.u, "past", out), "lease_expiry == MTP (1040) → lapsed (owned iff MTP < expiry)");
    CK(o.owner_now(o.u, "edge", out) && !memcmp(out, own, 20), "lease_expiry 1050 > MTP 1040 → owned");
    CK(o.owner_now(o.u, "future", out), "future lease owned even though wall clock is far past 1061 (no time(NULL))");
    CK(!o.owner_now(o.u, "nobody", out), "unknown name unowned");
    dns_chain_close(c);

    /* advance tip: MTP moves with the chain, not the clock */
    sqlite3_open(path, &db);
    ex(db, "UPDATE meta SET v='12' WHERE k='height'; UPDATE blocks SET time=1100 WHERE height=12");
    sqlite3_close(db);
    /* heights 2..12: 1001,1010..1090,1100 → median = 1050 */
    c = dns_chain_open(path); o = dns_chain_oracle(c);
    CK(!o.owner_now(o.u, "edge", out), "tip 12: MTP 1050 → edge (1050) lapses");
    CK(o.owner_now(o.u, "future", out), "tip 12: future (1061) still owned");
    dns_chain_close(c);

    /* no block times at all → fail closed */
    sqlite3_open(path, &db); ex(db, "DELETE FROM blocks"); sqlite3_close(db);
    c = dns_chain_open(path); o = dns_chain_oracle(c);
    CK(!o.owner_now(o.u, "future", out), "no block times → unowned (fail closed)");
    dns_chain_close(c);
    unlink(path);
    printf("%s (%d failure%s)\n", fails ? "FAILED" : "PASS", fails, fails == 1 ? "" : "s");
    return fails != 0;
}
