/* dns_chain.h — the SpChainOracle over the namespace-indexer sqlite db.
 *
 * Read-only, own connection (WAL-safe beside a live sync thread). Answers the
 * three questions sp_state admission asks:
 *   owner_now  — names.owner, GATED on lease_expiry (a lapsed name is unowned
 *                here even while the stale row lingers; this is what drives
 *                record eviction now that storage has no TTL)
 *   header_at  — blocks.hash at height; 0 above the sync tip (hold), -1 below
 *                the checkpoint horizon (admit on signature)
 *   tip        — the sync cursor height
 * and, for the A8-1 epoch floor (pepenet/state.h SpChainOracle):
 *   epoch_start — start height of the name's current ownership epoch (the
 *                latest epochs row, only if its owner IS owner_now's answer;
 *                -1 otherwise), active from DNS_A81_FROM
 */
#ifndef DNS_CHAIN_H
#define DNS_CHAIN_H

#include "pepenet/state.h"
#include <stdint.h>

typedef struct DnsChain DnsChain;

/* A8-1 activation (Pepecoin mainnet height): a name whose current ownership
 * epoch starts at or above it gets the epoch-start floor on transfer; below it
 * the legacy receiver-tip floor, byte-for-byte. PROPOSED value — the go/no-go
 * and the final height are nowon's. Tests override with -DDNS_A81_FROM=<h>;
 * 0 disables the rule. */
#ifndef DNS_A81_FROM
#define DNS_A81_FROM 1330000u
#endif

DnsChain     *dns_chain_open(const char *indexer_db_path);   /* NULL on failure */
void          dns_chain_close(DnsChain *c);
SpChainOracle dns_chain_oracle(DnsChain *c);
/* this node's fold height and the last peer tip persisted by the indexer
 * (0 if unknown). WAL-safe read; used by the tls fail-closed page. */
void          dns_chain_sync(DnsChain *c, int64_t *height, int64_t *peer_height);
/* start height of `name`'s current ownership epoch (indexer epochs table), -1
 * if unknown. Read-only; used for the overlay's seniority priority. */
int64_t       dns_chain_epoch_start(DnsChain *c, const char *name);

#endif /* DNS_CHAIN_H */
