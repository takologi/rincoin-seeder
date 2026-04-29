#ifndef _DNS_H_
#define _DNS_H_ 1

#include <stdint.h>
#include <string>
#include <vector>

struct addr_t {
    int v;
    union {
       unsigned char v4[4];
       unsigned char v6[16];
    } data;
};

// A single DNS zone the seeder is authoritative for.
//
// The seeder can be configured with one or more zones; each zone has its
// own SOA mailbox (`mbox`) and one *or more* NS hostnames (`ns`). All
// zones share the same crawler database, so adding a zone is essentially
// free — it just lets a single seeder process answer queries for
// several FQDNs (e.g. `seed.rincoin.net`, `seed.rincoin.org`,
// `seed.rin.so`) on the single privileged UDP/53 socket.
//
// The first entry of `ns` is used as the SOA MNAME (per RFC 1035 the
// SOA can only name a single primary master). All entries are emitted
// as NS RRs in the answer / authority section, which is what an HA
// resolver setup expects.
struct dns_zone_t {
    std::string host;             // FQDN this seeder is authoritative for, e.g. "seed.example.com"
    std::vector<std::string> ns;  // NS hostnames returned in NS records; ns[0] also becomes SOA MNAME
    std::string mbox;             // Mailbox in SOA records, '@' replaced by '.', e.g. "admin.example.com"
};

struct dns_opt_t {
  int port;
  int datattl;
  int nsttl;
  // List of zones this server answers for. Must contain at least one
  // entry. A query is matched against every zone's `host` (case
  // insensitive, exact name or `xHHHH.<host>` filter form). The first
  // matching zone is used to build the response — its `ns` / `mbox`
  // populate the SOA and NS records.
  std::vector<dns_zone_t> zones;
  const char *addr;
  int (*cb)(void *opt, char *requested_hostname, addr_t *addr, int max, int ipv4, int ipv6);

  // Per-thread statistics. Updated only by the owning DNS thread, so
  // they don't need to be atomic; the stats reporter sums values across
  // threads when displaying / exporting them.
  uint64_t nRequests;         // Total UDP datagrams received
  uint64_t nAnswered;         // Responses containing at least one answer RR
  uint64_t nRefusedNoZone;    // Query name did not match any configured zone
  uint64_t nRefusedBadFilter; // `xHHHH.` filter prefix not in whitelist
  uint64_t nRefusedFormat;    // Malformed packet / unsupported opcode / bad question
};

int dnsserver(dns_opt_t *opt);

#endif
