#include <algorithm>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <atomic>

#include "rincoin.h"
#include "db.h"

using namespace std;

bool fTestNet = false;

class CDnsSeedOpts {
public:
  int nThreads;
  int nPort;
  int nP2Port;
  int nMinimumHeight;
  // Activation height of the customized halving on the network being
  // crawled. -1 means "use the per-network default" (mainnet 840000,
  // testnet 4200, regtest 600 — picked at parse time once we know
  // whether --testnet was passed). 0 disables the cutoff entirely.
  // Anything > 0 is taken as an explicit override from
  // --customizedhalvingheight. See db.h::IsCustomizedHalvingEnforced().
  int nCustomizedHalvingHeightOpt;
  int nDnsThreads;
  int fUseTestNet;
  int fWipeBan;
  int fWipeIgnore;
  // Multi-zone configuration. The seeder can be authoritative for several
  // FQDNs at once (e.g. seed.rincoin.net, seed.rincoin.org, seed.rin.so)
  // through the single privileged UDP/53 socket. The three vectors below
  // are kept index-aligned: zoneHosts[i] is served with zoneNs[i] / zoneMbox[i].
  // Populated from the -h / -n / -m options (each may be repeated).
  // zoneNs[i] is itself a comma-separated list of NS hostnames so that a
  // single zone can advertise multiple nameservers (HA). The first entry
  // becomes the SOA MNAME; all entries are emitted as NS RRs.
  std::vector<std::string> zoneHosts;
  std::vector<std::vector<std::string>> zoneNs;
  std::vector<std::string> zoneMbox;
  const char *tor;
  const char *ip_addr;
  const char *ipv4_proxy;
  const char *ipv6_proxy;
  const char *magic;
  std::vector<string> vSeeds;
  std::set<uint64_t> filter_whitelist;

  CDnsSeedOpts() : nThreads(96), nDnsThreads(4), ip_addr("::"), nPort(53), nP2Port(0), nMinimumHeight(0), nCustomizedHalvingHeightOpt(-1), tor(NULL), fUseTestNet(false), fWipeBan(false), fWipeIgnore(false), ipv4_proxy(NULL), ipv6_proxy(NULL), magic(NULL) {}

  void ParseCommandLine(int argc, char **argv) {
    static const char *help = "Rincoin community seeder\n"
                              "Usage: %s -h <host> -n <ns> -m <mbox> [-h <host2> -n <ns2> -m <mbox2> ...] [-t <threads>] [-p <port>]\n"
                              "\n"
                              "Options:\n"
                              "-s <seed>       Seed node to collect peers from (replaces default; may repeat)\n"
                              "-h <host>       Hostname of the DNS seed (FQDN). Repeat -h together with -n / -m\n"
                              "                to serve more than one zone from a single process. The N-th -h\n"
                              "                pairs with the N-th -n and the N-th -m, so the order matters.\n"
                              "-n <ns>         Hostname of the nameserver returned in NS / SOA records.\n"
                              "                Must be supplied once per -h. Pass a comma-separated list\n"
                              "                (e.g. ns1.example.com,ns2.example.com) to advertise more\n"
                              "                than one NS record for the same zone (HA setups). The\n"
                              "                first entry is used as the SOA MNAME.\n"
                              "-m <mbox>       E-Mail address reported in SOA records (replace '@' with '.').\n"
                              "                Must be supplied once per -h.\n"
                              "-t <threads>    Number of crawlers to run in parallel (default 96)\n"
                              "-d <threads>    Number of DNS server threads (default 4)\n"
                              "-a <address>    Address to listen on (default ::)\n"
                              "-p <port>       UDP port to listen on (default 53)\n"
                              "-o <ip:port>    Tor proxy IP/Port\n"
                              "-i <ip:port>    IPV4 SOCKS5 proxy IP/Port\n"
                              "-k <ip:port>    IPV6 SOCKS5 proxy IP/Port\n"
                              "-w f1,f2,...    Allow these flag combinations as filters\n"
                              "--p2port <port> P2P port to connect to\n"
                              "--magic <hex>   Magic string/network prefix\n"
                              "--minheight <n> Minimum height of block chain\n"
                              "--customizedhalvingheight <n>\n"
                              "                Activation height of Rincoin's customized halving on the\n"
                              "                network being crawled. Once the seeder has observed any\n"
                              "                peer reporting a tip at or beyond this height, peers still\n"
                              "                announcing protocol < 70018 will be marked not-good and\n"
                              "                stop appearing in DNS answers (mirrors Rincoin Core's\n"
                              "                MIN_CUSTOMIZED_HALVING_PEER_PROTO_VERSION enforcement).\n"
                              "                Defaults: mainnet 840000, testnet 4200, regtest 600.\n"
                              "                Pass 0 to disable the cutoff entirely.\n"
                              "--testnet       Use testnet\n"
                              "--wipeban       Wipe list of banned nodes\n"
                              "--wipeignore    Wipe list of ignored nodes\n"
                              "-?, --help      Show this text\n"
                              "\n"
                              "Multi-zone example:\n"
                              "  %s -h seed.rincoin.net -n ns.example.com -m admin.example.com \\\n"
                              "     -h seed.rincoin.org -n ns.example.com -m admin.example.com \\\n"
                              "     -h seed.rin.so      -n ns.example.com -m admin.example.com\n"
                              "\n";
    bool showHelp = false;

    while(1) {
      static struct option long_options[] = {
        {"seed", required_argument, 0, 's'},
        {"host", required_argument, 0, 'h'},
        {"ns",   required_argument, 0, 'n'},
        {"mbox", required_argument, 0, 'm'},
        {"threads", required_argument, 0, 't'},
        {"dnsthreads", required_argument, 0, 'd'},
        {"address", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"onion", required_argument, 0, 'o'},
        {"proxyipv4", required_argument, 0, 'i'},
        {"proxyipv6", required_argument, 0, 'k'},
        {"filter", required_argument, 0, 'w'},
        {"p2port", required_argument, 0, 'b'},
        {"magic", required_argument, 0, 'q'},
        {"minheight", required_argument, 0, 'x'},
        // Long-only options use values >= 256 so they never collide with
        // the short-option char range used by getopt_long().
        {"customizedhalvingheight", required_argument, 0, 256},
        {"testnet", no_argument, &fUseTestNet, 1},
        {"wipeban", no_argument, &fWipeBan, 1},
        {"wipeignore", no_argument, &fWipeBan, 1},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
      };
      int option_index = 0;
      int c = getopt_long(argc, argv, "s:h:n:m:t:a:p:d:o:i:k:w:b:q:x:", long_options, &option_index);
      if (c == -1) break;
      switch (c) {
        case 's': {
          vSeeds.emplace_back(optarg);
          break;
        }

        case 'h': {
          // Append a new zone host. The matching -n / -m must follow
          // (any order, but each -h needs its own -n and -m for
          // validation to pass below).
          zoneHosts.emplace_back(optarg);
          break;
        }

        case 'm': {
          zoneMbox.emplace_back(optarg);
          break;
        }

        case 'n': {
          // Split comma-separated list. Empty fragments and whitespace
          // are skipped so that trailing commas / accidental spaces
          // don't produce bogus NS entries.
          std::vector<std::string> nslist;
          const char *p = optarg;
          while (*p) {
            while (*p == ' ' || *p == '\t' || *p == ',') p++;
            const char *start = p;
            while (*p && *p != ',') p++;
            const char *end = p;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
            if (end > start) nslist.emplace_back(start, end - start);
          }
          zoneNs.emplace_back(std::move(nslist));
          break;
        }
        
        case 't': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n < 1000) nThreads = n;
          break;
        }

        case 'd': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n < 1000) nDnsThreads = n;
          break;
        }

        case 'a': {
          if (strchr(optarg, ':')==NULL) {
            char* ip4_addr = (char*) malloc(strlen(optarg)+8);
            strcpy(ip4_addr, "::FFFF:");
            strcat(ip4_addr, optarg);
            ip_addr = ip4_addr;
          } else {
            ip_addr = optarg;
          }
          break;
        }

        case 'p': {
          int p = strtol(optarg, NULL, 10);
          if (p > 0 && p < 65536) nPort = p;
          break;
        }

        case 'o': {
          tor = optarg;
          break;
        }

        case 'i': {
          ipv4_proxy = optarg;
          break;
        }

        case 'k': {
          ipv6_proxy = optarg;
          break;
        }

        case 'w': {
          char* ptr = optarg;
          while (*ptr != 0) {
            unsigned long l = strtoul(ptr, &ptr, 0);
            if (*ptr == ',') {
                ptr++;
            } else if (*ptr != 0) {
                break;
            }
            filter_whitelist.insert(l);
          }
          break;
        }

        case 'b': {
          int p = strtol(optarg, NULL, 10);
          if (p > 0 && p < 65536) nP2Port = p;
          break;
        }

        case 'q': {
          long int n;
          unsigned int c;
          if (strlen(optarg)!=8) {
            break; /* must be 4 hex-encoded bytes */
          }
          n = strtol(optarg, NULL, 16);
          if (n==0 && strcmp(optarg, "00000000")) {
            break; /* hex decode failed */
          }
          magic = optarg;
          break;
        }

        case 'x': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n <= 0x7fffffff) nMinimumHeight = n;
          break;
        }

        case 256: {
          // --customizedhalvingheight. Accept 0 (explicitly disable) and
          // any positive int up to INT_MAX. Negative values are silently
          // ignored (treated as "keep the default").
          char *end = NULL;
          long n = strtol(optarg, &end, 10);
          if (end != optarg && n >= 0 && n <= 0x7fffffff) {
            nCustomizedHalvingHeightOpt = (int)n;
          }
          break;
        }

        case '?': {
          showHelp = true;
          break;
        }
      }
    }
    if (filter_whitelist.empty()) {
        filter_whitelist.insert(NODE_NETWORK); // x1
        filter_whitelist.insert(NODE_NETWORK | NODE_BLOOM); // x5
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS); // x9
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_COMPACT_FILTERS); // x49
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2); // x809
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2 | NODE_COMPACT_FILTERS); //x849
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_BLOOM); // xd
        filter_whitelist.insert(NODE_NETWORK_LIMITED); // x400
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_BLOOM); // x404
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS); // x408
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_COMPACT_FILTERS); // x448
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_P2P_V2); // xc08
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_P2P_V2 | NODE_COMPACT_FILTERS); // xc48
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_BLOOM); // x40c
        // MWEB variants — mirror every WITNESS combo above with NODE_MWEB added
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_MWEB);                                        // x1000009
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_MWEB | NODE_BLOOM);                            // x100000d
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_MWEB | NODE_COMPACT_FILTERS);                  // x1000049
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_MWEB | NODE_P2P_V2);                           // x1000809
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_MWEB | NODE_P2P_V2 | NODE_COMPACT_FILTERS);    // x1000849
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_MWEB);                                  // x1000408
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_MWEB | NODE_BLOOM);                     // x100040c
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_MWEB | NODE_COMPACT_FILTERS);           // x1000448
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_MWEB | NODE_P2P_V2);                    // x1000c08
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_MWEB | NODE_P2P_V2 | NODE_COMPACT_FILTERS); // x1000c48
    }
    // Multi-zone validation: -h, -n, -m must each be supplied the same
    // number of times. The N-th -h is paired with the N-th -n / -m. If
    // any -h is given without a matching -n / -m (or vice versa) we
    // print help and let main() bail out below when it notices the
    // empty zone vector.
    if (zoneHosts.size() != zoneNs.size() || zoneHosts.size() != zoneMbox.size()) {
      fprintf(stderr, "Error: each -h must be matched by exactly one -n and one -m "
                      "(got %zu host(s), %zu ns, %zu mbox).\n",
              zoneHosts.size(), zoneNs.size(), zoneMbox.size());
      showHelp = true;
    }
    // Each -n value, after comma-splitting, must yield at least one
    // non-empty NS hostname. Catches typos like `-n ,` or `-n ""`
    // before they reach the DNS thread.
    for (size_t i = 0; i < zoneNs.size(); ++i) {
      if (zoneNs[i].empty()) {
        fprintf(stderr, "Error: -n for zone #%zu (%s) yielded no NS hostnames.\n",
                i, i < zoneHosts.size() ? zoneHosts[i].c_str() : "?");
        showHelp = true;
      }
    }
    if (showHelp) fprintf(stderr, help, argv[0], argv[0]);
  }
};

#include "dns.h"

CAddrDb db;

extern "C" void* ThreadCrawler(void* data) {
  int *nThreads=(int*)data;
  do {
    std::vector<CServiceResult> ips;
    int wait = 5;
    db.GetMany(ips, 16, wait);
    int64 now = time(NULL);
    if (ips.empty()) {
      wait *= 1000;
      wait += rand() % (500 * *nThreads);
      Sleep(wait);
      continue;
    }
    vector<CAddress> addr;
    for (int i=0; i<ips.size(); i++) {
      CServiceResult &res = ips[i];
      res.nBanTime = 0;
      res.nClientV = 0;
      res.nHeight = 0;
      res.strClientV = "";
      res.services = 0;
      bool getaddr = res.ourLastSuccess + 86400 < now;
      res.fGood = TestNode(res.service,res.nBanTime,res.nClientV,res.strClientV,res.nHeight,getaddr ? &addr : NULL, res.services);
    }
    db.ResultMany(ips);
    db.Add(addr);
  } while(1);
  return nullptr;
}

extern "C" int GetIPList(void *thread, char *requestedHostname, addr_t *addr, int max, int ipv4, int ipv6);

class CDnsThread {
public:
  struct FlagSpecificData {
      int nIPv4, nIPv6;
      std::vector<addr_t> cache;
      time_t cacheTime;
      unsigned int cacheHits;
      FlagSpecificData() : nIPv4(0), nIPv6(0), cacheTime(0), cacheHits(0) {}
  };

  dns_opt_t dns_opt; // must be first
  const int id;
  std::map<uint64_t, FlagSpecificData> perflag;
  std::atomic<uint64_t> dbQueries;
  std::set<uint64_t> filterWhitelist;

  void cacheHit(uint64_t requestedFlags, bool force = false) {
    static bool nets[NET_MAX] = {};
    if (!nets[NET_IPV4]) {
        nets[NET_IPV4] = true;
        nets[NET_IPV6] = true;
    }
    time_t now = time(NULL);
    FlagSpecificData& thisflag = perflag[requestedFlags];
    thisflag.cacheHits++;
    if (force || thisflag.cacheHits * 400 > (thisflag.cache.size()*thisflag.cache.size()) || (thisflag.cacheHits*thisflag.cacheHits * 20 > thisflag.cache.size() && (now - thisflag.cacheTime > 5))) {
      set<CNetAddr> ips;
      db.GetIPs(ips, requestedFlags, 1000, nets);
      dbQueries++;
      thisflag.cache.clear();
      thisflag.nIPv4 = 0;
      thisflag.nIPv6 = 0;
      thisflag.cache.reserve(ips.size());
      for (set<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
        struct in_addr addr;
        struct in6_addr addr6;
        if ((*it).GetInAddr(&addr)) {
          addr_t a;
          a.v = 4;
          memcpy(&a.data.v4, &addr, 4);
          thisflag.cache.push_back(a);
          thisflag.nIPv4++;
        } else if ((*it).GetIn6Addr(&addr6)) {
          addr_t a;
          a.v = 6;
          memcpy(&a.data.v6, &addr6, 16);
          thisflag.cache.push_back(a);
          thisflag.nIPv6++;
        }
      }
      thisflag.cacheHits = 0;
      thisflag.cacheTime = now;
    }
  }

  CDnsThread(CDnsSeedOpts* opts, int idIn) : id(idIn) {
    // Build per-thread dns_opt_t. The zones vector is shared
    // structurally (same content) between every DNS thread; each thread
    // keeps its own copy so its statistics counters can be updated
    // without locking.
    dns_opt.zones.clear();
    dns_opt.zones.reserve(opts->zoneHosts.size());
    for (size_t i = 0; i < opts->zoneHosts.size(); ++i) {
      dns_zone_t z;
      z.host = opts->zoneHosts[i];
      z.ns   = opts->zoneNs[i];
      z.mbox = opts->zoneMbox[i];
      dns_opt.zones.push_back(z);
    }
    dns_opt.datattl = 3600;
    dns_opt.nsttl = 40000;
    dns_opt.cb = GetIPList;
    dns_opt.addr = opts->ip_addr;
    dns_opt.port = opts->nPort;
    dns_opt.nRequests = 0;
    dns_opt.nAnswered = 0;
    dns_opt.nRefusedNoZone = 0;
    dns_opt.nRefusedBadFilter = 0;
    dns_opt.nRefusedFormat = 0;
    dbQueries = 0;
    perflag.clear();
    filterWhitelist = opts->filter_whitelist;
  }

  void run() {
    // dnsserver() runs forever in the normal case. Any return value
    // means the thread is giving up, which historically went silent and
    // looked indistinguishable from a healthy seeder. Make it loud so
    // systemd / journald show the cause (typically a failed bind on
    // privileged port 53 \u2014 see dns.cpp for the underlying message).
    int rv = dnsserver(&dns_opt);
    fprintf(stderr, "ERROR: DNS thread #%d exiting (dnsserver returned %d) \u2014"
                    " no further DNS responses from this thread on port %d\n",
            id, rv, dns_opt.port);
    fflush(stderr);
  }
};

extern "C" int GetIPList(void *data, char *requestedHostname, addr_t* addr, int max, int ipv4, int ipv6) {
  CDnsThread *thread = (CDnsThread*)data;

  // Two accepted query name forms:
  //   1) "<zone>"            — return random IPs from the global cache
  //   2) "xHHHH.<zone>"      — return random IPs whose service flags
  //                             equal the hex bitmask HHHH (must be
  //                             whitelisted via -w / built-in defaults)
  // In both cases <zone> must be one of the configured -h hosts. The
  // suffix match is case insensitive. dnshandle() in dns.cpp has
  // already verified the suffix matches *some* configured zone, but
  // GetIPList re-validates because it also has to extract the prefix.
  uint64_t requestedFlags = 0;
  int hostlen = strlen(requestedHostname);
  const char *suffix = requestedHostname; // pointer to "<zone>" portion
  if (hostlen > 1 && requestedHostname[0] == 'x' && requestedHostname[1] != '0') {
    char *pEnd;
    uint64_t flags = (uint64_t)strtoull(requestedHostname+1, &pEnd, 16);
    if (*pEnd == '.' && pEnd <= requestedHostname+17 &&
        std::find(thread->filterWhitelist.begin(), thread->filterWhitelist.end(), flags) != thread->filterWhitelist.end()) {
      requestedFlags = flags;
      suffix = pEnd + 1;
    } else {
      // Either the hex parse failed, the prefix overflowed 16 hex
      // digits, or the requested service-flag combination is not in
      // the whitelist. Bump the dedicated counter so monitoring can
      // distinguish "scanner probing arbitrary flag combos" from
      // "client asked for a zone we don't serve".
      thread->dns_opt.nRefusedBadFilter++;
      return 0;
    }
  }
  // Validate the suffix against every configured zone.
  bool matched = false;
  for (size_t z = 0; z < thread->dns_opt.zones.size(); ++z) {
    if (strcasecmp(suffix, thread->dns_opt.zones[z].host.c_str()) == 0) {
      matched = true;
      break;
    }
  }
  if (!matched) return 0;

  thread->cacheHit(requestedFlags);
  auto& thisflag = thread->perflag[requestedFlags];
  unsigned int size = thisflag.cache.size();
  unsigned int maxmax = (ipv4 ? thisflag.nIPv4 : 0) + (ipv6 ? thisflag.nIPv6 : 0);
  if (max > size)
    max = size;
  if (max > maxmax)
    max = maxmax;
  int i=0;
  while (i<max) {
    int j = i + (rand() % (size - i));
    do {
        bool ok = (ipv4 && thisflag.cache[j].v == 4) ||
                  (ipv6 && thisflag.cache[j].v == 6);
        if (ok) break;
        j++;
        if (j==size)
            j=i;
    } while(1);
    addr[i] = thisflag.cache[j];
    thisflag.cache[j] = thisflag.cache[i];
    thisflag.cache[i] = addr[i];
    i++;
  }
  return max;
}

vector<CDnsThread*> dnsThread;

extern "C" void* ThreadDNS(void* arg) {
  CDnsThread *thread = (CDnsThread*)arg;
  thread->run();
  return nullptr;
}

int StatCompare(const CAddrReport& a, const CAddrReport& b) {
  if (a.uptime[4] == b.uptime[4]) {
    if (a.uptime[3] == b.uptime[3]) {
      return a.clientVersion > b.clientVersion;
    } else {
      return a.uptime[3] > b.uptime[3];
    }
  } else {
    return a.uptime[4] > b.uptime[4];
  }
}

extern "C" void* ThreadDumper(void*) {
  int count = 0;
  do {
    Sleep(100000 << count); // First 100s, than 200s, 400s, 800s, 1600s, and then 3200s forever
    if (count < 5)
        count++;
    {
      vector<CAddrReport> v = db.GetAll();
      sort(v.begin(), v.end(), StatCompare);
      FILE *f = fopen("dnsseed.dat.new","w+");
      if (f) {
        {
          CAutoFile cf(f);
          cf << db;
        }
        rename("dnsseed.dat.new", "dnsseed.dat");
      }
      FILE *d = fopen("dnsseed.dump", "w");
      fprintf(d, "# address                                        good  lastSuccess    %%(2h)   %%(8h)   %%(1d)   %%(7d)  %%(30d)  blocks      svcs  version\n");
      double stat[5]={0,0,0,0,0};
      for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++) {
        CAddrReport rep = *it;
        fprintf(d, "%-47s  %4d  %11" PRId64 "  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%  %6i  %08" PRIx64 "  %5i \"%s\"\n", rep.ip.ToString().c_str(), (int)rep.fGood, rep.lastSuccess, 100.0*rep.uptime[0], 100.0*rep.uptime[1], 100.0*rep.uptime[2], 100.0*rep.uptime[3], 100.0*rep.uptime[4], rep.blocks, rep.services, rep.clientVersion, rep.clientSubVersion.c_str());
        stat[0] += rep.uptime[0];
        stat[1] += rep.uptime[1];
        stat[2] += rep.uptime[2];
        stat[3] += rep.uptime[3];
        stat[4] += rep.uptime[4];
      }
      fclose(d);
      FILE *ff = fopen("dnsstats.log", "a");
      fprintf(ff, "%llu %g %g %g %g %g\n", (unsigned long long)(time(NULL)), stat[0], stat[1], stat[2], stat[3], stat[4]);
      fclose(ff);
    }
  } while(1);
  return nullptr;
}

extern "C" void* ThreadStats(void*) {
  bool first = true;
  do {
    char c[256];
    time_t tim = time(NULL);
    struct tm *tmp = localtime(&tim);
    strftime(c, 256, "[%y-%m-%d %H:%M:%S]", tmp);
    CAddrDbStats stats;
    db.GetStats(stats);
    if (first)
    {
      first = false;
      printf("\n\n\n\x1b[3A");
    }
    else
      printf("\x1b[2K\x1b[u");
    printf("\x1b[s");
    uint64_t requests = 0;
    uint64_t answered = 0;
    uint64_t refusedNoZone = 0;
    uint64_t refusedBadFilter = 0;
    uint64_t refusedFormat = 0;
    uint64_t queries = 0;
    for (unsigned int i=0; i<dnsThread.size(); i++) {
      requests         += dnsThread[i]->dns_opt.nRequests;
      answered         += dnsThread[i]->dns_opt.nAnswered;
      refusedNoZone    += dnsThread[i]->dns_opt.nRefusedNoZone;
      refusedBadFilter += dnsThread[i]->dns_opt.nRefusedBadFilter;
      refusedFormat    += dnsThread[i]->dns_opt.nRefusedFormat;
      queries          += dnsThread[i]->dbQueries;
    }
    printf("%s %i/%i available (%i tried in %is, %i new, %i active), %i banned; "
           "DNS req=%llu ans=%llu refusedZone=%llu refusedFilter=%llu refusedFormat=%llu db=%llu",
           c, stats.nGood, stats.nAvail, stats.nTracked, stats.nAge, stats.nNew,
           stats.nAvail - stats.nTracked - stats.nNew, stats.nBanned,
           (unsigned long long)requests,
           (unsigned long long)answered,
           (unsigned long long)refusedNoZone,
           (unsigned long long)refusedBadFilter,
           (unsigned long long)refusedFormat,
           (unsigned long long)queries);
    Sleep(1000);
  } while(1);
  return nullptr;
}

static const string mainnet_seeds[] = {"seed.rin.so", ""};
static const string testnet_seeds[] = {""};
static const string *seeds = mainnet_seeds;
static vector<string> vSeeds;

extern "C" void* ThreadSeeder(void*) {
  vector<string> vDnsSeeds;
  for (const string& seed: vSeeds) {
    size_t len = seed.size();
    if (len > 6 && !seed.compare(len - 6, 6, ".onion")) {
      db.Add(CService(seed.c_str(), GetDefaultPort()), true);
    } else {
      vDnsSeeds.push_back(seed);
    }
  }
  do {
    for (const string& seed: vDnsSeeds) {
      vector<CNetAddr> ips;
      LookupHost(seed.c_str(), ips);
      for (vector<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
        db.Add(CService(*it, GetDefaultPort()), true);
      }
    }
    Sleep(1800000);
  } while(1);
  return nullptr;
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  setbuf(stdout, NULL);
  CDnsSeedOpts opts;
  opts.ParseCommandLine(argc, argv);
  printf("Supporting whitelisted filters: ");
  for (std::set<uint64_t>::const_iterator it = opts.filter_whitelist.begin(); it != opts.filter_whitelist.end(); it++) {
      if (it != opts.filter_whitelist.begin()) {
          printf(",");
      }
      printf("0x%lx", (unsigned long)*it);
  }
  printf("\n");
  if (opts.tor) {
    CService service(opts.tor, 9050);
    if (service.IsValid()) {
      printf("Using Tor proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_TOR, service);
    }
  }
  if (opts.ipv4_proxy) {
    CService service(opts.ipv4_proxy, 9050);
    if (service.IsValid()) {
      printf("Using IPv4 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV4, service);
    }
  }
  if (opts.ipv6_proxy) {
    CService service(opts.ipv6_proxy, 9050);
    if (service.IsValid()) {
      printf("Using IPv6 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV6, service);
    }
  }
  bool fDNS = true;
  if (opts.fUseTestNet) {
      printf("Using testnet.\n");
      pchMessageStart[0] = 0x0b;
      pchMessageStart[1] = 0x11;
      pchMessageStart[2] = 0x09;
      pchMessageStart[3] = 0x07;
      seeds = testnet_seeds;
      fTestNet = true;
  }
  if (opts.nP2Port) {
    printf("Using P2P port %i\n", opts.nP2Port);
    nDefaultP2Port = opts.nP2Port;
  }
  if (opts.magic) {
    printf("Using magic %s\n", opts.magic);
    for (int n=0; n<4; ++n) {
      unsigned int c = 0;
      sscanf(&opts.magic[n*2], "%2x", &c);
      pchMessageStart[n] = (unsigned char) (c & 0xff);
    }
  }
  if (opts.nMinimumHeight) {
    printf("Using minimum height %i\n", opts.nMinimumHeight);
    nMinimumHeight = opts.nMinimumHeight;
  }
  // Resolve the customized-halving cutoff once we know the network. The
  // defaults mirror Rincoin Core's `nCustomizedHalvingPhase4StartHeight`
  // (= 4 * nSubsidyHalvingInterval) from src/chainparams.cpp:
  //   mainnet: 4 * 210000 = 840000
  //   testnet: 4 *   1050 =   4200
  //   regtest: 4 *    150 =    600   (never reached by --testnet here)
  // 0 explicitly disables the cutoff. -1 (the default opt value) means
  // "use the per-network default".
  if (opts.nCustomizedHalvingHeightOpt >= 0) {
      nCustomizedHalvingHeight = opts.nCustomizedHalvingHeightOpt;
  } else {
      nCustomizedHalvingHeight = opts.fUseTestNet ? 4200 : 840000;
  }
  if (nCustomizedHalvingHeight > 0) {
    printf("Customized halving cutoff: %i (peers with proto<70018 will be"
           " demoted once any crawled peer reports a tip >= this height)\n",
           nCustomizedHalvingHeight);
  } else {
    printf("Customized halving cutoff: disabled\n");
  }
  if (!opts.vSeeds.empty()) {
    printf("Overriding DNS seeds\n");
    swap(opts.vSeeds, vSeeds);
  } else {
    for (int i=0; seeds[i][0]; i++) {
      vSeeds.emplace_back(seeds[i]);
    }
  }
  if (opts.zoneHosts.empty()) {
    // No -h given at all → run as a pure crawler with no DNS server.
    // Useful for warm-starting the database or for monitoring-only setups.
    printf("No DNS zone configured (-h). Not starting DNS server.\n");
    fDNS = false;
  }
  // The earlier ParseCommandLine() validation guarantees that
  // zoneHosts.size() == zoneNs.size() == zoneMbox.size(), so we don't
  // need to re-check the individual vectors here.
  FILE *f = fopen("dnsseed.dat","r");
  if (f) {
    printf("Loading dnsseed.dat...");
    CAutoFile cf(f);
    cf >> db;
    if (opts.fWipeBan)
        db.banned.clear();
    if (opts.fWipeIgnore)
        db.ResetIgnores();
    printf("done\n");
  }
  pthread_t threadDns, threadSeed, threadDump, threadStats;
  if (fDNS) {
    printf("Starting %i DNS threads on port %i for %zu zone(s):\n",
           opts.nDnsThreads, opts.nPort, opts.zoneHosts.size());
    for (size_t z = 0; z < opts.zoneHosts.size(); ++z) {
      // Join zoneNs[z] for the banner so operators can confirm at a
      // glance that all NS hostnames they passed via comma-list landed.
      std::string nsjoined;
      for (size_t j = 0; j < opts.zoneNs[z].size(); ++j) {
        if (j) nsjoined += ",";
        nsjoined += opts.zoneNs[z][j];
      }
      printf("  zone[%zu]: host=%s ns=%s mbox=%s\n",
             z, opts.zoneHosts[z].c_str(),
             nsjoined.c_str(), opts.zoneMbox[z].c_str());
    }
    dnsThread.clear();
    for (int i=0; i<opts.nDnsThreads; i++) {
      dnsThread.push_back(new CDnsThread(&opts, i));
      pthread_create(&threadDns, NULL, ThreadDNS, dnsThread[i]);
      printf(".");
      Sleep(20);
    }
    printf("done\n");
  }
  printf("Starting seeder...");
  pthread_create(&threadSeed, NULL, ThreadSeeder, NULL);
  printf("done\n");
  printf("Starting %i crawler threads...", opts.nThreads);
  pthread_attr_t attr_crawler;
  pthread_attr_init(&attr_crawler);
  pthread_attr_setstacksize(&attr_crawler, 0x20000);
  for (int i=0; i<opts.nThreads; i++) {
    pthread_t thread;
    pthread_create(&thread, &attr_crawler, ThreadCrawler, &opts.nThreads);
  }
  pthread_attr_destroy(&attr_crawler);
  printf("done\n");
  pthread_create(&threadStats, NULL, ThreadStats, NULL);
  pthread_create(&threadDump, NULL, ThreadDumper, NULL);
  void* res;
  pthread_join(threadDump, &res);
  return 0;
}
