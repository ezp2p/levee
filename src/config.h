#pragma once

/* levee.yaml: where leveed listens, the address friends reach its Puddle at, where its files are, how much it keeps, and the
 * relay for calls (README.md, "levee.yaml"). leveed and leveectl read the same file. */

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace levee {

struct TurnConfig {
    bool on = true;
    unsigned port = 3478;                       /* UDP: the relay's own port, where the Puddle asks for an allocation */
    unsigned relay_from = 49160, relay_to = 49199; /* UDP: the relayed addresses the other side of a call reaches */
    std::string public_ip;                      /* what relayed candidates name; "" = the address's host, looked up */
};

/* An address or a range of them, "127.0.0.1", "172.16.0.0/12", "::1", "fd00::/8" */
struct IpNet {
    bool v6 = false;
    unsigned char addr[16] = {};
    unsigned bits = 0;
};

struct Config {
    std::string listen = "0.0.0.0";
    unsigned port = 8443;    /* TCP: HTTPS, everything but calls */
    std::string address;     /* host[:port] others reach the Puddle at, through a reverse proxy or not: required */
    std::string data_dir;
    unsigned threads = 2;
    uint64_t spool_max_bytes = 1ull << 30;  /* what waits for the Puddle while it is away */
    double spool_keep_days = 30; /* then given up, and the sender and the Puddle told (spec/06, "When the Levee gives up") */
    int64_t spool_keep_ms() const { return (int64_t)(spool_keep_days * 24 * 3600 * 1000); }
    uint64_t file_max_bytes = 100ull << 20; /* the largest file the Puddle may leave here */
    uint64_t files_max_bytes = 4ull << 30;  /* all of them together */
    int files_keep_days = 30;
    TurnConfig turn;
    /* Reverse proxies in front: a request from one of these is taken to come from the address it names in
     * X-Forwarded-For. Empty: every request is from the address it comes from. */
    std::vector<IpNet> trusted_proxies;
};

/* Read `path`. false with the reason in `err`. Unknown keys are an error, so a typo is not silently ignored. */
bool load_config(const std::string &path, Config &out, std::string &err);

/* "1.2.3.4", "1.2.3.0/24", "::1", "fd00::/8"; false if it is none of these. */
bool parse_ipnet(std::string_view text, IpNet &out);
/* Whether the address `ip` (as text) is in `net`. */
bool ipnet_contains(const IpNet &net, std::string_view ip);

/* Where a request really comes from: `peer` (the address it came from), unless that is a trusted proxy; then, walking
 * X-Forwarded-For from the right, the first address that isn't one. Proxies append the address they had the request from,
 * so only the right-hand entries are theirs: anything further left the client wrote itself and could make up. */
std::string client_address(const std::vector<IpNet> &trusted, std::string_view peer, std::string_view forwarded_for);

/* "host:port" with the port always said (443 when the address has none). */
std::string address_with_port(const std::string &address);
/* The host part of an address, without brackets. */
std::string address_host(const std::string &address);

} // namespace levee
