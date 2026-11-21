#pragma once

/* levee.yaml: where leveed listens, the address friends reach its Puddle at, where its files are, how much it keeps, and the
 * relay for calls (README.md, "levee.yaml"). leveed and leveectl read the same file. */

#include <cstdint>
#include <string>

namespace levee {

struct TurnConfig {
    bool on = true;
    unsigned port = 3478;                       /* UDP: the relay's own port, where the Puddle asks for an allocation */
    unsigned relay_from = 49160, relay_to = 49199; /* UDP: the relayed addresses the other side of a call reaches */
    std::string public_ip;                      /* what relayed candidates name; "" = the address's host, looked up */
};

struct Config {
    std::string listen = "0.0.0.0";
    unsigned port = 8443;    /* TCP: HTTPS, everything but calls */
    std::string address;     /* host[:port] others reach the Puddle at, through a reverse proxy or not: required */
    std::string data_dir;
    unsigned threads = 2;
    uint64_t spool_max_bytes = 1ull << 30;  /* what waits for the Puddle while it is away */
    int spool_keep_days = 30;
    uint64_t file_max_bytes = 100ull << 20; /* the largest file the Puddle may leave here */
    uint64_t files_max_bytes = 4ull << 30;  /* all of them together */
    int files_keep_days = 30;
    TurnConfig turn;
};

/* Read `path`. false with the reason in `err`. Unknown keys are an error, so a typo is not silently ignored. */
bool load_config(const std::string &path, Config &out, std::string &err);

/* "host:port" with the port always said (443 when the address has none). */
std::string address_with_port(const std::string &address);
/* The host part of an address, without brackets. */
std::string address_host(const std::string &address);

} // namespace levee
