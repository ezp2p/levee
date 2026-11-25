#pragma once

/* The relay for calls (the protocol's spec/06, "Calls: the relay"): a TURN server (RFC 8656) over UDP, for the Levee's own
 * Puddle only. Nothing can reach a Puddle behind a Levee by UDP, so the Puddle asks here for a relayed address (an
 * allocation), offers only that in its calls, and its media goes through: the other side sends to the relayed address, and
 * the Levee passes it on to the Puddle over the Puddle's own flow to `port`, and back.
 *
 * What it does: Binding (so a client learns its reflexive address), Allocate (UDP only), Refresh, CreatePermission,
 * ChannelBind, Send and Data indications, and ChannelData. Long-term credentials (RFC 8489, MD5 and HMAC-SHA1), realm the
 * Levee's id, with the one username and password the Puddle was given when it joined. One relayed port per allocation,
 * from `relay_from`..`relay_to`, so a reverse proxy isn't involved: those ports and `port` are published directly. IPv4.
 *
 * The media is DTLS-SRTP end to end; the relay sees sizes and timing. Its own thread. */

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace levee {

struct TurnSettings {
    std::string bind;          /* "" = every address */
    unsigned port = 3478;
    unsigned relay_from = 49160, relay_to = 49199;
    std::string public_ip;     /* what XOR-RELAYED-ADDRESS names (IPv4) */
    std::string realm;         /* the Levee's id */
};

class Turn {
public:
    explicit Turn(const TurnSettings &s);
    ~Turn();

    /* false with the reason in `err` if the port can't be bound */
    bool start(std::string &err);
    void stop();

    /* the only credentials it takes; "" for none (no Puddle joined): every allocation is refused, and those made are dropped */
    void set_credentials(const std::string &user, const std::string &pass);

    unsigned port() const { return port_; }
    /* allocations now, for tests and the log */
    size_t allocations() const { return allocs_.load(); }

    struct Impl;

private:
    void run();
    TurnSettings s_;
    unsigned port_ = 0;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> allocs_{0};
    std::mutex mu_;
    std::string user_, pass_;
    bool creds_changed_ = false;
    Impl *impl_ = nullptr;
};

} // namespace levee
