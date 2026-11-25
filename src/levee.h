#pragma once

/* The Levee itself (the protocol's spec/06): one Puddle's public side.
 *
 * Everything that comes to the Levee's address is either the Puddle's own business with its Levee (`/levee/v1/...`, signed by
 * the Puddle in X-Levee-Signature) or for the Puddle:
 *
 * - checked first, as the Puddle would, up to the signature: from someone the Puddle told us about (peers), or a first
 *   contact on a route that proves itself with a chain in the body, rate-limited. Anything else is a plain 404.
 * - while the Puddle is attached (it held a request on `inbox` in the last 30 seconds): handed over at once, and the caller
 *   waits up to 30 seconds for the Puddle's answer;
 * - while it is not: a one-way request is spooled and answered 202 with a custody receipt; anything else, 404.
 *
 * Outgoing (`send`) the Levee makes the Puddle's request for it and hands back the answer. Files wait here until each friend
 * has fetched them. Thread-safe: Drogon calls in from several threads; one lock guards the state. */

#include "config.h"
#include "store.h"
#include "turn.h"

#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <trantor/net/EventLoop.h>

#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace levee {

using Callback = std::function<void(const drogon::HttpResponsePtr &)>;

/* Token buckets: `burst` at once, refilled at one per `every_ms`. */
class Bucket {
public:
    Bucket(double burst, int64_t every_ms) : burst_(burst), every_ms_(every_ms), tokens_(burst) {}
    bool take(int64_t now_ms);

private:
    double burst_;
    int64_t every_ms_;
    double tokens_;
    int64_t at_ = 0;
};

class Levee {
public:
    Levee(const Config &cfg, const Key &key, Store &store, trantor::EventLoop *loop);
    ~Levee();

    void handle(const drogon::HttpRequestPtr &req, Callback &&cb);
    /* every second: waits that ran out, the spool's and the files' limits */
    void tick();
    /* answer everyone waiting, before stopping */
    void stop();

    void set_turn(Turn *t) { turn_ = t; }

    static drogon::HttpResponsePtr not_found();

    /* how long a request for the Puddle waits for its answer, and an inbox request for something to hand over (tests shorten
     * them) */
    int64_t answer_wait_ms = 8000; /* under a Puddle's 10 s wait for any reply, so a one-way request is kept before its caller gives up */
    int64_t inbox_wait_ms = 25000;
    int64_t attached_ms = 10000; /* since the Puddle's last inbox request, when none is waiting now */

private:
    struct Waiting {
        Item item;
        Callback cb;
        int64_t deadline = 0;
        bool handed = false; /* given to the Puddle on inbox already */
    };
    struct Poll {
        uint64_t after = 0;
        Callback cb;
        int64_t deadline = 0;
        drogon::HttpRequestPtr req; /* so a Puddle that went away (its connection closed) isn't counted as there */
    };

    void incoming(const drogon::HttpRequestPtr &req, Callback &&cb);
    void attach(const drogon::HttpRequestPtr &req, Callback &&cb);
    void detach(const drogon::HttpRequestPtr &req, Callback &&cb);
    void peers(const drogon::HttpRequestPtr &req, Callback &&cb);
    void inbox(const drogon::HttpRequestPtr &req, Callback &&cb);
    void inbox_body(const drogon::HttpRequestPtr &req, uint64_t n, Callback &&cb);
    void answer(const drogon::HttpRequestPtr &req, uint64_t n, Callback &&cb);
    void send(const drogon::HttpRequestPtr &req, Callback &&cb);
    void file_put(const drogon::HttpRequestPtr &req, const std::string &file, const std::string &piece, Callback &&cb);
    void file_ready(const drogon::HttpRequestPtr &req, const std::string &file, Callback &&cb);
    void file_get(const drogon::HttpRequestPtr &req, const std::string &file, const std::string &piece, Callback &&cb);
    void file_done(const drogon::HttpRequestPtr &req, const std::string &file, Callback &&cb);

    /* the Puddle's own request: X-Levee-Signature for this Levee, by the joined Puddle's current key. Fills `sig`. Locked. */
    bool from_puddle(const drogon::HttpRequestPtr &req, pp_reqsig &sig);
    /* open a body sealed to this Levee (attach, peers, ready); "" with false if it won't */
    bool open_sealed(const drogon::HttpRequestPtr &req, const pp_reqsig &sig, std::string &plain, unsigned char answer_key[32]);
    /* the items with n > after, as inbox gives them; locked */
    Json::Value items_after(uint64_t after, bool &any);
    /* hand what is new to whoever waits on inbox; locked, the callbacks to call collected in `out` */
    void wake_polls(std::vector<std::pair<Callback, drogon::HttpResponsePtr>> &out);
    bool attached_now(int64_t now) const;
    /* spool a live request nobody answered, if it is one-way: the custody receipt for its caller, or nullptr. Locked. */
    drogon::HttpResponsePtr spool_with_custody(const Item &it);
    bool puddle_key(unsigned char pub[32]) const;
    void load_puddle_key();
    /* Giving up (spec/06, "When the Levee gives up"): each sender who can be reached is owed a notice, and the Puddle is told
     * on inbox when `tell_puddle`. Locked. */
    void give_up(const std::vector<GivenUp> &what, const std::string &for_id, bool tell_puddle);
    /* send the notices that are due, one sender at a time; locked */
    void send_notices(int64_t now);
    void notice_sent(const std::string &sender, const std::string &for_id, size_t items, bool ok);

    Config cfg_;
    Key key_;
    Store &store_;
    trantor::EventLoop *loop_;
    Turn *turn_ = nullptr;

    std::mutex mu_;
    std::map<uint64_t, Waiting> live_;
    std::vector<Poll> polls_;
    std::deque<std::pair<uint64_t, std::pair<std::string, std::string>>> notices_; /* n -> (file, by) */
    int64_t last_poll_ = 0;
    int64_t last_give_up_check_ = 0;
    std::set<std::string> notifying_; /* "<sender>\n<for>": a notice on its way now */
    unsigned char puddle_pub_[32] = {};
    bool have_puddle_ = false;
    pp_replay *replay_;
    Bucket strangers_{60, 1000};                 /* first contacts, from anyone: a minute's worth at once, then one a second */
    std::map<std::string, Bucket> stranger_ips_; /* and from each address: 10 at once, then one every 6 seconds */
    bool stopping_ = false;
};

} // namespace levee
