#include "levee.h"

#include "util.h"

#include <drogon/HttpClient.h>
#include <trantor/utils/Logger.h>

#include <arpa/inet.h>

#include <algorithm>
#include <cstring>

using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;

namespace levee {

static constexpr size_t INLINE_BODY_MAX = 256 * 1024; /* larger bodies are fetched on their own (inbox/<n>/body) */
static constexpr size_t INBOX_MAX_ITEMS = 64;
static constexpr size_t INBOX_MAX_BYTES = 4 << 20;
static constexpr size_t SEND_MAX_ANSWER = 32 << 20;

/* LEVEE_LOG=debug: say why each request for the Puddle was refused or kept */
static bool debug_log()
{
    static const bool on = getenv("LEVEE_LOG") && !strcmp(getenv("LEVEE_LOG"), "debug");
    return on;
}

bool Bucket::take(int64_t now)
{
    if (at_ == 0)
        at_ = now;
    tokens_ = std::min(burst_, tokens_ + (double)(now - at_) / (double)every_ms_);
    at_ = now;
    if (tokens_ < 1)
        return false;
    tokens_ -= 1;
    return true;
}

HttpResponsePtr Levee::not_found()
{
    auto r = HttpResponse::newHttpResponse();
    r->setStatusCode(drogon::k404NotFound);
    r->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    r->setBody("{\"error\":\"not_found\"}");
    return r;
}

static HttpResponsePtr status_only(int status)
{
    auto r = HttpResponse::newHttpResponse();
    r->setStatusCode((drogon::HttpStatusCode)status);
    r->setContentTypeCode(drogon::CT_NONE);
    return r;
}

static HttpResponsePtr json_answer(int status, const Json::Value &v)
{
    auto r = HttpResponse::newHttpResponse();
    r->setStatusCode((drogon::HttpStatusCode)status);
    r->setContentTypeCode(drogon::CT_APPLICATION_JSON);
    r->setBody(to_json(v));
    return r;
}

/* An answer passed on as it came: status, the headers the protocol passes, and the body. */
static HttpResponsePtr passed(int status, const std::string &type, const std::string &receipt, const std::string &custody,
                              const std::string &range, std::string body, const std::string &levee_status = "")
{
    auto r = HttpResponse::newHttpResponse();
    r->setStatusCode((drogon::HttpStatusCode)status);
    if (!type.empty())
        r->setContentTypeString(type);
    else
        r->setContentTypeCode(drogon::CT_NONE);
    if (!receipt.empty())
        r->addHeader("X-Puddle-Receipt", receipt);
    if (!custody.empty())
        r->addHeader("X-Puddle-Custody", custody);
    if (!range.empty())
        r->addHeader("Content-Range", range);
    if (!levee_status.empty())
        r->addHeader("X-Levee-Status", levee_status);
    r->setBody(std::move(body));
    return r;
}

static std::string target_of(const HttpRequestPtr &req)
{
    std::string t = req->path();
    if (!req->query().empty())
        t += "?" + req->query();
    return t;
}

static std::string method_of(const HttpRequestPtr &req)
{
    return req->method() == drogon::Get ? "GET" : req->method() == drogon::Post ? "POST" : "";
}

/* A request that proves itself with a key chain in its body (or a phone pairing): the Levee can't open the body, so it can't
 * check these, and lets them through rate-limited (spec/06, "Coming in"). */
static bool first_contact_route(const std::string &method, const std::string &path)
{
    return method == "POST" && (path == "/stream/v1/access" || path == "/stream/v1/access/status" || path == "/stream/v1/access/result" ||
                                path == "/stream/v1/identity" || path == "/device/v1/pair");
}

/* One-way: kept while the Puddle is away (spec/06, the table) */
static bool one_way_route(const std::string &method, const std::string &path)
{
    if (method != "POST")
        return false;
    static const char *const exact[] = { "/stream/v1/address", "/stream/v1/access", "/stream/v1/access/result", "/stream/v1/close",
                                         "/stream/v1/events",  "/stream/v1/profile", "/stream/v1/group/invite",
                                         "/stream/v1/call/end", "/stream/v1/call/group/leave" };
    for (const char *e : exact)
        if (path == e)
            return true;
    const std::string pre = "/stream/v1/files/";
    if (path.compare(0, pre.size(), pre) == 0) {
        size_t slash = path.find('/', pre.size());
        if (slash != std::string::npos) {
            std::string what = path.substr(slash + 1);
            return what == "request" || what == "granted" || what == "refused" || what == "done";
        }
    }
    return false;
}

Levee::Levee(const Config &cfg, const Key &key, Store &store, trantor::EventLoop *loop)
    : cfg_(cfg), key_(key), store_(store), loop_(loop), replay_(pp_replay_new(0))
{
    load_puddle_key();
}

Levee::~Levee()
{
    pp_replay_free(replay_);
}

void Levee::load_puddle_key()
{
    have_puddle_ = false;
    const Join &j = store_.join();
    if (j.puddle.empty())
        return;
    pp_chain_head h;
    char why[200];
    if (pp_chain_verify(j.chain.data(), j.chain.size(), j.puddle.c_str(), &h, why, sizeof why) == 0) {
        memcpy(puddle_pub_, h.sign_pub, 32);
        have_puddle_ = true;
    } else {
        LOG_WARN << "the joined Puddle's key chain doesn't check (" << why << "): it can't attach until it joins again";
    }
}

bool Levee::puddle_key(unsigned char pub[32]) const
{
    if (!have_puddle_)
        return false;
    memcpy(pub, puddle_pub_, 32);
    return true;
}

bool Levee::attached_now(int64_t now) const
{
    for (const Poll &p : polls_)
        if (p.req && p.req->connected())
            return true;
    return last_poll_ && now - last_poll_ < attached_ms;
}

HttpResponsePtr Levee::spool_with_custody(const Item &in)
{
    std::string path = in.target.substr(0, in.target.find('?'));
    const Join &j = store_.join();
    if (j.puddle.empty() || !one_way_route(in.method, path) || store_.spooled_nonce(in.sender, in.nonce) ||
        store_.spool_bytes() + in.body.size() + 4096 > cfg_.spool_max_bytes)
        return nullptr;
    Item it = in;
    it.live = false;
    pp_signer s;
    pp_signer_from_seed(&s, key_.id.c_str(), key_.seed);
    char custody[PP_CUSTODY_MAX];
    if (pp_custody_sign(&s, j.puddle.c_str(), it.nonce.c_str(), sha256_hex(it.body).c_str(), custody, sizeof custody) != 0 || !store_.spool(it))
        return nullptr;
    auto r = status_only(202);
    r->addHeader("X-Puddle-Custody", custody);
    return r;
}

void Levee::handle(const HttpRequestPtr &req, Callback &&cb)
{
    const std::string &path = req->path();
    static const std::string pre = "/levee/v1/";
    if (path.compare(0, pre.size(), pre) != 0)
        return incoming(req, std::move(cb));
    std::string rest = path.substr(pre.size());
    std::string m = method_of(req);
    std::vector<std::string> seg;
    for (size_t at = 0; at <= rest.size();) {
        size_t s = rest.find('/', at);
        seg.push_back(rest.substr(at, s == std::string::npos ? std::string::npos : s - at));
        if (s == std::string::npos)
            break;
        at = s + 1;
    }
    auto num = [](const std::string &s, uint64_t &out) {
        if (s.empty() || s.size() > 18 || !std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; }))
            return false;
        out = strtoull(s.c_str(), nullptr, 10);
        return true;
    };
    uint64_t n = 0;
    if (m == "POST" && seg.size() == 1 && seg[0] == "attach")
        return attach(req, std::move(cb));
    if (m == "POST" && seg.size() == 1 && seg[0] == "detach")
        return detach(req, std::move(cb));
    if (m == "POST" && seg.size() == 1 && seg[0] == "peers")
        return peers(req, std::move(cb));
    if (m == "GET" && seg.size() == 1 && seg[0] == "inbox")
        return inbox(req, std::move(cb));
    if (m == "GET" && seg.size() == 3 && seg[0] == "inbox" && num(seg[1], n) && seg[2] == "body")
        return inbox_body(req, n, std::move(cb));
    if (m == "POST" && seg.size() == 2 && seg[0] == "answer" && num(seg[1], n))
        return answer(req, n, std::move(cb));
    if (m == "POST" && seg.size() == 1 && seg[0] == "send")
        return send(req, std::move(cb));
    if (seg.size() == 3 && seg[0] == "files") {
        if (m == "POST" && seg[2] == "ready")
            return file_ready(req, seg[1], std::move(cb));
        if (m == "POST" && seg[2] == "done")
            return file_done(req, seg[1], std::move(cb));
        if (m == "POST")
            return file_put(req, seg[1], seg[2], std::move(cb));
        if (m == "GET")
            return file_get(req, seg[1], seg[2], std::move(cb));
    }
    cb(not_found());
}

/* ---------------------------------------------------------------- coming in */

void Levee::incoming(const HttpRequestPtr &req, Callback &&cb)
{
    std::string m = method_of(req), target = target_of(req), path = req->path();
    std::string sig_header(req->getHeader("x-puddle-signature"));
    pp_reqsig sig;
    if (m.empty() || sig_header.empty() || pp_reqsig_parse(sig_header.c_str(), &sig) != 0)
        return cb(not_found());
    int64_t now = wall_ms();
    std::vector<std::pair<Callback, HttpResponsePtr>> later;
    HttpResponsePtr now_answer;
    {
        std::lock_guard<std::mutex> g(mu_);
        const Join &j = store_.join();
        if (j.puddle.empty() || stopping_)
            return cb(not_found());

        /* checked as the Puddle would, up to the signature */
        auto known = store_.peers().find(sig.id);
        bool ok = false;
        if (known != store_.peers().end()) {
            struct Look {
                const unsigned char *pub;
            } look = { known->second.data() };
            auto lookup = [](void *u, const char *, const char *, unsigned char out[32]) -> int {
                memcpy(out, ((Look *)u)->pub, 32);
                return 1;
            };
            pp_authn a = pp_reqsig_authenticate(sig_header.c_str(), m.c_str(), target.c_str(), req->body().data(), req->body().size(),
                                                j.puddle.c_str(), lookup, &look, nullptr, now, nullptr);
            ok = a == PP_AUTHN_OK || a == PP_AUTHN_SKEW; /* the Puddle says what is wrong with the clock, as it would */
            if (debug_log())
                LOG_INFO << m << " " << path << " from " << sig.id << ": " << (int)a << (attached_now(now) ? ", the Puddle is here" : ", the Puddle is away");
        }
        if (!ok && first_contact_route(m, path)) {
            std::string ip = client_address(cfg_.trusted_proxies, req->peerAddr().toIp(), req->getHeader("x-forwarded-for"));
            auto b = stranger_ips_.try_emplace(ip, 10, 6000).first;
            ok = strangers_.take(now) && b->second.take(now);
            if (stranger_ips_.size() > 4096)
                stranger_ips_.clear();
        }
        if (!ok) {
            if (debug_log()) LOG_INFO << "refused " << m << " " << path << " from " << sig.id << (known == store_.peers().end() ? " (not a peer)" : " (signature)");
            return cb(not_found());
        }

        Item it;
        it.n = store_.next_n();
        it.received = now;
        it.method = m;
        it.target = target;
        it.signature = sig_header;
        it.seal = std::string(req->getHeader("x-puddle-seal"));
        it.content_type = std::string(req->getHeader("content-type"));
        if (m == "GET")
            it.range = std::string(req->getHeader("range"));
        it.body = std::string(req->body());
        it.sender = sig.id;
        it.nonce = sig.nonce;

        if (attached_now(now)) {
            it.live = true;
            Waiting w;
            w.item = std::move(it);
            w.cb = std::move(cb);
            w.deadline = now + answer_wait_ms;
            live_.emplace(w.item.n, std::move(w));
            wake_polls(later);
        } else {
            now_answer = spool_with_custody(it);
            if (debug_log()) LOG_INFO << (now_answer ? "kept " : "the Puddle is away, refused ") << m << " " << path << " from " << sig.id;
            if (!now_answer)
                now_answer = not_found();
        }
    }
    for (auto &[c, r] : later)
        c(r);
    if (now_answer)
        cb(now_answer);
}

Json::Value Levee::items_after(uint64_t after, bool &any)
{
    Json::Value items(Json::arrayValue);
    std::vector<Json::Value> all;
    size_t bytes = 0;
    auto item_json = [&](const Item &i) {
        Json::Value v;
        v["n"] = (Json::UInt64)i.n;
        v["live"] = i.live;
        v["received"] = (Json::Int64)i.received;
        v["method"] = i.method;
        v["target"] = i.target;
        Json::Value h(Json::objectValue);
        h["X-Puddle-Signature"] = i.signature;
        if (!i.seal.empty())
            h["X-Puddle-Seal"] = i.seal;
        if (!i.content_type.empty())
            h["Content-Type"] = i.content_type;
        if (!i.range.empty())
            h["Range"] = i.range;
        v["headers"] = h;
        if (i.body.size() > INLINE_BODY_MAX) {
            v["body_size"] = (Json::UInt64)i.body.size();
        } else {
            v["body"] = base64((const unsigned char *)i.body.data(), i.body.size());
            bytes += i.body.size();
        }
        return v;
    };
    std::map<uint64_t, Json::Value> by_n;
    for (const Item &i : store_.spooled_after(after, INBOX_MAX_ITEMS, INBOX_MAX_BYTES))
        by_n[i.n] = item_json(i);
    for (auto &[n, w] : live_)
        if (n > after && !w.handed && by_n.size() < INBOX_MAX_ITEMS && bytes < INBOX_MAX_BYTES)
            by_n[n] = item_json(w.item);
    for (auto &[n, fd] : notices_)
        if (n > after) {
            Json::Value v;
            v["n"] = (Json::UInt64)n;
            v["file_done"]["file"] = fd.first;
            v["file_done"]["by"] = fd.second;
            by_n[n] = v;
        }
    for (auto &[n, v] : by_n) {
        items.append(v);
        auto w = live_.find(n);
        if (w != live_.end())
            w->second.handed = true;
    }
    any = !by_n.empty();
    return items;
}

void Levee::wake_polls(std::vector<std::pair<Callback, HttpResponsePtr>> &out)
{
    std::vector<Poll> still;
    for (Poll &p : polls_) {
        bool any = false;
        Json::Value items = items_after(p.after, any);
        if (!any) {
            still.push_back(std::move(p));
            continue;
        }
        Json::Value v;
        v["items"] = items;
        out.emplace_back(std::move(p.cb), json_answer(200, v));
        last_poll_ = wall_ms();
    }
    polls_ = std::move(still);
}

/* ---------------------------------------------------------------- the Puddle's own requests */

bool Levee::from_puddle(const HttpRequestPtr &req, pp_reqsig &sig)
{
    unsigned char pub[32];
    if (!puddle_key(pub))
        return false;
    std::string header(req->getHeader("x-levee-signature")), m = method_of(req), target = target_of(req);
    struct Look {
        const unsigned char *pub;
        const std::string *id;
    } look = { pub, &store_.join().puddle };
    auto lookup = [](void *u, const char *id, const char *, unsigned char out[32]) -> int {
        Look *l = (Look *)u;
        if (*l->id != id)
            return 0;
        memcpy(out, l->pub, 32);
        return 1;
    };
    return !header.empty() && !m.empty() &&
           pp_reqsig_authenticate(header.c_str(), m.c_str(), target.c_str(), req->body().data(), req->body().size(), key_.id.c_str(),
                                  lookup, &look, replay_, wall_ms(), &sig) == PP_AUTHN_OK;
}

bool Levee::open_sealed(const HttpRequestPtr &req, const pp_reqsig &sig, std::string &plain, unsigned char answer_key[32])
{
    std::string seal(req->getHeader("x-puddle-seal")), m = method_of(req), target = target_of(req);
    std::string_view body = req->body();
    if (seal.empty() || (!body.empty() && body.size() < PP_SEAL_TAG_LEN))
        return false;
    plain.assign(body.empty() ? 0 : body.size() - PP_SEAL_TAG_LEN, '\0');
    return pp_open_request(seal.c_str(), key_.seal_sk, sig.id, key_.id.c_str(), sig.nonce, m.c_str(), target.c_str(),
                           (const unsigned char *)body.data(), body.size(), (unsigned char *)plain.data(), answer_key) == 0;
}

void Levee::attach(const HttpRequestPtr &req, Callback &&cb)
{
    std::string header(req->getHeader("x-levee-signature"));
    pp_reqsig sig;
    std::string plain;
    unsigned char akey[32];
    if (header.empty() || pp_reqsig_parse(header.c_str(), &sig) != 0 || !open_sealed(req, sig, plain, akey))
        return cb(not_found());
    Json::Value body;
    if (!parse_object(plain, body) || !body["chain"].isString())
        return cb(not_found());
    std::string chain = body["chain"].asString(), token = body.get("token", "").asString();
    pp_chain_head h;
    char why[200];
    if (pp_chain_verify(chain.data(), chain.size(), sig.id, &h, why, sizeof why) != 0)
        return cb(not_found());
    struct Look {
        const unsigned char *pub;
    } look = { h.sign_pub };
    auto lookup = [](void *u, const char *, const char *, unsigned char out[32]) -> int {
        memcpy(out, ((Look *)u)->pub, 32);
        return 1;
    };
    std::string m = method_of(req), target = target_of(req);
    if (pp_reqsig_authenticate(header.c_str(), m.c_str(), target.c_str(), req->body().data(), req->body().size(), key_.id.c_str(), lookup,
                               &look, replay_, wall_ms(), nullptr) != PP_AUTHN_OK)
        return cb(not_found());

    Json::Value out;
    {
        std::lock_guard<std::mutex> g(mu_);
        Join &j = store_.join();
        if (!token.empty()) { /* leveectl may have made a token since: read it afresh */
            Store fresh;
            std::string err;
            if (fresh.open(store_.dir(), err)) {
                j.token = fresh.join().token;
                j.replace = fresh.join().replace;
            }
        }
        bool same = j.puddle == sig.id;
        bool by_token = !token.empty() && !j.token.empty() && token == j.token && (j.puddle.empty() || same || j.replace);
        if (!same && !by_token)
            return cb(not_found());
        if (!same) { /* a new Puddle: nothing of the old one's stays */
            LOG_INFO << "joined by the Puddle " << sig.id << (j.puddle.empty() ? "" : ", replacing " + j.puddle);
            store_.drop_spool();
            store_.drop_files();
            store_.clear_peers();
            for (auto &[n, w] : live_)
                w.cb(not_found());
            live_.clear();
            notices_.clear();
            j.turn_user.clear();
        }
        j.puddle = sig.id;
        j.chain = chain;
        if (by_token)
            j.token.clear(), j.replace = false;
        if (j.turn_user.empty())
            j.turn_user = random_token(), j.turn_pass = random_token();
        if (!store_.save_join())
            return cb(status_only(500));
        load_puddle_key();
        if (turn_)
            turn_->set_credentials(j.turn_user, j.turn_pass);
        out["levee"]["id"] = key_.id;
        out["levee"]["key"] = base64(key_.pub, 32);
        out["address"] = address_with_port(cfg_.address);
        if (cfg_.turn.on) {
            out["turn"]["port"] = cfg_.turn.port;
            out["turn"]["username"] = j.turn_user;
            out["turn"]["password"] = j.turn_pass;
        }
    }
    /* sealed back, with a receipt of the Levee's */
    std::string text = to_json(out);
    std::string sealed(pp_seal_answer_len(text.size()), '\0');
    if (pp_seal_answer(akey, 200, text.data(), text.size(), (unsigned char *)sealed.data()) != 0)
        return cb(status_only(500));
    pp_signer s;
    pp_signer_from_seed(&s, key_.id.c_str(), key_.seed);
    char receipt[PP_RECEIPT_MAX];
    if (pp_receipt_sign(&s, sig.nonce, 200, sha256_hex(sealed).c_str(), receipt, sizeof receipt) != 0)
        return cb(status_only(500));
    cb(passed(200, PP_SEALED_TYPE, receipt, "", "", std::move(sealed)));
}

void Levee::detach(const HttpRequestPtr &req, Callback &&cb)
{
    std::vector<Callback> dropped;
    {
        std::lock_guard<std::mutex> g(mu_);
        pp_reqsig sig;
        if (!from_puddle(req, sig))
            return cb(not_found());
        LOG_INFO << "the Puddle " << store_.join().puddle << " left";
        Join &j = store_.join();
        j = Join{};
        store_.save_join();
        store_.drop_spool();
        store_.drop_files();
        store_.clear_peers();
        have_puddle_ = false;
        for (auto &[n, w] : live_)
            dropped.push_back(std::move(w.cb));
        live_.clear();
        for (Poll &p : polls_)
            dropped.push_back(std::move(p.cb));
        polls_.clear();
        notices_.clear();
        last_poll_ = 0;
        if (turn_)
            turn_->set_credentials("", "");
    }
    for (auto &c : dropped)
        c(not_found());
    cb(status_only(204));
}

void Levee::peers(const HttpRequestPtr &req, Callback &&cb)
{
    std::lock_guard<std::mutex> g(mu_);
    pp_reqsig sig;
    std::string plain, err;
    unsigned char akey[32];
    if (!from_puddle(req, sig) || !open_sealed(req, sig, plain, akey))
        return cb(not_found());
    if (!store_.set_peers(plain, err))
        return cb(status_only(400));
    cb(status_only(204));
}

void Levee::inbox(const HttpRequestPtr &req, Callback &&cb)
{
    uint64_t after = 0;
    std::string a = req->getParameter("after");
    if (!a.empty()) {
        if (a.size() > 18 || !std::all_of(a.begin(), a.end(), [](char c) { return c >= '0' && c <= '9'; }))
            return cb(not_found());
        after = strtoull(a.c_str(), nullptr, 10);
    }
    std::lock_guard<std::mutex> g(mu_);
    pp_reqsig sig;
    if (!from_puddle(req, sig) || stopping_)
        return cb(not_found());
    int64_t now = wall_ms();
    last_poll_ = now;
    store_.drop_spooled_upto(after);
    while (!notices_.empty() && notices_.front().first <= after)
        notices_.pop_front();
    /* one waiting at a time: an older request is answered empty */
    for (Poll &p : polls_)
        p.cb(json_answer(200, Json::Value(Json::objectValue)));
    polls_.clear();
    bool any = false;
    Json::Value items = items_after(after, any);
    if (any) {
        Json::Value v;
        v["items"] = items;
        return cb(json_answer(200, v));
    }
    Poll p;
    p.after = after;
    p.cb = std::move(cb);
    p.deadline = now + inbox_wait_ms;
    p.req = req;
    polls_.push_back(std::move(p));
}

void Levee::inbox_body(const HttpRequestPtr &req, uint64_t n, Callback &&cb)
{
    std::lock_guard<std::mutex> g(mu_);
    pp_reqsig sig;
    if (!from_puddle(req, sig))
        return cb(not_found());
    auto w = live_.find(n);
    if (w != live_.end())
        return cb(passed(200, "application/octet-stream", "", "", "", w->second.item.body));
    for (const Item &i : store_.spooled_after(n - 1, 1, SIZE_MAX))
        if (i.n == n)
            return cb(passed(200, "application/octet-stream", "", "", "", i.body));
    cb(not_found());
}

void Levee::answer(const HttpRequestPtr &req, uint64_t n, Callback &&cb)
{
    Callback waiting;
    HttpResponsePtr out;
    {
        std::lock_guard<std::mutex> g(mu_);
        pp_reqsig sig;
        if (!from_puddle(req, sig))
            return cb(not_found());
        auto w = live_.find(n);
        if (w == live_.end())
            return cb(not_found());
        std::string st(req->getHeader("x-levee-status"));
        int status = atoi(st.c_str());
        if (status < 100 || status > 599)
            return cb(status_only(400));
        waiting = std::move(w->second.cb);
        if (debug_log())
            LOG_INFO << "the Puddle answered " << n << ": " << status;
        live_.erase(w);
        out = passed(status, std::string(req->getHeader("content-type")), std::string(req->getHeader("x-puddle-receipt")), "",
                     std::string(req->getHeader("content-range")), std::string(req->body()));
    }
    waiting(out);
    cb(status_only(204));
}

/* ---------------------------------------------------------------- going out */

/* a numeric host no one should dial (as Puddle's client refuses): unspecified, multicast, broadcast, link-local */
static bool undialable(const std::string &host)
{
    unsigned char a[16];
    if (inet_pton(AF_INET, host.c_str(), a) == 1)
        return a[0] == 0 || a[0] >= 224 || (a[0] == 169 && a[1] == 254);
    if (inet_pton(AF_INET6, host.c_str(), a) == 1) {
        static const unsigned char zero[16] = {};
        return !memcmp(a, zero, 16) || a[0] == 0xff || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80);
    }
    return host.empty();
}

void Levee::send(const HttpRequestPtr &req, Callback &&cb)
{
    {
        std::lock_guard<std::mutex> g(mu_);
        pp_reqsig sig;
        if (!from_puddle(req, sig))
            return cb(not_found());
    }
    std::string to(req->getHeader("x-levee-to")), method(req->getHeader("x-levee-method")), target(req->getHeader("x-levee-target"));
    int timeout = atoi(std::string(req->getHeader("x-levee-timeout")).c_str());
    if (timeout <= 0)
        timeout = 30;
    timeout = std::min(timeout, 60);
    std::string host = address_host(to), with_port = address_with_port(to);
    if (to.empty() || to.size() > 300 || (method != "GET" && method != "POST") || target.empty() || target[0] != '/' ||
        target.size() > 1100 || undialable(host))
        return cb(status_only(400));
    auto client = drogon::HttpClient::newHttpClient("https://" + with_port, loop_, false, false);
    auto out = drogon::HttpRequest::newHttpRequest();
    out->setMethod(method == "GET" ? drogon::Get : drogon::Post);
    out->setPathEncode(false);
    out->setPath(target);
    for (const char *h : { "X-Puddle-Signature", "X-Puddle-Seal" }) {
        std::string v(req->getHeader(h));
        if (!v.empty())
            out->addHeader(h, v);
    }
    if (method == "GET") {
        std::string r(req->getHeader("range"));
        if (!r.empty())
            out->addHeader("Range", r);
    } else {
        std::string ct(req->getHeader("content-type"));
        if (!ct.empty())
            out->setContentTypeString(ct);
        else
            out->setContentTypeCode(drogon::CT_NONE);
        out->setBody(std::string(req->body()));
    }
    client->setUserAgent("");
    client->sendRequest(
        out,
        [cb = std::move(cb), client](drogon::ReqResult r, const HttpResponsePtr &resp) {
            if (r != drogon::ReqResult::Ok || !resp) {
                auto a = status_only(200);
                a->addHeader("X-Levee-Status", "0");
                a->addHeader("X-Levee-Error", r == drogon::ReqResult::Timeout ? "timeout" : "unreachable");
                return cb(a);
            }
            if (resp->body().size() > SEND_MAX_ANSWER) {
                auto a = status_only(200);
                a->addHeader("X-Levee-Status", "0");
                a->addHeader("X-Levee-Error", "too_large");
                return cb(a);
            }
            std::string type(resp->getHeader("content-type"));
            cb(passed(200, type.empty() ? "application/octet-stream" : type, std::string(resp->getHeader("x-puddle-receipt")),
                      std::string(resp->getHeader("x-puddle-custody")), std::string(resp->getHeader("content-range")),
                      std::string(resp->body()), std::to_string((int)resp->statusCode())));
        },
        (double)timeout);
}

/* ---------------------------------------------------------------- files */

void Levee::file_put(const HttpRequestPtr &req, const std::string &file, const std::string &piece, Callback &&cb)
{
    std::lock_guard<std::mutex> g(mu_);
    pp_reqsig sig;
    if (!from_puddle(req, sig))
        return cb(not_found());
    if (!store_.put_piece(file, piece, std::string(req->body()), cfg_.file_max_bytes, cfg_.files_max_bytes))
        return cb(json_answer(409, [] {
            Json::Value v;
            v["error"] = "no_room";
            return v;
        }()));
    cb(status_only(204));
}

void Levee::file_ready(const HttpRequestPtr &req, const std::string &file, Callback &&cb)
{
    std::lock_guard<std::mutex> g(mu_);
    pp_reqsig sig;
    std::string plain;
    unsigned char akey[32];
    if (!from_puddle(req, sig) || !open_sealed(req, sig, plain, akey))
        return cb(not_found());
    Json::Value v;
    auto m = store_.file(file);
    if (!m || !parse_object(plain, v) || !v["for"].isArray())
        return cb(not_found());
    std::string hashes;
    if (!store_.read_piece(file, "hashes", hashes))
        return cb(json_answer(409, [] {
            Json::Value e;
            e["error"] = "incomplete";
            return e;
        }()));
    /* every chunk the hashes count must be here: the hashes piece is sealed, so the Levee counts the files it holds instead */
    m->for_whom.clear();
    for (const Json::Value &f : v["for"])
        if (f.isString() && pp_id_valid(f.asCString()))
            m->for_whom.insert(f.asString());
    m->ready = !m->for_whom.empty();
    m->created = wall_ms();
    if (!store_.save_file(*m))
        return cb(status_only(500));
    cb(status_only(204));
}

/* a friend's request for a file: signed for the Puddle's id, by someone the file is for */
static bool friend_of(const HttpRequestPtr &req, const std::string &puddle, const std::map<std::string, std::array<unsigned char, 32>> &peers,
                      const FileMeta &m, pp_replay *replay, pp_reqsig &sig)
{
    std::string header(req->getHeader("x-puddle-signature")), method = method_of(req), target = target_of(req);
    if (header.empty() || pp_reqsig_parse(header.c_str(), &sig) != 0 || !m.for_whom.count(sig.id))
        return false;
    auto k = peers.find(sig.id);
    if (k == peers.end())
        return false;
    struct Look {
        const unsigned char *pub;
    } look = { k->second.data() };
    auto lookup = [](void *u, const char *, const char *, unsigned char out[32]) -> int {
        memcpy(out, ((Look *)u)->pub, 32);
        return 1;
    };
    return pp_reqsig_authenticate(header.c_str(), method.c_str(), target.c_str(), req->body().data(), req->body().size(), puddle.c_str(),
                                  lookup, &look, replay, wall_ms(), nullptr) == PP_AUTHN_OK;
}

void Levee::file_get(const HttpRequestPtr &req, const std::string &file, const std::string &piece, Callback &&cb)
{
    std::lock_guard<std::mutex> g(mu_);
    auto m = store_.file(file);
    pp_reqsig sig;
    std::string data;
    if (!m || !m->ready || !friend_of(req, store_.join().puddle, store_.peers(), *m, nullptr, sig) || !store_.read_piece(file, piece, data))
        return cb(not_found());
    cb(passed(200, "application/octet-stream", "", "", "", std::move(data)));
}

void Levee::file_done(const HttpRequestPtr &req, const std::string &file, Callback &&cb)
{
    std::vector<std::pair<Callback, HttpResponsePtr>> later;
    {
        std::lock_guard<std::mutex> g(mu_);
        auto m = store_.file(file);
        pp_reqsig sig;
        if (!m || !friend_of(req, store_.join().puddle, store_.peers(), *m, replay_, sig))
            return cb(not_found());
        m->for_whom.erase(sig.id);
        if (m->for_whom.empty())
            store_.remove_file(file);
        else
            store_.save_file(*m);
        notices_.emplace_back(store_.next_n(), std::make_pair(file, std::string(sig.id)));
        wake_polls(later);
    }
    for (auto &[c, r] : later)
        c(r);
    cb(status_only(204));
}

/* ---------------------------------------------------------------- time */

void Levee::tick()
{
    std::vector<std::pair<Callback, HttpResponsePtr>> later;
    {
        std::lock_guard<std::mutex> g(mu_);
        int64_t now = wall_ms();
        for (auto it = live_.begin(); it != live_.end();) {
            if (it->second.deadline <= now) {
                /* the Puddle didn't answer (it went away meanwhile): a one-way request is kept for it, as if it had been away */
                HttpResponsePtr kept = spool_with_custody(it->second.item);
                if (debug_log())
                    LOG_INFO << "the Puddle didn't answer " << it->first << (it->second.handed ? " (handed over)" : "") << ": " << (kept ? "kept" : "refused");
                later.emplace_back(std::move(it->second.cb), kept ? kept : not_found());
                it = live_.erase(it);
            } else {
                ++it;
            }
        }
        std::vector<Poll> still;
        for (Poll &p : polls_) {
            if (p.req && !p.req->connected()) {
                later.emplace_back(std::move(p.cb), not_found());
                continue;
            }
            if (p.deadline <= now) {
                Json::Value v;
                v["items"] = Json::Value(Json::arrayValue);
                later.emplace_back(std::move(p.cb), json_answer(200, v));
                last_poll_ = now;
            } else {
                still.push_back(std::move(p));
            }
        }
        polls_ = std::move(still);
        static int64_t last_trim = 0;
        if (now - last_trim > 60 * 1000) {
            last_trim = now;
            store_.trim_spool(cfg_.spool_max_bytes, now - (int64_t)cfg_.spool_keep_days * 24 * 3600 * 1000);
            for (const FileMeta &f : store_.files())
                if (f.created && now - f.created > (int64_t)cfg_.files_keep_days * 24 * 3600 * 1000)
                    store_.remove_file(f.id);
        }
    }
    for (auto &[c, r] : later)
        c(r);
}

void Levee::stop()
{
    std::vector<Callback> all;
    {
        std::lock_guard<std::mutex> g(mu_);
        stopping_ = true;
        for (auto &[n, w] : live_)
            all.push_back(std::move(w.cb));
        live_.clear();
        for (Poll &p : polls_)
            all.push_back(std::move(p.cb));
        polls_.clear();
    }
    for (auto &c : all)
        c(not_found());
}

} // namespace levee
