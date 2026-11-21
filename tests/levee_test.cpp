/* leveed as a Puddle and its friends meet it (the protocol's spec/06): joining with a link, a friend's request spooled while
 * the Puddle is away and handed over when it comes, one passed through while it is there, sending out, files left for a
 * friend, and leaving. */

#include "harness.h"

using levee::base64;
using levee::parse_object;
using levee::sha256_hex;
using levee::unbase64_any;

static std::string query_value(const std::string &link, const std::string &key)
{
    size_t at = link.find(key + "=");
    if (at == std::string::npos)
        return "";
    at += key.size() + 1;
    size_t end = link.find_first_of("&\n", at);
    return link.substr(at, end == std::string::npos ? std::string::npos : end - at);
}

/* the Puddle's own request to its Levee: signed in X-Levee-Signature, sealed to the Levee when `seal_to` is given */
struct Sent {
    Reply r;
    unsigned char answer_key[32] = {};
    std::string nonce;
};

static Sent puddle_call(unsigned port, const Ident &me, const std::string &levee_id, const unsigned char *seal_to, const std::string &method,
                        const std::string &target, const std::string &body, std::vector<std::string> headers = {})
{
    Sent s;
    if (seal_to) {
        pp_sealed_request sr;
        if (pp_seal_request(&me.signer, method.c_str(), target.c_str(), body.data(), body.size(), levee_id.c_str(), seal_to, 0, &sr) != 0)
            return s;
        headers.push_back(std::string("X-Levee-Signature: ") + sr.signature);
        headers.push_back(std::string("X-Puddle-Seal: ") + sr.seal);
        headers.push_back("Content-Type: application/puddle-sealed");
        memcpy(s.answer_key, sr.answer_key, 32);
        s.nonce = sr.nonce;
        std::string sealed(sr.body ? (const char *)sr.body : "", sr.body_len);
        pp_sealed_request_free(&sr);
        s.r = https(port, method, target, sealed, headers);
    } else {
        headers.push_back("X-Levee-Signature: " + me.signature(method, target, body, levee_id));
        s.r = https(port, method, target, body, headers);
    }
    return s;
}

int main()
{
    LeveeProc lv;
    std::string init = lv.ctl("init");
    CHECK(init.find("Levee ") == 0);
    std::string link = lv.ctl("join");
    CHECK(link.rfind("levee://127.0.0.1:", 0) == 0);
    std::string levee_id = query_value(link, "id"), token = query_value(link, "token"), k = query_value(link, "k");
    unsigned char seal_pk[32];
    CHECK(pp_id_valid(levee_id.c_str()) && token.size() == 26 && levee::unbase32(k, seal_pk, 32));
    link = lv.ctl("join"); /* nobody joined yet: another link replaces the first */
    token = query_value(link, "token");
    CHECK(lv.start());

    Ident puddle(1), friend_(2), stranger(3), other(4);

    /* ---- joining ---- */
    auto attach_body = [](const Ident &who, const std::string &tok) {
        Json::Value v;
        v["chain"] = who.chain;
        if (!tok.empty())
            v["token"] = tok;
        return levee::to_json(v);
    };
    Sent a = puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/attach", attach_body(puddle, "wrongtokenaaaaaaaaaaaaaaaa"));
    CHECK(a.r.status == 404);
    a = puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/attach", attach_body(puddle, ""));
    CHECK(a.r.status == 404); /* not joined yet, and no token */
    a = puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/attach", attach_body(puddle, token));
    CHECK(a.r.status == 200);
    std::string plain(a.r.body.size(), '\0');
    size_t pl = 0;
    CHECK(pp_open_answer(a.answer_key, 200, (const unsigned char *)a.r.body.data(), a.r.body.size(), (unsigned char *)plain.data(), &pl) == 0);
    plain.resize(pl);
    Json::Value joined;
    CHECK(parse_object(plain, joined));
    unsigned char levee_pub[32] = {};
    CHECK(joined["levee"]["id"].asString() == levee_id && levee::unbase64(joined["levee"]["key"].asString(), levee_pub, 32));
    char derived[PP_ID_LEN + 1];
    pp_key_id_b32(PP_LABEL_LEVEE, levee_pub, derived);
    CHECK(levee_id == derived);
    CHECK(joined["address"].asString() == "127.0.0.1:" + std::to_string(lv.port));
    CHECK(joined["turn"]["port"].asUInt() == lv.turn_port && joined["turn"]["username"].asString().size() == 26);
    CHECK(pp_receipt_verify(a.r.h("x-puddle-receipt").c_str(), levee_id.c_str(), levee_pub, a.nonce.c_str(), 200,
                            sha256_hex(a.r.body).c_str()) == PP_RECEIPT_OK);
    /* the token is spent; the Puddle comes back without one; nobody else can */
    a = puddle_call(lv.port, other, levee_id, seal_pk, "POST", "/levee/v1/attach", attach_body(other, token));
    CHECK(a.r.status == 404);
    a = puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/attach", attach_body(puddle, ""));
    CHECK(a.r.status == 200);
    CHECK(lv.ctl("join").find("is joined") != std::string::npos);

    /* ---- a friend's request before the Puddle has said who its friends are: not let through ---- */
    std::string events = "{\"chat\":\"x\",\"events\":[]}";
    auto friend_post = [&](const Ident &who, const std::string &target, const std::string &body) {
        return https(lv.port, "POST", target, body, { "X-Puddle-Signature: " + who.signature("POST", target, body, puddle.id) });
    };
    CHECK(friend_post(friend_, "/stream/v1/events", events).status == 404);

    /* ---- peers, sealed ---- */
    Json::Value peers;
    peers["peers"][0]["id"] = friend_.id;
    peers["peers"][0]["chain"] = friend_.chain;
    peers["devices"] = Json::arrayValue;
    CHECK(puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/peers", levee::to_json(peers)).r.status == 204);
    CHECK(puddle_call(lv.port, other, levee_id, seal_pk, "POST", "/levee/v1/peers", levee::to_json(peers)).r.status == 404);

    /* ---- the Puddle is away: a one-way request is spooled, with a custody receipt; the rest is 404 ---- */
    std::string target = "/stream/v1/events", sig = friend_.signature("POST", target, events, puddle.id);
    Reply sp = https(lv.port, "POST", target, events, { "X-Puddle-Signature: " + sig, "Content-Type: application/json" });
    CHECK(sp.status == 202);
    pp_reqsig parsed;
    CHECK(pp_reqsig_parse(sig.c_str(), &parsed) == 0);
    CHECK(pp_custody_verify(sp.h("x-puddle-custody").c_str(), puddle.id.c_str(), levee_id.c_str(), levee_pub, parsed.nonce,
                            sha256_hex(events).c_str()) == PP_RECEIPT_OK);
    CHECK(https(lv.port, "POST", target, events, { "X-Puddle-Signature: " + sig }).status == 404); /* the same request again */
    CHECK(friend_post(stranger, "/stream/v1/events", events).status == 404);
    Reply get = https(lv.port, "GET", "/stream/v1/media?x=1", "",
                      { "X-Puddle-Signature: " + friend_.signature("GET", "/stream/v1/media?x=1", "", puddle.id) });
    CHECK(get.status == 404);
    /* a first contact goes through (rate-limited) even from a stranger: spooled too, though the stranger can't trust the custody */
    std::string acc = "{\"sealed\":\"for the Puddle\"}";
    Reply first = https(lv.port, "POST", "/stream/v1/access", acc,
                        { "X-Puddle-Signature: " + stranger.signature("POST", "/stream/v1/access", acc, "*") });
    CHECK(first.status == 202);

    /* ---- the Puddle comes: what waited is handed over, and taken ---- */
    Sent in = puddle_call(lv.port, puddle, levee_id, nullptr, "GET", "/levee/v1/inbox?after=0", "");
    CHECK(in.r.status == 200);
    Json::Value inbox;
    CHECK(parse_object(in.r.body, inbox) && inbox["items"].size() == 2);
    const Json::Value &it0 = inbox["items"][0];
    std::string body0;
    CHECK(!it0["live"].asBool() && it0["method"].asString() == "POST" && it0["target"].asString() == target &&
          it0["headers"]["X-Puddle-Signature"].asString() == sig && unbase64_any(it0["body"].asString(), body0) && body0 == events);
    CHECK(it0["headers"]["Content-Type"].asString() == "application/json");
    uint64_t last = inbox["items"][1]["n"].asUInt64();
    CHECK(puddle_call(lv.port, other, levee_id, nullptr, "GET", "/levee/v1/inbox?after=0", "").r.status == 404);

    /* ---- the Puddle is there: a request passes through and the answer comes back as it was ---- */
    std::thread puddle_side([&] {
        Sent poll = puddle_call(lv.port, puddle, levee_id, nullptr, "GET", "/levee/v1/inbox?after=" + std::to_string(last), "");
        Json::Value v;
        if (poll.r.status != 200 || !parse_object(poll.r.body, v) || v["items"].size() != 1 || !v["items"][0]["live"].asBool())
            return;
        uint64_t n = v["items"][0]["n"].asUInt64();
        last = n;
        puddle_call(lv.port, puddle, levee_id, nullptr, "POST", "/levee/v1/answer/" + std::to_string(n), "{\"taken\":1}",
                    { "X-Levee-Status: 201", "X-Puddle-Receipt: v2 id=x; kid=y; sig=z", "Content-Type: application/puddle-sealed" });
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    Reply live = friend_post(friend_, "/stream/v1/events", events);
    puddle_side.join();
    CHECK(live.status == 201 && live.body == "{\"taken\":1}" && live.h("x-puddle-receipt") == "v2 id=x; kid=y; sig=z");
    CHECK(live.h("content-type") == "application/puddle-sealed");

    /* ---- going out ---- */
    Sent out = puddle_call(lv.port, puddle, levee_id, nullptr, "POST", "/levee/v1/send", "",
                           { "X-Levee-To: 127.0.0.1:" + std::to_string(lv.port), "X-Levee-Method: GET", "X-Levee-Target: /nothing/here",
                             "X-Levee-Timeout: 5" });
    CHECK(out.r.status == 200 && out.r.h("x-levee-status") == "404" && out.r.body == "{\"error\":\"not_found\"}");
    out = puddle_call(lv.port, puddle, levee_id, nullptr, "POST", "/levee/v1/send", "",
                      { "X-Levee-To: 127.0.0.1:" + std::to_string(free_port()), "X-Levee-Method: GET", "X-Levee-Target: /x", "X-Levee-Timeout: 3" });
    CHECK(out.r.status == 200 && out.r.h("x-levee-status") == "0" && !out.r.h("x-levee-error").empty());
    out = puddle_call(lv.port, puddle, levee_id, nullptr, "POST", "/levee/v1/send", "",
                      { "X-Levee-To: 224.0.0.1:443", "X-Levee-Method: GET", "X-Levee-Target: /x" });
    CHECK(out.r.status == 400);
    CHECK(puddle_call(lv.port, other, levee_id, nullptr, "POST", "/levee/v1/send", "",
                      { "X-Levee-To: 127.0.0.1:1", "X-Levee-Method: GET", "X-Levee-Target: /x" })
              .r.status == 404);

    /* ---- a file left for a friend ---- */
    std::string file = sha256_hex("the file's id"), hashes = "sealed hashes", chunk(70000, 'c');
    CHECK(puddle_call(lv.port, puddle, levee_id, nullptr, "POST", "/levee/v1/files/" + file + "/hashes", hashes).r.status == 204);
    CHECK(puddle_call(lv.port, puddle, levee_id, nullptr, "POST", "/levee/v1/files/" + file + "/0", chunk).r.status == 204);
    std::string piece_target = "/levee/v1/files/" + file + "/0";
    auto fetch = [&](const Ident &who, const std::string &t) {
        return https(lv.port, "GET", t, "", { "X-Puddle-Signature: " + who.signature("GET", t, "", puddle.id) });
    };
    CHECK(fetch(friend_, piece_target).status == 404); /* not ready */
    Json::Value ready;
    ready["for"][0] = friend_.id;
    CHECK(puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/files/" + file + "/ready", levee::to_json(ready)).r.status == 204);
    Reply got = fetch(friend_, piece_target);
    CHECK(got.status == 200 && got.body == chunk);
    CHECK(fetch(friend_, "/levee/v1/files/" + file + "/hashes").body == hashes);
    CHECK(fetch(stranger, piece_target).status == 404);
    CHECK(fetch(friend_, "/levee/v1/files/" + file + "/7").status == 404);
    std::string done_t = "/levee/v1/files/" + file + "/done";
    CHECK(https(lv.port, "POST", done_t, "", { "X-Puddle-Signature: " + friend_.signature("POST", done_t, "", puddle.id) }).status == 204);
    CHECK(fetch(friend_, piece_target).status == 404); /* gone once everyone it was for has it */
    in = puddle_call(lv.port, puddle, levee_id, nullptr, "GET", "/levee/v1/inbox?after=" + std::to_string(last), "");
    CHECK(parse_object(in.r.body, inbox) && inbox["items"].size() == 1 && inbox["items"][0]["file_done"]["file"].asString() == file &&
          inbox["items"][0]["file_done"]["by"].asString() == friend_.id);

    /* ---- leaving ---- */
    CHECK(puddle_call(lv.port, other, levee_id, nullptr, "POST", "/levee/v1/detach", "").r.status == 404);
    CHECK(puddle_call(lv.port, puddle, levee_id, nullptr, "POST", "/levee/v1/detach", "").r.status == 204);
    CHECK(friend_post(friend_, "/stream/v1/events", events).status == 404);
    CHECK(lv.ctl("status").find("none joined") != std::string::npos);

    /* ---- a restart keeps the join ---- */
    link = lv.ctl("join");
    token = query_value(link, "token");
    a = puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/attach", attach_body(puddle, token));
    CHECK(a.r.status == 200);
    lv.stop();
    CHECK(lv.start());
    a = puddle_call(lv.port, puddle, levee_id, seal_pk, "POST", "/levee/v1/attach", attach_body(puddle, ""));
    CHECK(a.r.status == 200);

    return finish("levee_test");
}
