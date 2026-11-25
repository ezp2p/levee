/* Two real Puddles (puddled, a separate program: PUDDLED in CMakeLists.txt), Alice behind a real Levee, over TLS on this machine:
 * Alice joins with the link leveectl makes; her address becomes the Levee's; Bob asks for a stream at it; they talk, Alice's
 * side going out through the Levee; Alice stops, and what Bob sends meanwhile is taken by the Levee (Bob counts it delivered)
 * and reaches Alice when she comes back; then the Levee gives up on one (its keep_days run out) and tells both of them, and Bob
 * sends it again once Alice is back; Alice leaves the Levee. Skipped (77) without a puddled. */

#include "harness.h"

#include <fstream>
#include <sys/stat.h>

using levee::parse_object;

struct Node {
    std::string name, dir, conf, token;
    unsigned port = 0;
    pid_t pid = 0;

    bool make(const std::string &root, const char *who, const std::string &extra = "")
    {
        name = who;
        dir = root + "/" + who;
        conf = dir + "/puddle.yaml";
        mkdir(dir.c_str(), 0700);
        std::ofstream(dir + "/profiles.yaml") << "profiles:\n  - id: main\n    display_name: " << who << "\n";
        port = free_port();
        std::ofstream(conf) << "address: 127.0.0.1\nport: " << port << "\ndata_dir: " << dir << "/data\nprofiles: " << dir << "/profiles.yaml\n" << extra << (getenv("LEVEE_LOG") ? "log: debug\n" : "");
        std::string out = run_out(std::string(PUDDLED) + " -c " + conf + " --init < /dev/null 2>&1");
        if (access((dir + "/data/identity").c_str(), F_OK) != 0) {
            fprintf(stderr, "%s: puddled --init: %s\n", who, out.c_str());
            return false;
        }
        return up();
    }
    bool up()
    {
        pid = spawn({ PUDDLED, "-c", conf }, dir + "/log");
        if (pid <= 0 || !until([&] { return port_open(port); }, 20000))
            return false;
        std::ifstream f(dir + "/data/state/owner-token");
        std::getline(f, token);
        return !token.empty();
    }
    void down()
    {
        if (pid) {
            kill(pid, SIGTERM);
            int st;
            waitpid(pid, &st, 0);
            pid = 0;
        }
    }
    ~Node() { down(); }

    Reply call(const std::string &method, const std::string &path, const std::string &body = "")
    {
        return https(port, method, path, body, { "Authorization: Bearer " + token });
    }
    /* upload `bytes` as a file the owner will send, a MiB at a time: its id, or "" */
    std::string upload(const std::string &bytes)
    {
        Json::Value v;
        Reply r = call("POST", "/api/v1/files/uploads/create", "{\"size\":" + std::to_string(bytes.size()) + "}");
        if (r.status != 201 || !parse_object(r.body, v))
            return "";
        std::string u = "/api/v1/files/uploads/" + v["upload"].asString();
        for (size_t at = 0, n = 0; at < bytes.size(); at += 1 << 20, n++)
            if (call("POST", u + "/chunks/" + std::to_string(n), bytes.substr(at, 1 << 20)).status != 200)
                return "";
        r = call("POST", u + "/finish", "");
        return r.status == 201 && parse_object(r.body, v) ? v["id"].asString() : "";
    }
    Json::Value json(const std::string &method, const std::string &path, const std::string &body = "")
    {
        Json::Value v;
        parse_object(call(method, path, body).body, v);
        return v;
    }
};

static std::string id_of(Node &n)
{
    return n.json("GET", "/api/v1/identity")["id"].asString();
}

/* the texts of a DM, oldest first */
static std::vector<std::string> texts(Node &n, const std::string &with)
{
    std::vector<std::string> out;
    Json::Value page = n.json("GET", "/api/v1/conversations/" + with + "/messages?limit=50");
    for (const Json::Value &m : page["items"])
        if (m.isMember("body"))
            out.push_back(m["body"].asString());
    return out;
}

static bool has_text(Node &n, const std::string &with, const std::string &t)
{
    for (const std::string &s : texts(n, with))
        if (s == t)
            return true;
    return false;
}

/* the owner's own message `t` is delivered: no `delivery` left on it */
static bool delivered(Node &n, const std::string &with, const std::string &t)
{
    Json::Value page = n.json("GET", "/api/v1/conversations/" + with + "/messages?limit=50");
    for (const Json::Value &m : page["items"])
        if (m.isMember("body") && m["body"].asString() == t)
            return !m.isMember("delivery");
    return false;
}

/* the delivery of the owner's own message `t`: its state ("" when delivered), and whether they are back */
static Json::Value delivery_of(Node &n, const std::string &with, const std::string &t)
{
    Json::Value page = n.json("GET", "/api/v1/conversations/" + with + "/messages?limit=50");
    for (const Json::Value &m : page["items"])
        if (m.isMember("body") && m["body"].asString() == t)
            return m.isMember("delivery") ? m["delivery"] : Json::Value(Json::objectValue);
    return Json::Value(Json::nullValue);
}

static std::string id_of_message(Node &n, const std::string &with, const std::string &t)
{
    Json::Value page = n.json("GET", "/api/v1/conversations/" + with + "/messages?limit=50");
    for (const Json::Value &m : page["items"])
        if (m.isMember("body") && m["body"].asString() == t)
            return m["id"].asString();
    return "";
}

int main()
{
    if (access(PUDDLED, X_OK) != 0) {
        fprintf(stderr, "e2e_test: skipped: no puddled at %s (build Puddle, or set -DPUDDLED=)\n", PUDDLED);
        return 77;
    }
    LeveeProc lv;
    CHECK(lv.ctl("init").rfind("Levee ", 0) == 0);
    std::string link = lv.ctl("join");
    link = link.substr(0, link.find('\n'));
    CHECK(link.rfind("levee://", 0) == 0);
    CHECK(lv.start());

    char tmpl[] = "/tmp/levee-e2e-XXXXXX";
    std::string root = mkdtemp(tmpl);
    Node alice, bob;
    CHECK(alice.make(root, "alice") && bob.make(root, "bob", "files:\n  auto_download: never\n"));
    std::string a_id = id_of(alice), b_id = id_of(bob);
    CHECK(a_id.size() == 52 && b_id.size() == 52);

    /* ---- Alice joins her Levee ---- */
    Json::Value bad = alice.json("POST", "/api/v1/levee/join", "{\"link\":\"levee://nowhere\"}");
    CHECK(bad["error"].asString() == "bad_link");
    Json::Value body;
    body["link"] = link;
    Reply j = alice.call("POST", "/api/v1/levee/join", levee::to_json(body));
    CHECK(j.status == 200);
    Json::Value st;
    CHECK(parse_object(j.body, st) && st["joined"].asBool() && st["address"].asString() == "127.0.0.1:" + std::to_string(lv.port));
    CHECK(bob.call("POST", "/api/v1/levee/join", levee::to_json(body)).status == 409); /* the link is spent, and Alice is joined */
    CHECK(until([&] { return alice.json("GET", "/api/v1/levee")["attached"].asBool(); }, 15000));

    /* her link says the Levee's address */
    Json::Value inv = alice.json("POST", "/api/v1/invites/create", "{}");
    std::string a_link = inv["link"].asString();
    CHECK(a_link.find("127.0.0.1:" + std::to_string(lv.port)) != std::string::npos);
    CHECK(a_link.find(":" + std::to_string(alice.port)) == std::string::npos);

    /* ---- Bob asks for a stream at it; the invite in her link says yes ---- */
    Json::Value req;
    req["target"] = a_link;
    req["message"] = "hello through the levee";
    CHECK(bob.call("POST", "/api/v1/streams/request", levee::to_json(req)).status == 201);
    CHECK(until([&] { return alice.json("GET", "/api/v1/streams/" + b_id)["state"].asString() == "active"; }, 30000));
    CHECK(until([&] { return bob.json("GET", "/api/v1/streams/" + a_id)["state"].asString() == "active"; }, 30000));
    /* Bob reaches Alice at the Levee, never at her own port */
    CHECK(bob.json("GET", "/api/v1/streams/" + a_id)["address"].asString() == "127.0.0.1:" + std::to_string(lv.port));

    /* ---- they talk ---- */
    CHECK(bob.call("POST", "/api/v1/conversations/" + a_id + "/messages/send", "{\"body\":\"hi alice\"}").status < 300);
    CHECK(until([&] { return has_text(alice, b_id, "hi alice"); }, 30000));
    CHECK(alice.call("POST", "/api/v1/conversations/" + b_id + "/messages/send", "{\"body\":\"hi bob, from behind my levee\"}").status < 300);
    CHECK(until([&] { return has_text(bob, a_id, "hi bob, from behind my levee"); }, 30000));
    CHECK(until([&] { return delivered(alice, b_id, "hi bob, from behind my levee"); }, 30000));

    /* ---- a call: Alice's media goes through her Levee's relay, Bob's straight to it ---- */
    Reply started = alice.call("POST", "/api/v1/calls/start", "{\"user\":\"" + b_id + "\"}");
    Json::Value call;
    CHECK(started.status == 201 && parse_object(started.body, call));
    std::string call_id = call["id"].asString();
    std::string incoming;
    CHECK(until([&] {
        Json::Value calls = bob.json("GET", "/api/v1/calls");
        for (const Json::Value &c : calls["items"])
            if (c["direction"].asString() == "incoming" && c["state"].asString() == "ringing")
                incoming = c["id"].asString();
        return !incoming.empty();
    }, 30000));
    CHECK(bob.call("POST", "/api/v1/calls/" + incoming + "/accept", "{}").status < 300);
    auto active = [&](Node &n, const std::string &id) {
        Json::Value c = n.json("GET", "/api/v1/calls/" + id);
        return c["state"].asString() == "active" && c["media"].asBool();
    };
    CHECK(until([&] { return active(alice, call_id) && active(bob, incoming); }, 30000));
    if (!active(alice, call_id))
        fprintf(stderr, "alice's call: %s\n", alice.call("GET", "/api/v1/calls/" + call_id).body.c_str());
    CHECK(alice.call("POST", "/api/v1/calls/" + call_id + "/end", "{}").status < 300);
    CHECK(until([&] { return bob.json("GET", "/api/v1/calls/" + incoming)["state"].asString() == "ended"; }, 20000));

    /* ---- Alice is away: the Levee takes what Bob sends, and Bob counts it delivered ---- */
    /* Bob knows which Levee answers for her (it came with her answer to his request) */
    CHECK(run_out("grep -rl levee_id " + bob.dir + "/data/state/streams").find(a_id) != std::string::npos);
    alice.down();
    CHECK(bob.call("POST", "/api/v1/conversations/" + a_id + "/messages/send", "{\"body\":\"while you were out\"}").status < 300);
    CHECK(until([&] { return delivered(bob, a_id, "while you were out"); }, 40000));
    CHECK(lv.ctl("status").find("waiting for the Puddle: 0 ") == std::string::npos);
    /* ---- she comes back, and it is handed over ---- */
    CHECK(alice.up());
    CHECK(until([&] { return has_text(alice, b_id, "while you were out"); }, 40000));

    /* ---- a file: left at her Levee, sealed under its own key, and fetched from there while she is away ---- */
    std::string bytes;
    for (int i = 0; i < (5 << 19); i++)
        bytes.push_back((char)(i * 131 + (i >> 9)));
    std::string file = alice.upload(bytes);
    CHECK(file.size() == 64);
    Json::Value msg;
    msg["body"] = "a file for you";
    msg["files"][0]["id"] = file;
    msg["files"][0]["name"] = "pattern.bin";
    msg["files"][0]["mime"] = "application/octet-stream";
    CHECK(alice.call("POST", "/api/v1/conversations/" + b_id + "/messages/send", levee::to_json(msg)).status < 300);
    CHECK(until([&] { return has_text(bob, a_id, "a file for you"); }, 30000));
    CHECK(until([&] { return lv.ctl("status").find("files waiting for friends: 1") != std::string::npos; }, 30000));
    std::string message_id;
    {
        Json::Value page = bob.json("GET", "/api/v1/conversations/" + a_id + "/messages?limit=50");
        for (const Json::Value &m : page["items"])
            if (m.isMember("body") && m["body"].asString() == "a file for you")
                message_id = m["id"].asString();
    }
    alice.down();
    CHECK(bob.call("POST", "/api/v1/conversations/" + a_id + "/messages/" + message_id + "/files/" + file + "/download", "{}").status == 200);
    CHECK(until([&] { return bob.json("GET", "/api/v1/files/" + file)["state"].asString() == "available"; }, 40000));
    Reply content = bob.call("GET", "/api/v1/files/" + file + "/content");
    CHECK(content.status == 200 && content.body == bytes);
    /* fetched whole by everyone it was for: gone from the Levee */
    CHECK(until([&] { return lv.ctl("status").find("files waiting for friends: 0") != std::string::npos; }, 20000));
    CHECK(alice.up());

    /* ---- the Levee gives up on what Bob sent while she was away, and says so to both (spec/06, "When the Levee gives up") ---- */
    lv.stop();
    { /* keep things for 0.0002 days (17 seconds) */
        FILE *f = fopen(lv.yaml.c_str(), "a");
        fputs("spool:\n  keep_days: 0.0002\n", f);
        fclose(f);
    }
    CHECK(lv.start());
    CHECK(until([&] { return alice.json("GET", "/api/v1/levee")["attached"].asBool(); }, 60000));
    alice.down();
    const std::string lost = "this one waits too long";
    CHECK(bob.call("POST", "/api/v1/conversations/" + a_id + "/messages/send", "{\"body\":\"" + lost + "\"}").status < 300);
    CHECK(until([&] { return delivered(bob, a_id, lost); }, 40000)); /* the custody receipt: delivered, for now */
    /* the Levee gives up on it, and tells Bob: not delivered, and not tried again by itself */
    CHECK(until([&] { return delivery_of(bob, a_id, lost)["state"].asString() == "undelivered"; }, 60000));
    Json::Value d = delivery_of(bob, a_id, lost);
    CHECK(!d["back"].asBool());
    std::string lost_id = id_of_message(bob, a_id, lost);
    CHECK(lost_id.size() == 64);
    CHECK(bob.call("POST", "/api/v1/conversations/" + a_id + "/messages/" + lost_id + "/resend", "{}").status == 409); /* not back yet */
    CHECK(lv.ctl("status").find("waiting for the Puddle: 0 ") != std::string::npos);
    /* Alice comes back and is told something from Bob expired before she did; she never sees what */
    CHECK(alice.up());
    CHECK(until([&] {
        Json::Value st = alice.json("GET", "/api/v1/levee");
        for (const Json::Value &x : st["dropped"])
            if (x["from"].asString() == b_id && x["target"].asString() == "/stream/v1/events")
                return true;
        return false;
    }, 40000));
    CHECK(!has_text(alice, b_id, lost));
    /* once Bob hears from her, it may go again: the same message, as a new request */
    CHECK(alice.call("POST", "/api/v1/conversations/" + b_id + "/messages/send", "{\"body\":\"back again\"}").status < 300);
    CHECK(until([&] { return has_text(bob, a_id, "back again"); }, 30000));
    CHECK(until([&] { return delivery_of(bob, a_id, lost)["back"].asBool(); }, 20000));
    CHECK(bob.call("POST", "/api/v1/conversations/" + a_id + "/messages/" + lost_id + "/resend", "{}").status == 200);
    CHECK(until([&] { return has_text(alice, b_id, lost); }, 30000));
    CHECK(until([&] { return delivered(bob, a_id, lost); }, 30000));
    CHECK(alice.call("POST", "/api/v1/levee/dropped/clear", "{}").status == 200);
    CHECK(alice.json("GET", "/api/v1/levee")["dropped"].size() == 0);

    /* ---- she leaves the Levee ---- */
    CHECK(alice.call("POST", "/api/v1/levee/leave", "{}").status == 204);
    CHECK(!alice.json("GET", "/api/v1/levee")["joined"].asBool());
    CHECK(lv.ctl("status").find("none joined") != std::string::npos);
    /* Bob is told where she is now, and still reaches her */
    CHECK(until([&] { return bob.json("GET", "/api/v1/streams/" + a_id)["address"].asString() == "127.0.0.1:" + std::to_string(alice.port); }, 40000));
    CHECK(bob.call("POST", "/api/v1/conversations/" + a_id + "/messages/send", "{\"body\":\"direct again\"}").status < 300);
    CHECK(until([&] { return has_text(alice, b_id, "direct again"); }, 30000));

    if (failures) {
        Reply m = bob.call("GET", "/api/v1/conversations/" + a_id + "/messages?limit=50");
        fprintf(stderr, "bob's messages: %d %s\n", m.status, m.body.substr(0, 3000).c_str());
        fprintf(stderr, "bob's stream: %s\n", bob.call("GET", "/api/v1/streams/" + a_id).body.c_str());
        fprintf(stderr, "--- alice's log ---\n%s\n--- bob's log ---\n%s\n--- leveed ---\n%s\n", run_out("tail -40 " + alice.dir + "/log").c_str(),
                run_out("tail -30 " + bob.dir + "/log").c_str(), run_out("tail -30 " + lv.dir + "/leveed.log").c_str());
    }
    alice.down();
    bob.down();
    if (!getenv("LEVEE_KEEP"))
        std::filesystem::remove_all(root);
    return finish("e2e_test");
}
