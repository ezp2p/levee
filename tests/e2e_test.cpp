/* Two real Puddles (puddled, a separate program: PUDDLED in CMakeLists.txt), Alice behind a real Levee, over TLS on this machine:
 * Alice joins with the link leveectl makes; her address becomes the Levee's; Bob asks for a stream at it; they talk, Alice's
 * side going out through the Levee; Alice stops, and what Bob sends meanwhile is taken by the Levee (Bob counts it delivered)
 * and reaches Alice when she comes back; Alice leaves the Levee. Skipped (77) without a puddled. */

#include "harness.h"

#include <fstream>
#include <sys/stat.h>

using levee::parse_object;

struct Node {
    std::string name, dir, conf, token;
    unsigned port = 0;
    pid_t pid = 0;

    bool make(const std::string &root, const char *who)
    {
        name = who;
        dir = root + "/" + who;
        conf = dir + "/puddle.yaml";
        mkdir(dir.c_str(), 0700);
        std::ofstream(dir + "/profiles.yaml") << "profiles:\n  - id: main\n    display_name: " << who << "\n";
        port = free_port();
        std::ofstream(conf) << "address: 127.0.0.1\nport: " << port << "\ndata_dir: " << dir << "/data\nprofiles: " << dir << "/profiles.yaml\n" << (getenv("LEVEE_LOG") ? "log: debug\n" : "");
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
    CHECK(alice.make(root, "alice") && bob.make(root, "bob"));
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
