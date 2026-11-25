/* leveed: the Levee service. Serves the protocol's spec/06 over HTTPS on one port, and the relay for calls on UDP, until it is
 * asked to stop (Ctrl-C or SIGTERM). Usage: leveed [-c levee.yaml] */

#include "config.h"
#include "levee.h"
#include "store.h"
#include "tls.h"
#include "turn.h"

#include <drogon/drogon.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace levee;
using namespace drogon;

/* The IPv4 address relayed candidates name: turn.public_ip, or the address's host looked up. "" if neither gives one. */
static std::string public_ipv4(const Config &cfg)
{
    if (!cfg.turn.public_ip.empty())
        return cfg.turn.public_ip;
    std::string host = address_host(cfg.address);
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
        return "";
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((sockaddr_in *)res->ai_addr)->sin_addr, ip, sizeof ip);
    freeaddrinfo(res);
    return ip;
}

int main(int argc, char **argv)
{
    std::string path = "levee.yaml";
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc) {
            path = argv[++i];
        } else {
            fprintf(stderr, "usage: leveed [-c levee.yaml]\n");
            return 2;
        }
    }
    trantor::Logger::setOutputFunction([](const char *msg, uint64_t len) { fwrite(msg, 1, len, stdout); }, [] { fflush(stdout); });
    setvbuf(stdout, nullptr, _IOLBF, 0);
    Config cfg;
    Key key;
    Store store;
    std::string err;
    if (!load_config(path, cfg, err) || !load_or_create_key(cfg.data_dir, key, err) || !ensure_certificate(cfg.data_dir, err) ||
        !store.open(cfg.data_dir, err)) {
        fprintf(stderr, "leveed: %s\n", err.c_str());
        return 1;
    }
    Levee lv(cfg, key, store, app().getLoop());

    std::unique_ptr<Turn> turn;
    if (cfg.turn.on) {
        TurnSettings ts;
        ts.bind = cfg.listen == "0.0.0.0" || cfg.listen == "::" ? "" : cfg.listen;
        ts.port = cfg.turn.port;
        ts.relay_from = cfg.turn.relay_from;
        ts.relay_to = cfg.turn.relay_to;
        ts.public_ip = public_ipv4(cfg);
        ts.realm = key.id;
        if (ts.public_ip.empty()) {
            LOG_WARN << "no relay for calls: set turn.public_ip (the address's host has no IPv4 address)";
        } else {
            turn = std::make_unique<Turn>(ts);
            if (!turn->start(err)) {
                fprintf(stderr, "leveed: %s\n", err.c_str());
                return 1;
            }
            turn->set_credentials(store.join().turn_user, store.join().turn_pass);
            lv.set_turn(turn.get());
        }
    }

    /* every request goes to the Levee, whatever its path and method, so nothing is answered differently from an unknown path */
    app().registerHandlerViaRegex(
        "/.*", [&lv](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&cb) { lv.handle(req, std::move(cb)); },
        {Get, Post, Put, Delete, Patch, Options, Head});
    app().setCustom404Page(Levee::not_found(), false);
    auto stop = [&lv, &turn] {
        LOG_INFO << "stopping";
        lv.stop();
        if (turn)
            turn->stop();
        app().getLoop()->runAfter(0.3, [] { app().quit(); });
    };
    app()
        .setLogLevel(getenv("LEVEE_LOG") && !strcmp(getenv("LEVEE_LOG"), "debug") ? trantor::Logger::kDebug : trantor::Logger::kInfo)
        .addListener(cfg.listen, (uint16_t)cfg.port, true, cfg.data_dir + "/cert.pem", cfg.data_dir + "/key.pem")
        .setThreadNum(cfg.threads)
        .enableServerHeader(false)
        .enableDateHeader(false)
        .setClientMaxBodySize(40 << 20)
        .setClientMaxMemoryBodySize(40 << 20)
        .setIdleConnectionTimeout(120)
        .setTermSignalHandler(stop)
        .setIntSignalHandler(stop);
    app().getLoop()->runEvery(1.0, [&lv] { lv.tick(); });
    app().getLoop()->queueInLoop([&] {
        LOG_INFO << "Levee " << key.id << " for " << (store.join().puddle.empty() ? std::string("no Puddle yet") : "the Puddle " + store.join().puddle)
                 << ", listening on " << cfg.listen << ":" << cfg.port << " (TCP), reached at " << address_with_port(cfg.address);
        if (turn)
            LOG_INFO << "relay for calls on UDP " << turn->port() << ", relaying from " << cfg.turn.relay_from << "-" << cfg.turn.relay_to;
    });
    app().run();
    return 0;
}
