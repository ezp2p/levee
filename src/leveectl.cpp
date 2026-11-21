/* leveectl: setting up a Levee from its own machine (README.md, "Setting up").
 *
 *   leveectl [-c levee.yaml] init              make the key and certificate; says the Levee's id
 *   leveectl [-c levee.yaml] join [--replace]  a join link for the Puddle; --replace when another is joined now
 *   leveectl [-c levee.yaml] status            who is joined, what waits */

#include "config.h"
#include "store.h"
#include "tls.h"
#include "util.h"

#include <cstdio>
#include <cstring>
#include <string>

using namespace levee;

int main(int argc, char **argv)
{
    std::string path = "levee.yaml", cmd;
    bool replace = false;
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc)
            path = argv[++i];
        else if (!strcmp(argv[i], "--replace"))
            replace = true;
        else if (cmd.empty())
            cmd = argv[i];
        else
            cmd = "?";
    }
    if (cmd != "init" && cmd != "join" && cmd != "status") {
        fprintf(stderr, "usage: leveectl [-c levee.yaml] init | join [--replace] | status\n");
        return 2;
    }
    Config cfg;
    Key key;
    Store store;
    std::string err;
    if (!load_config(path, cfg, err) || !load_or_create_key(cfg.data_dir, key, err) || !ensure_certificate(cfg.data_dir, err) ||
        !store.open(cfg.data_dir, err)) {
        fprintf(stderr, "leveectl: %s\n", err.c_str());
        return 1;
    }
    Join &j = store.join();
    if (cmd == "init") {
        printf("Levee %s, reached at %s\n", key.id.c_str(), address_with_port(cfg.address).c_str());
        return 0;
    }
    if (cmd == "status") {
        printf("Levee %s, reached at %s\n", key.id.c_str(), address_with_port(cfg.address).c_str());
        printf("Puddle: %s\n", j.puddle.empty() ? "none joined" : j.puddle.c_str());
        printf("friends and phones it knows: %zu\n", store.peers().size());
        printf("waiting for the Puddle: %zu (%.0f KB)\n", store.spooled_after(0, SIZE_MAX, SIZE_MAX).size(), (double)store.spool_bytes() / 1024);
        printf("files waiting for friends: %zu (%.1f MB)\n", store.files().size(), (double)store.files_bytes() / (1 << 20));
        printf("join link open: %s\n", j.token.empty() ? "no" : "yes");
        return 0;
    }
    /* join */
    if (!j.puddle.empty() && !replace) {
        fprintf(stderr, "leveectl: the Puddle %s is joined; `join --replace` makes a link another may join with, which replaces it\n",
                j.puddle.c_str());
        return 1;
    }
    j.token = random_token();
    j.replace = replace;
    if (j.token.empty() || !store.save_join()) {
        fprintf(stderr, "leveectl: could not save the join link\n");
        return 1;
    }
    std::string addr = cfg.address;
    printf("levee://%s?id=%s&k=%s&token=%s\n", addr.c_str(), key.id.c_str(), base32(key.seal_pk, 32).c_str(), j.token.c_str());
    fflush(stdout);
    fprintf(stderr, "Give this to the Puddle (Settings, Levee). It is good once.\n");
    return 0;
}
