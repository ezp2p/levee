/* levee.yaml (config.h): trusted_proxies, and where a request really comes from behind them. */

#include "harness.h"
#include "config.h"

#include <filesystem>

using namespace levee;

static std::vector<IpNet> nets(std::initializer_list<const char *> list)
{
    std::vector<IpNet> out;
    for (const char *t : list) {
        IpNet n;
        CHECK(parse_ipnet(t, n));
        out.push_back(n);
    }
    return out;
}

int main()
{
    IpNet n;
    CHECK(parse_ipnet("127.0.0.1", n) && !n.v6 && n.bits == 32);
    CHECK(parse_ipnet("172.16.0.0/12", n) && n.bits == 12);
    CHECK(parse_ipnet("::1", n) && n.v6 && n.bits == 128);
    CHECK(parse_ipnet("fd00::/8", n) && n.v6 && n.bits == 8);
    CHECK(!parse_ipnet("", n) && !parse_ipnet("levee.example.org", n) && !parse_ipnet("10.0.0.0/33", n) && !parse_ipnet("10.0.0.0/", n) &&
          !parse_ipnet("10.0.0.0/1x", n) && !parse_ipnet("::/129", n));

    CHECK(parse_ipnet("172.16.0.0/12", n));
    CHECK(ipnet_contains(n, "172.18.0.1") && ipnet_contains(n, "172.31.255.255") && !ipnet_contains(n, "172.32.0.1"));
    CHECK(ipnet_contains(n, "::ffff:172.18.0.1")); /* the same address, as a dual-stack socket says it */
    CHECK(!ipnet_contains(n, "fd00::1") && !ipnet_contains(n, "nonsense"));
    CHECK(parse_ipnet("0.0.0.0/0", n) && ipnet_contains(n, "203.0.113.7"));

    /* no proxies: the address the request came from, whatever it says */
    CHECK(client_address({}, "203.0.113.7", "198.51.100.1") == "203.0.113.7");
    auto t = nets({ "127.0.0.1", "172.16.0.0/12" });
    /* not from a proxy: X-Forwarded-For is the client's own say, and ignored */
    CHECK(client_address(t, "203.0.113.7", "198.51.100.1") == "203.0.113.7");
    /* from the proxy: the address it says it had the request from */
    CHECK(client_address(t, "127.0.0.1", "198.51.100.1") == "198.51.100.1");
    CHECK(client_address(t, "::ffff:127.0.0.1", "198.51.100.1") == "198.51.100.1");
    /* a client that writes its own X-Forwarded-For can't choose: the proxy's entry is the right-hand one */
    CHECK(client_address(t, "127.0.0.1", "1.1.1.1, 198.51.100.1") == "198.51.100.1");
    /* two proxies (one on the host, one in a container): walk past both */
    CHECK(client_address(t, "172.18.0.2", "198.51.100.1, 127.0.0.1") == "198.51.100.1");
    CHECK(client_address(t, "127.0.0.1", " 198.51.100.1 ,  2001:db8::5 ") == "2001:db8::5");
    /* from the proxy but it said nothing (or nonsense): the proxy, as without the setting */
    CHECK(client_address(t, "127.0.0.1", "") == "127.0.0.1");
    CHECK(client_address(t, "127.0.0.1", "unknown") == "127.0.0.1");
    CHECK(client_address(t, "127.0.0.1", "198.51.100.1, unknown") == "127.0.0.1");

    /* in levee.yaml */
    char tmpl[] = "/tmp/levee-config-XXXXXX";
    std::string dir = mkdtemp(tmpl), path = dir + "/levee.yaml", err;
    auto load = [&](const std::string &extra, Config &c) {
        FILE *f = fopen(path.c_str(), "w");
        fprintf(f, "address: levee.example.org\ndata_dir: %s/data\n%s", dir.c_str(), extra.c_str());
        fclose(f);
        c = Config();
        err.clear();
        return load_config(path, c, err);
    };
    Config c;
    CHECK(load("", c) && c.trusted_proxies.empty());
    CHECK(load("trusted_proxies: [127.0.0.1, 172.16.0.0/12, '::1']\n", c) && c.trusted_proxies.size() == 3 && c.trusted_proxies[2].v6);
    CHECK(!load("trusted_proxies: 127.0.0.1\n", c) && err.find("trusted_proxies") != std::string::npos);
    CHECK(!load("trusted_proxies: [proxy.example.org]\n", c) && err.find("proxy.example.org") != std::string::npos);

    std::filesystem::remove_all(dir);
    return finish("config_test");
}
