#include "config.h"

#include <yaml-cpp/yaml.h>

#include <arpa/inet.h>

#include <cstdio>
#include <cstring>
#include <set>

namespace levee {

static bool unsigned_of(const YAML::Node &n, const char *what, unsigned max, unsigned &out, std::string &err)
{
    try {
        long long v = n.as<long long>();
        if (v < 0 || (unsigned long long)v > max) {
            err = std::string(what) + ": out of range";
            return false;
        }
        out = (unsigned)v;
        return true;
    } catch (...) {
        err = std::string(what) + ": not a number";
        return false;
    }
}

static bool check_keys(const YAML::Node &n, const std::set<std::string> &allowed, const std::string &where, std::string &err)
{
    for (auto it = n.begin(); it != n.end(); ++it) {
        std::string k = it->first.as<std::string>();
        if (!allowed.count(k)) {
            err = "unknown setting " + where + k;
            return false;
        }
    }
    return true;
}

bool load_config(const std::string &path, Config &c, std::string &err)
{
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const std::exception &e) {
        err = path + ": " + e.what();
        return false;
    }
    if (!root.IsMap()) {
        err = path + ": not a map of settings";
        return false;
    }
    if (!check_keys(root, {"listen", "port", "address", "data_dir", "threads", "spool", "files", "turn", "trusted_proxies"}, "", err))
        return false;
    try {
        if (root["listen"])
            c.listen = root["listen"].as<std::string>();
        if (root["port"] && !unsigned_of(root["port"], "port", 65535, c.port, err))
            return false;
        if (root["address"])
            c.address = root["address"].as<std::string>();
        if (root["data_dir"])
            c.data_dir = root["data_dir"].as<std::string>();
        if (root["threads"] && !unsigned_of(root["threads"], "threads", 64, c.threads, err))
            return false;
        if (YAML::Node s = root["spool"]) {
            if (!s.IsMap() || !check_keys(s, {"max_mb", "keep_days"}, "spool.", err))
                return err.empty() ? (err = "spool: a map", false) : false;
            unsigned v;
            if (s["max_mb"]) {
                if (!unsigned_of(s["max_mb"], "spool.max_mb", 1u << 20, v, err))
                    return false;
                c.spool_max_bytes = (uint64_t)v << 20;
            }
            if (s["keep_days"]) {
                if (!unsigned_of(s["keep_days"], "spool.keep_days", 3650, v, err))
                    return false;
                c.spool_keep_days = (int)v;
            }
        }
        if (YAML::Node f = root["files"]) {
            if (!f.IsMap() || !check_keys(f, {"max_mb", "total_mb", "keep_days"}, "files.", err))
                return err.empty() ? (err = "files: a map", false) : false;
            unsigned v;
            if (f["max_mb"]) {
                if (!unsigned_of(f["max_mb"], "files.max_mb", 1u << 20, v, err))
                    return false;
                c.file_max_bytes = (uint64_t)v << 20;
            }
            if (f["total_mb"]) {
                if (!unsigned_of(f["total_mb"], "files.total_mb", 1u << 24, v, err))
                    return false;
                c.files_max_bytes = (uint64_t)v << 20;
            }
            if (f["keep_days"]) {
                if (!unsigned_of(f["keep_days"], "files.keep_days", 3650, v, err))
                    return false;
                c.files_keep_days = (int)v;
            }
        }
        if (YAML::Node t = root["turn"]) {
            if (t.IsScalar()) {
                c.turn.on = t.as<bool>();
            } else {
                if (!t.IsMap() || !check_keys(t, {"port", "relay_ports", "public_ip"}, "turn.", err))
                    return err.empty() ? (err = "turn: false, or a map", false) : false;
                if (t["port"] && !unsigned_of(t["port"], "turn.port", 65535, c.turn.port, err))
                    return false;
                if (t["public_ip"])
                    c.turn.public_ip = t["public_ip"].as<std::string>();
                if (t["relay_ports"]) {
                    std::string r = t["relay_ports"].as<std::string>();
                    unsigned a = 0, b = 0;
                    char dash = 0;
                    if (sscanf(r.c_str(), "%u%c%u", &a, &dash, &b) != 3 || dash != '-' || a == 0 || b < a || b > 65535 || b - a > 1000) {
                        err = "turn.relay_ports: a range like 49160-49199";
                        return false;
                    }
                    c.turn.relay_from = a, c.turn.relay_to = b;
                }
            }
        }
        if (YAML::Node t = root["trusted_proxies"]) {
            if (!t.IsSequence()) {
                err = "trusted_proxies: a list of addresses or ranges, like [127.0.0.1, 172.16.0.0/12]";
                return false;
            }
            for (const auto &n : t) {
                IpNet net;
                std::string text = n.as<std::string>();
                if (!parse_ipnet(text, net)) {
                    err = "trusted_proxies: \"" + text + "\" is not an address or a range like 172.16.0.0/12";
                    return false;
                }
                c.trusted_proxies.push_back(net);
            }
        }
    } catch (const std::exception &e) {
        err = path + ": " + e.what();
        return false;
    }
    if (c.address.empty()) {
        err = "address: required (where others reach the Puddle, e.g. levee.example.org:443)";
        return false;
    }
    if (c.data_dir.empty()) {
        err = "data_dir: required";
        return false;
    }
    return true;
}

std::string address_with_port(const std::string &a)
{
    if (!a.empty() && a[0] == '[')
        return a.find("]:") != std::string::npos ? a : a + ":443";
    size_t colon = a.rfind(':');
    return colon != std::string::npos && a.find(':') == colon ? a : a + ":443";
}

std::string address_host(const std::string &a)
{
    if (!a.empty() && a[0] == '[') {
        size_t e = a.find(']');
        return e == std::string::npos ? a : a.substr(1, e - 1);
    }
    size_t colon = a.rfind(':');
    return colon != std::string::npos && a.find(':') == colon ? a.substr(0, colon) : a;
}

/* The address as 16 bytes; an IPv4 one, or one written as IPv6 but mapped (::ffff:1.2.3.4), as 4. */
static bool parse_ip(std::string_view text, unsigned char out[16], bool &v6)
{
    std::string t(text);
    if (t.size() > 2 && t.front() == '[' && t.back() == ']')
        t = t.substr(1, t.size() - 2);
    in_addr a4;
    if (inet_pton(AF_INET, t.c_str(), &a4) == 1) {
        memset(out, 0, 16);
        memcpy(out, &a4, 4);
        v6 = false;
        return true;
    }
    in6_addr a6;
    if (inet_pton(AF_INET6, t.c_str(), &a6) != 1)
        return false;
    static const unsigned char mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    if (!memcmp(&a6, mapped, 12)) {
        memset(out, 0, 16);
        memcpy(out, (const unsigned char *)&a6 + 12, 4);
        v6 = false;
        return true;
    }
    memcpy(out, &a6, 16);
    v6 = true;
    return true;
}

bool parse_ipnet(std::string_view text, IpNet &out)
{
    size_t slash = text.find('/');
    if (!parse_ip(text.substr(0, slash), out.addr, out.v6))
        return false;
    unsigned most = out.v6 ? 128 : 32;
    out.bits = most;
    if (slash != std::string_view::npos) {
        std::string_view b = text.substr(slash + 1);
        if (b.empty() || b.size() > 3)
            return false;
        unsigned n = 0;
        for (char ch : b) {
            if (ch < '0' || ch > '9')
                return false;
            n = n * 10 + unsigned(ch - '0');
        }
        if (n > most)
            return false;
        out.bits = n;
    }
    return true;
}

bool ipnet_contains(const IpNet &net, std::string_view ip)
{
    unsigned char a[16];
    bool v6 = false;
    if (!parse_ip(ip, a, v6) || v6 != net.v6)
        return false;
    unsigned whole = net.bits / 8, rest = net.bits % 8;
    if (memcmp(a, net.addr, whole))
        return false;
    if (rest) {
        unsigned char mask = (unsigned char)(0xff << (8 - rest));
        if ((a[whole] & mask) != (net.addr[whole] & mask))
            return false;
    }
    return true;
}

static bool trusted_one(const std::vector<IpNet> &trusted, std::string_view ip)
{
    for (const IpNet &n : trusted)
        if (ipnet_contains(n, ip))
            return true;
    return false;
}

static std::string_view trim(std::string_view s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

std::string client_address(const std::vector<IpNet> &trusted, std::string_view peer, std::string_view forwarded_for)
{
    if (trusted.empty() || !trusted_one(trusted, peer))
        return std::string(peer);
    std::string_view rest = forwarded_for, last(peer);
    while (!rest.empty()) {
        size_t comma = rest.rfind(',');
        std::string_view one = trim(comma == std::string_view::npos ? rest : rest.substr(comma + 1));
        rest = comma == std::string_view::npos ? std::string_view() : rest.substr(0, comma);
        unsigned char a[16];
        bool v6;
        if (!parse_ip(one, a, v6)) /* not an address (a port, "unknown", a typo): stop at the last one we could read */
            break;
        last = one;
        if (!trusted_one(trusted, one))
            break;
    }
    return std::string(last);
}

} // namespace levee
