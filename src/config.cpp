#include "config.h"

#include <yaml-cpp/yaml.h>

#include <cstdio>
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
    if (!check_keys(root, {"listen", "port", "address", "data_dir", "threads", "spool", "files", "turn"}, "", err))
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

} // namespace levee
