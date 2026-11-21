#include "store.h"

#include "util.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <sys/stat.h>

namespace fs = std::filesystem;

namespace levee {

static bool valid_file_id(const std::string &s)
{
    unsigned char raw[32];
    return unhex(s, raw, 32);
}

/* "hashes", or a chunk number below a million */
static bool valid_piece(const std::string &p)
{
    if (p == "hashes")
        return true;
    if (p.empty() || p.size() > 6 || (p.size() > 1 && p[0] == '0'))
        return false;
    return std::all_of(p.begin(), p.end(), [](char c) { return c >= '0' && c <= '9'; });
}

bool load_or_create_key(const std::string &dir, Key &k, std::string &err)
{
    std::error_code ec;
    fs::create_directories(dir, ec);
    std::string path = dir + "/levee.key", text;
    if (!read_file(path, text)) {
        unsigned char seed[32];
        if (!random_bytes(seed, sizeof seed) || !write_file(path, hex(seed, 32) + "\n", true)) {
            err = "could not make " + path;
            return false;
        }
        OPENSSL_cleanse(seed, sizeof seed);
        if (!read_file(path, text)) {
            err = "could not read " + path;
            return false;
        }
    }
    if (text.size() < 64 || !unhex(text.substr(0, 64), k.seed, 32) || pp_ed25519_public(k.seed, k.pub) != 0 ||
        pp_seal_key_from_seed(k.seed, PP_SEAL_INFO_LEVEE, k.seal_sk, k.seal_pk) != 0) {
        err = path + " is damaged";
        return false;
    }
    char id[PP_ID_LEN + 1];
    pp_key_id_b32(PP_LABEL_LEVEE, k.pub, id);
    k.id = id;
    return true;
}

bool Store::open(const std::string &dir, std::string &err)
{
    dir_ = dir;
    std::error_code ec;
    fs::create_directories(dir + "/spool", ec);
    fs::create_directories(dir + "/files", ec);
    if (ec) {
        err = "could not make the folders in " + dir + ": " + ec.message();
        return false;
    }
    std::string text;
    Json::Value j;
    if (read_file(dir + "/join.json", text)) {
        if (!parse_object(text, j)) {
            err = dir + "/join.json is damaged";
            return false;
        }
        join_.puddle = j.get("puddle", "").asString();
        join_.chain = j.get("chain", "").asString();
        join_.turn_user = j.get("turn_user", "").asString();
        join_.turn_pass = j.get("turn_pass", "").asString();
        join_.token = j.get("token", "").asString();
        join_.replace = j.get("replace", false).asBool();
    }
    if (read_file(dir + "/peers.json", text)) {
        std::string why;
        if (!set_peers(text, why)) {
            err = dir + "/peers.json is damaged: " + why;
            return false;
        }
    }
    /* the spool: numbers carry on from the highest there */
    for (const auto &e : fs::directory_iterator(dir + "/spool", ec)) {
        std::string name = e.path().filename().string();
        if (name.size() < 6 || name.substr(name.size() - 5) != ".json")
            continue;
        uint64_t n = strtoull(name.c_str(), nullptr, 10);
        if (!n)
            continue;
        uint64_t size = (uint64_t)e.file_size(ec);
        spooled_[n] = size;
        spool_bytes_ += size;
        next_n_ = std::max(next_n_, n + 1);
        Json::Value it;
        if (read_file(e.path().string(), text) && parse_object(text, it)) {
            std::string key = it.get("sender", "").asString() + ":" + it.get("nonce", "").asString();
            spool_nonces_.insert(key);
            spool_nonce_of_[n] = key;
        }
    }
    return true;
}

bool Store::save_join()
{
    Json::Value j;
    j["puddle"] = join_.puddle;
    j["chain"] = join_.chain;
    j["turn_user"] = join_.turn_user;
    j["turn_pass"] = join_.turn_pass;
    j["token"] = join_.token;
    j["replace"] = join_.replace;
    return write_file(dir_ + "/join.json", to_json(j) + "\n", true);
}

bool Store::set_peers(const std::string &json, std::string &err)
{
    Json::Value j;
    if (!parse_object(json, j) || !j["peers"].isArray() || (j.isMember("devices") && !j["devices"].isArray())) {
        err = "not {peers: [...], devices: [...]}";
        return false;
    }
    std::map<std::string, std::array<unsigned char, 32>> keys;
    for (const Json::Value &p : j["peers"]) {
        if (!p.isObject() || !p["id"].isString() || !p["chain"].isString())
            continue;
        std::string id = p["id"].asString(), chain = p["chain"].asString();
        pp_chain_head h;
        char why[200];
        if (pp_chain_verify(chain.data(), chain.size(), id.c_str(), &h, why, sizeof why) != 0)
            continue;
        std::array<unsigned char, 32> k;
        memcpy(k.data(), h.sign_pub, 32);
        keys[id] = k;
    }
    for (const Json::Value &d : j["devices"]) {
        if (!d.isObject() || !d["id"].isString() || !d["key"].isString())
            continue;
        std::array<unsigned char, 32> k;
        char id[PP_ID_LEN + 1];
        if (!unbase64(d["key"].asString(), k.data(), 32))
            continue;
        pp_key_id_b32(PP_LABEL_DEVICE, k.data(), id);
        if (d["id"].asString() != id)
            continue;
        keys[id] = k;
    }
    peer_keys_ = std::move(keys);
    if (!write_file(dir_ + "/peers.json", json, true)) {
        err = "could not write peers.json";
        return false;
    }
    return true;
}

void Store::clear_peers()
{
    peer_keys_.clear();
    std::error_code ec;
    fs::remove(dir_ + "/peers.json", ec);
}

static std::string spool_path(const std::string &dir, uint64_t n)
{
    return dir + "/spool/" + std::to_string(n) + ".json";
}

bool Store::spool(const Item &it)
{
    Json::Value j;
    j["n"] = (Json::UInt64)it.n;
    j["received"] = (Json::Int64)it.received;
    j["method"] = it.method;
    j["target"] = it.target;
    j["signature"] = it.signature;
    j["seal"] = it.seal;
    j["content_type"] = it.content_type;
    j["sender"] = it.sender;
    j["nonce"] = it.nonce;
    j["body"] = base64((const unsigned char *)it.body.data(), it.body.size());
    std::string text = to_json(j) + "\n";
    if (!write_file(spool_path(dir_, it.n), text, true))
        return false;
    spooled_[it.n] = text.size();
    spool_bytes_ += text.size();
    std::string key = it.sender + ":" + it.nonce;
    spool_nonces_.insert(key);
    spool_nonce_of_[it.n] = key;
    return true;
}

std::vector<Item> Store::spooled_after(uint64_t after, size_t max_items, size_t max_bytes)
{
    std::vector<Item> out;
    size_t bytes = 0;
    for (auto it = spooled_.upper_bound(after); it != spooled_.end() && out.size() < max_items; ++it) {
        std::string text;
        Json::Value j;
        if (!read_file(spool_path(dir_, it->first), text) || !parse_object(text, j))
            continue;
        Item i;
        i.n = it->first;
        i.live = false;
        i.received = j.get("received", 0).asInt64();
        i.method = j.get("method", "").asString();
        i.target = j.get("target", "").asString();
        i.signature = j.get("signature", "").asString();
        i.seal = j.get("seal", "").asString();
        i.content_type = j.get("content_type", "").asString();
        i.sender = j.get("sender", "").asString();
        i.nonce = j.get("nonce", "").asString();
        if (!unbase64_any(j.get("body", "").asString(), i.body))
            continue;
        if (!out.empty() && bytes + i.body.size() > max_bytes)
            break;
        bytes += i.body.size();
        out.push_back(std::move(i));
    }
    return out;
}

void Store::drop_spooled_upto(uint64_t n)
{
    std::error_code ec;
    while (!spooled_.empty() && spooled_.begin()->first <= n) {
        auto it = spooled_.begin();
        fs::remove(spool_path(dir_, it->first), ec);
        spool_bytes_ -= std::min(spool_bytes_, it->second);
        auto k = spool_nonce_of_.find(it->first);
        if (k != spool_nonce_of_.end()) {
            spool_nonces_.erase(k->second);
            spool_nonce_of_.erase(k);
        }
        spooled_.erase(it);
    }
}

void Store::drop_spool()
{
    if (!spooled_.empty())
        drop_spooled_upto(spooled_.rbegin()->first);
}

void Store::trim_spool(uint64_t max_bytes, int64_t before_ms)
{
    std::error_code ec;
    while (!spooled_.empty()) {
        auto it = spooled_.begin();
        bool old = false;
        if (spool_bytes_ <= max_bytes) {
            struct stat st;
            old = stat(spool_path(dir_, it->first).c_str(), &st) == 0 && (int64_t)st.st_mtime * 1000 < before_ms;
            if (!old)
                break;
        }
        drop_spooled_upto(it->first);
    }
}

bool Store::spooled_nonce(const std::string &sender, const std::string &nonce) const
{
    return spool_nonces_.count(sender + ":" + nonce) > 0;
}

/* ---- files ---- */

std::optional<FileMeta> Store::file(const std::string &id)
{
    if (!valid_file_id(id))
        return std::nullopt;
    std::string text;
    Json::Value j;
    if (!read_file(file_dir(id) + "/meta.json", text) || !parse_object(text, j))
        return std::nullopt;
    FileMeta m;
    m.id = id;
    for (const Json::Value &f : j["for"])
        if (f.isString())
            m.for_whom.insert(f.asString());
    m.ready = j.get("ready", false).asBool();
    m.created = j.get("created", 0).asInt64();
    m.bytes = j.get("bytes", 0).asUInt64();
    return m;
}

bool Store::save_file(const FileMeta &m)
{
    if (!valid_file_id(m.id))
        return false;
    Json::Value j;
    j["for"] = Json::arrayValue;
    for (const std::string &f : m.for_whom)
        j["for"].append(f);
    j["ready"] = m.ready;
    j["created"] = (Json::Int64)m.created;
    j["bytes"] = (Json::UInt64)m.bytes;
    std::error_code ec;
    fs::create_directories(file_dir(m.id), ec);
    return write_file(file_dir(m.id) + "/meta.json", to_json(j) + "\n");
}

bool Store::put_piece(const std::string &file, const std::string &piece, const std::string &data, uint64_t max_file, uint64_t max_total)
{
    if (!valid_file_id(file) || !valid_piece(piece))
        return false;
    FileMeta m;
    if (auto have = this->file(file))
        m = *have;
    else
        m.id = file, m.created = wall_ms();
    std::string path = file_dir(file) + "/" + piece;
    std::error_code ec;
    uint64_t before = fs::exists(path, ec) ? (uint64_t)fs::file_size(path, ec) : 0;
    uint64_t bytes = m.bytes - std::min(m.bytes, before) + data.size();
       /* sealed: 16 bytes more for every 64 KiB, and for each piece */
    if (bytes > max_file + (max_file >> 12) + 4096 || files_bytes() - std::min(files_bytes(), before) + data.size() > max_total)
        return false;
    m.ready = false; /* a piece put again: ready must be said again */
    m.bytes = bytes;
    fs::create_directories(file_dir(file), ec);
    return write_file(path, data) && save_file(m);
}

bool Store::read_piece(const std::string &file, const std::string &piece, std::string &out)
{
    return valid_file_id(file) && valid_piece(piece) && read_file(file_dir(file) + "/" + piece, out);
}

void Store::remove_file(const std::string &id)
{
    if (!valid_file_id(id))
        return;
    std::error_code ec;
    fs::remove_all(file_dir(id), ec);
}

std::vector<FileMeta> Store::files()
{
    std::vector<FileMeta> out;
    std::error_code ec;
    for (const auto &e : fs::directory_iterator(dir_ + "/files", ec))
        if (auto m = file(e.path().filename().string()))
            out.push_back(*m);
    return out;
}

uint64_t Store::files_bytes()
{
    uint64_t total = 0;
    for (const FileMeta &m : files())
        total += m.bytes;
    return total;
}

void Store::drop_files()
{
    std::error_code ec;
    fs::remove_all(dir_ + "/files", ec);
    fs::create_directories(dir_ + "/files", ec);
}

} // namespace levee
