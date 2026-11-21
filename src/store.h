#pragma once

/* What a Levee keeps, as plain files in its data folder (README.md, "The data folder"; the protocol's spec/06, "What a Levee
 * keeps"). No database. Not thread-safe: the Levee calls it under its own lock.
 *
 *   levee.key              the seed of its Ed25519 key, hex (0600): its id and sealing key come from it
 *   cert.pem, key.pem      TLS, self-signed unless the operator put their own (tls.h)
 *   join.json              the Puddle it serves (id and key chain), the relay's credentials, an open join token
 *   peers.json             who may reach the Puddle: its friends' chains and its phones' keys (sealed to the Levee on the way)
 *   spool/<n>.json         a one-way request that came while the Puddle was away, body and all (base64)
 *   files/<file>/          a file the Puddle left for friends: meta.json (who may fetch it), and its sealed pieces */

#include <puddle_proto.h>

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace levee {

struct Key {
    unsigned char seed[32] = {};
    unsigned char pub[32] = {};
    std::string id;
    unsigned char seal_sk[32] = {}, seal_pk[32] = {};
};

/* Make levee.key in `dir` (which is made too) unless it is there; then read it. */
bool load_or_create_key(const std::string &dir, Key &out, std::string &err);

struct Join {
    std::string puddle;      /* the Puddle's id; "" = none joined */
    std::string chain;       /* its key chain, as it last sent it */
    std::string turn_user, turn_pass;
    std::string token;       /* an open join token, "" for none */
    bool replace = false;    /* the token may replace the Puddle joined now */
};

/* A request for the Puddle: live (someone waits for the answer) or spooled (answered with a custody receipt). */
struct Item {
    uint64_t n = 0;
    bool live = false;
    int64_t received = 0;
    std::string method, target, signature, seal, content_type, range;
    std::string body;
    std::string sender, nonce; /* from the signature: what the replay memory and the logs know it by */
    /* a friend has fetched a whole file: told to the Puddle on inbox */
    std::string file_done, file_done_by;
};

struct FileMeta {
    std::string id;
    std::set<std::string> for_whom;
    bool ready = false;
    int64_t created = 0;
    uint64_t bytes = 0;
};

class Store {
public:
    bool open(const std::string &dir, std::string &err);
    const std::string &dir() const { return dir_; }

    Join &join() { return join_; }
    bool save_join();

    /* who may reach the Puddle: user id or device id -> current signing key */
    const std::map<std::string, std::array<unsigned char, 32>> &peers() const { return peer_keys_; }
    /* Take a peers list as the Puddle sent it ({"peers": [{id, chain}], "devices": [{id, key}]}): false if malformed. A chain
     * that doesn't check is left out. */
    bool set_peers(const std::string &json, std::string &err);
    void clear_peers();

    uint64_t next_n() { return next_n_++; }

    bool spool(const Item &it);
    std::vector<Item> spooled_after(uint64_t after, size_t max_items, size_t max_bytes);
    void drop_spooled_upto(uint64_t n);
    void drop_spool();
    uint64_t spool_bytes() const { return spool_bytes_; }
    /* the oldest first, while there is more than `max_bytes` or older than `before_ms` */
    void trim_spool(uint64_t max_bytes, int64_t before_ms);
    bool spooled_nonce(const std::string &sender, const std::string &nonce) const;

    /* files */
    std::string file_dir(const std::string &file) const { return dir_ + "/files/" + file; }
    std::optional<FileMeta> file(const std::string &id);
    bool put_piece(const std::string &file, const std::string &piece, const std::string &data, uint64_t max_file, uint64_t max_total);
    bool read_piece(const std::string &file, const std::string &piece, std::string &out);
    bool save_file(const FileMeta &m);
    void remove_file(const std::string &id);
    std::vector<FileMeta> files();
    uint64_t files_bytes();
    void drop_files();

private:
    std::string dir_;
    Join join_;
    std::map<std::string, std::array<unsigned char, 32>> peer_keys_;
    uint64_t next_n_ = 1;
    std::map<uint64_t, uint64_t> spooled_; /* n -> bytes on disk */
    uint64_t spool_bytes_ = 0;
    std::set<std::string> spool_nonces_;   /* "<sender>:<nonce>" of what is spooled */
    std::map<uint64_t, std::string> spool_nonce_of_;
};

} // namespace levee
