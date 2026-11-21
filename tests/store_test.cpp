/* What a Levee keeps (store.h): its key, the join, the spool across a restart, and files. */

#include "harness.h"
#include "store.h"

using namespace levee;

int main()
{
    char tmpl[] = "/tmp/levee-store-XXXXXX";
    std::string dir = mkdtemp(tmpl);
    std::string err;

    Key k1, k2;
    CHECK(load_or_create_key(dir, k1, err) && load_or_create_key(dir, k2, err));
    CHECK(k1.id == k2.id && pp_id_valid(k1.id.c_str()) && !memcmp(k1.seal_pk, k2.seal_pk, 32));

    {
        Store s;
        CHECK(s.open(dir, err));
        s.join().puddle = "p";
        s.join().token = "t";
        CHECK(s.save_join());
        for (int i = 0; i < 3; i++) {
            Item it;
            it.n = s.next_n();
            it.received = 1000 + i;
            it.method = "POST";
            it.target = "/stream/v1/events";
            it.signature = "sig";
            it.sender = "alice";
            it.nonce = "nonce" + std::to_string(i);
            it.body = std::string(10, (char)('a' + i));
            CHECK(s.spool(it));
        }
        CHECK(s.spooled_nonce("alice", "nonce1") && !s.spooled_nonce("alice", "nonce9"));
    }
    Store s;
    CHECK(s.open(dir, err));
    CHECK(s.join().puddle == "p" && s.join().token == "t");
    auto all = s.spooled_after(0, 10, 1 << 20);
    CHECK(all.size() == 3 && all[1].body == std::string(10, 'b') && all[2].received == 1002);
    CHECK(s.next_n() == 4); /* numbers carry on */
    s.drop_spooled_upto(all[0].n);
    CHECK(s.spooled_after(0, 10, 1 << 20).size() == 2 && !s.spooled_nonce("alice", "nonce0"));
    s.trim_spool(0, 0); /* nothing may stay */
    CHECK(s.spooled_after(0, 10, 1 << 20).empty() && s.spool_bytes() == 0);

    std::string f = sha256_hex("f");
    CHECK(s.put_piece(f, "hashes", "h", 100, 1000) && s.put_piece(f, "0", std::string(50, 'x'), 100, 1000));
    CHECK(!s.put_piece(f, "1", std::string(2 << 20, 'x'), 1 << 20, 8 << 20)); /* larger than a file may be */
    CHECK(!s.put_piece(f, "1", std::string(2000, 'x'), 1 << 20, 1000));       /* more than all files may be */
    CHECK(!s.put_piece("not-an-id", "0", "x", 100, 1000) && !s.put_piece(f, "../x", "x", 100, 1000) && !s.put_piece(f, "01", "x", 100, 1000));
    auto m = s.file(f);
    CHECK(m && !m->ready && m->bytes == 51);
    std::string back;
    CHECK(s.read_piece(f, "0", back) && back == std::string(50, 'x'));
    s.remove_file(f);
    CHECK(!s.file(f));

    std::filesystem::remove_all(dir);
    return finish("store_test");
}
