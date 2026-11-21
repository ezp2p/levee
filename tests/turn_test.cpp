/* The relay for calls (turn.h) as a TURN client and a peer meet it: credentials, an allocation, permissions, Send and Data
 * indications, a channel both ways, refreshing to nothing, and credentials taken away. */

#include "harness.h"
#include "turn.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <poll.h>

#include <map>

using levee::Turn;
using levee::TurnSettings;

static const uint32_t COOKIE = 0x2112A442;

static void put16(std::string &s, uint16_t v) { s.push_back((char)(v >> 8)), s.push_back((char)v); }
static void put32(std::string &s, uint32_t v) { put16(s, (uint16_t)(v >> 16)), put16(s, (uint16_t)v); }
static uint16_t get16(const std::string &s, size_t at) { return (uint16_t)((unsigned char)s[at] << 8 | (unsigned char)s[at + 1]); }

struct Stun {
    std::string b;
    Stun(uint16_t method, uint16_t cls)
    {
        uint16_t type = (uint16_t)((method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | cls);
        put16(b, type);
        put16(b, 0);
        put32(b, COOKIE);
        for (int i = 0; i < 12; i++)
            b.push_back((char)(rand() & 0xff));
    }
    void attr(uint16_t t, const std::string &v)
    {
        put16(b, t);
        put16(b, (uint16_t)v.size());
        b += v;
        while (b.size() % 4)
            b.push_back('\0');
    }
    void peer(uint16_t t, uint16_t port)
    {
        std::string v;
        v.push_back(0);
        v.push_back(1);
        put16(v, (uint16_t)(port ^ (COOKIE >> 16)));
        put32(v, 0x7f000001u ^ COOKIE);
        attr(t, v);
    }
    std::string done(const std::string &key)
    {
        size_t l = b.size() - 20 + (key.empty() ? 0 : 24);
        b[2] = (char)(l >> 8), b[3] = (char)l;
        if (!key.empty()) {
            unsigned char mac[20];
            unsigned ml;
            HMAC(EVP_sha1(), key.data(), (int)key.size(), (const unsigned char *)b.data(), b.size(), mac, &ml);
            attr(0x0008, std::string((const char *)mac, 20));
        }
        return b;
    }
};

struct Parsed {
    uint16_t method = 0, cls = 0;
    std::map<uint16_t, std::string> attrs;
    bool integrity_ok = false;
};

static Parsed parse(const std::string &m, const std::string &key)
{
    Parsed p;
    if (m.size() < 20)
        return p;
    uint16_t type = get16(m, 0);
    p.method = (uint16_t)((type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2));
    p.cls = type & 0x0110;
    for (size_t at = 20; at + 4 <= m.size();) {
        uint16_t t = get16(m, at), l = get16(m, at + 2);
        if (t == 0x0008 && !key.empty()) {
            std::string head = m.substr(0, at);
            size_t hl = at - 20 + 24;
            head[2] = (char)(hl >> 8), head[3] = (char)hl;
            unsigned char mac[20];
            unsigned ml;
            HMAC(EVP_sha1(), key.data(), (int)key.size(), (const unsigned char *)head.data(), head.size(), mac, &ml);
            p.integrity_ok = m.compare(at + 4, 20, std::string((const char *)mac, 20)) == 0;
        }
        p.attrs.emplace(t, m.substr(at + 4, l));
        at += 4 + ((l + 3u) & ~3u);
    }
    return p;
}

static int udp(unsigned *port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd, (sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(fd, (sockaddr *)&a, &l);
    *port = ntohs(a.sin_port);
    return fd;
}

static void send_to(int fd, unsigned port, const std::string &data)
{
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    sendto(fd, data.data(), data.size(), 0, (sockaddr *)&a, sizeof a);
}

static std::string recv_from(int fd, unsigned *from_port = nullptr, int ms = 2000)
{
    pollfd p = { fd, POLLIN, 0 };
    if (poll(&p, 1, ms) <= 0)
        return "";
    char buf[70000];
    sockaddr_in a{};
    socklen_t l = sizeof a;
    ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (sockaddr *)&a, &l);
    if (from_port)
        *from_port = ntohs(a.sin_port);
    return n > 0 ? std::string(buf, (size_t)n) : "";
}

static unsigned xor_port(const std::string &v)
{
    return v.size() == 8 ? (unsigned)(get16(v, 2) ^ (COOKIE >> 16)) : 0;
}

int main()
{
    TurnSettings s;
    s.bind = "127.0.0.1";
    s.port = free_port(SOCK_DGRAM);
    s.relay_from = 42200 + (s.port % 500);
    s.relay_to = s.relay_from + 4;
    s.public_ip = "127.0.0.1";
    s.realm = "the-levee";
    Turn turn(s);
    std::string err;
    CHECK(turn.start(err));
    turn.set_credentials("alice", "secret");
    std::string up = "alice:the-levee:secret";
    unsigned char md5[16];
    unsigned ml;
    EVP_Digest(up.data(), up.size(), md5, &ml, EVP_md5(), nullptr);
    std::string key((const char *)md5, 16);

    unsigned cport, pport;
    int client = udp(&cport), peer = udp(&pport);
    std::string transport;
    put32(transport, 17u << 24);

    /* Binding needs nothing */
    send_to(client, s.port, Stun(0x001, 0x000).done(""));
    Parsed b = parse(recv_from(client), "");
    CHECK(b.method == 0x001 && b.cls == 0x100 && xor_port(b.attrs[0x0020]) == cport);

    /* Allocate: first refused with the realm and a nonce, then with credentials */
    Stun a1(0x003, 0x000);
    a1.attr(0x0019, transport);
    send_to(client, s.port, a1.done(""));
    Parsed r = parse(recv_from(client), "");
    CHECK(r.cls == 0x110 && r.attrs.count(0x0014) && r.attrs.count(0x0015));
    std::string nonce = r.attrs[0x0015];
    auto with_auth = [&](Stun st, const std::string &k = "") {
        st.attr(0x0006, "alice");
        st.attr(0x0014, "the-levee");
        st.attr(0x0015, nonce);
        return st.done(k.empty() ? key : k);
    };
    Stun bad(0x003, 0x000);
    bad.attr(0x0019, transport);
    std::string wrong_key(16, 'x');
    send_to(client, s.port, with_auth(bad, wrong_key));
    CHECK(parse(recv_from(client), "").cls == 0x110);
    Stun a2(0x003, 0x000);
    a2.attr(0x0019, transport);
    send_to(client, s.port, with_auth(a2));
    r = parse(recv_from(client), key);
    unsigned relay = xor_port(r.attrs[0x0016]);
    CHECK(r.method == 0x003 && r.cls == 0x100 && r.integrity_ok && relay >= s.relay_from && relay <= s.relay_to);
    CHECK(xor_port(r.attrs[0x0020]) == cport);
    CHECK(until([&] { return turn.allocations() == 1; }, 2000));

    /* no permission yet: what the peer sends is dropped */
    send_to(peer, relay, "too early");
    CHECK(recv_from(client, nullptr, 300).empty());

    Stun cp(0x008, 0x000);
    cp.peer(0x0012, (uint16_t)pport);
    send_to(client, s.port, with_auth(cp));
    r = parse(recv_from(client), key);
    CHECK(r.method == 0x008 && r.cls == 0x100 && r.integrity_ok);

    /* Send indication -> the peer, from the relayed port */
    Stun si(0x006, 0x010);
    si.peer(0x0012, (uint16_t)pport);
    si.attr(0x0013, "hello peer");
    send_to(client, s.port, si.done(""));
    unsigned from = 0;
    CHECK(recv_from(peer, &from) == "hello peer" && from == relay);
    /* the peer answers -> a Data indication */
    send_to(peer, relay, "hello client");
    r = parse(recv_from(client), "");
    CHECK(r.method == 0x007 && r.cls == 0x010 && r.attrs[0x0013] == "hello client" && xor_port(r.attrs[0x0012]) == pport);

    /* a channel, both ways */
    Stun cb(0x009, 0x000);
    std::string num;
    put32(num, 0x40010000u);
    cb.attr(0x000C, num);
    cb.peer(0x0012, (uint16_t)pport);
    send_to(client, s.port, with_auth(cb));
    r = parse(recv_from(client), key);
    CHECK(r.method == 0x009 && r.cls == 0x100);
    std::string cd;
    put16(cd, 0x4001);
    put16(cd, 5);
    cd += "media";
    send_to(client, s.port, cd);
    CHECK(recv_from(peer) == "media");
    send_to(peer, relay, "back");
    std::string got = recv_from(client);
    CHECK(got.size() == 8 && get16(got, 0) == 0x4001 && get16(got, 2) == 4 && got.substr(4) == "back");

    /* refreshed to nothing: gone */
    Stun rf(0x004, 0x000);
    std::string zero;
    put32(zero, 0);
    rf.attr(0x000D, zero);
    send_to(client, s.port, with_auth(rf));
    r = parse(recv_from(client), key);
    CHECK(r.method == 0x004 && r.cls == 0x100);
    CHECK(until([&] { return turn.allocations() == 0; }, 2000));

    /* again, then the credentials go (the Puddle left): the allocation goes with them, and no new one is made */
    Stun a3(0x003, 0x000);
    a3.attr(0x0019, transport);
    send_to(client, s.port, with_auth(a3));
    CHECK(parse(recv_from(client), key).cls == 0x100);
    CHECK(until([&] { return turn.allocations() == 1; }, 2000));
    turn.set_credentials("", "");
    CHECK(until([&] { return turn.allocations() == 0; }, 2000));
    Stun a4(0x003, 0x000);
    a4.attr(0x0019, transport);
    send_to(client, s.port, with_auth(a4));
    CHECK(parse(recv_from(client), "").cls == 0x110);

    close(client);
    close(peer);
    turn.stop();
    return finish("turn_test");
}
