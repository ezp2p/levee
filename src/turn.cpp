#include "turn.h"

#include "util.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <trantor/utils/Logger.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <map>
#include <memory>
#include <vector>

namespace levee {

/* ---------------------------------------------------------------- STUN messages (RFC 8489) */

static constexpr uint32_t COOKIE = 0x2112A442;

enum : uint16_t {
    M_BINDING = 0x001, M_ALLOCATE = 0x003, M_REFRESH = 0x004, M_SEND = 0x006, M_DATA = 0x007, M_CREATE_PERMISSION = 0x008,
    M_CHANNEL_BIND = 0x009,
};
enum : uint16_t { C_REQUEST = 0x000, C_INDICATION = 0x010, C_SUCCESS = 0x100, C_ERROR = 0x110 };
enum : uint16_t {
    A_MAPPED_ADDRESS = 0x0001, A_USERNAME = 0x0006, A_MESSAGE_INTEGRITY = 0x0008, A_ERROR_CODE = 0x0009, A_CHANNEL_NUMBER = 0x000C,
    A_LIFETIME = 0x000D, A_XOR_PEER_ADDRESS = 0x0012, A_DATA = 0x0013, A_REALM = 0x0014, A_NONCE = 0x0015,
    A_XOR_RELAYED_ADDRESS = 0x0016, A_REQUESTED_TRANSPORT = 0x0019, A_XOR_MAPPED_ADDRESS = 0x0020, A_SOFTWARE = 0x8022,
    A_FINGERPRINT = 0x8028,
};

static uint16_t get16(const unsigned char *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t get32(const unsigned char *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void put16(std::string &s, uint16_t v) { s.push_back((char)(v >> 8)), s.push_back((char)v); }
static void put32(std::string &s, uint32_t v) { put16(s, (uint16_t)(v >> 16)), put16(s, (uint16_t)v); }

static uint32_t crc32(const unsigned char *p, size_t n)
{
    static uint32_t table[256];
    static bool made = false;
    if (!made) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        made = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++)
        c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

struct Msg {
    uint16_t method = 0, cls = 0;
    unsigned char txid[12] = {};
    std::map<uint16_t, std::string> attrs; /* the first of each */
    size_t integrity_at = 0;               /* offset of MESSAGE-INTEGRITY, 0 if none */
    std::string raw;
};

static bool parse(const unsigned char *p, size_t n, Msg &m)
{
    if (n < 20 || (p[0] & 0xC0) != 0 || get32(p + 4) != COOKIE)
        return false;
    uint16_t type = get16(p), len = get16(p + 2);
    if ((size_t)len + 20 != n || len % 4)
        return false;
    m.method = (uint16_t)((type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2));
    m.cls = (uint16_t)(type & 0x0110);
    memcpy(m.txid, p + 8, 12);
    m.raw.assign((const char *)p, n);
    size_t at = 20;
    while (at + 4 <= n) {
        uint16_t t = get16(p + at), l = get16(p + at + 2);
        if (at + 4 + l > n)
            return false;
        if (t == A_MESSAGE_INTEGRITY && !m.integrity_at)
            m.integrity_at = at;
        if (!m.integrity_at || t == A_MESSAGE_INTEGRITY || t == A_FINGERPRINT)
            m.attrs.emplace(t, std::string((const char *)p + at + 4, l));
        at += 4 + ((l + 3) & ~3u);
    }
    return at == n;
}

class Builder {
public:
    Builder(uint16_t method, uint16_t cls, const unsigned char txid[12])
    {
        uint16_t type = (uint16_t)((method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | cls);
        put16(b_, type);
        put16(b_, 0);
        put32(b_, COOKIE);
        b_.append((const char *)txid, 12);
    }
    void attr(uint16_t t, const std::string &v)
    {
        put16(b_, t);
        put16(b_, (uint16_t)v.size());
        b_ += v;
        while (b_.size() % 4)
            b_.push_back('\0');
    }
    void xor_addr(uint16_t t, const sockaddr_in &a)
    {
        std::string v;
        v.push_back('\0');
        v.push_back('\x01');
        put16(v, (uint16_t)(ntohs(a.sin_port) ^ (COOKIE >> 16)));
        put32(v, ntohl(a.sin_addr.s_addr) ^ COOKIE);
        attr(t, v);
    }
    void error(int code, const char *reason)
    {
        std::string v;
        put16(v, 0);
        v.push_back((char)(code / 100));
        v.push_back((char)(code % 100));
        v += reason;
        attr(A_ERROR_CODE, v);
    }
    void u32(uint16_t t, uint32_t x)
    {
        std::string v;
        put32(v, x);
        attr(t, v);
    }
    /* MESSAGE-INTEGRITY (HMAC-SHA1 under `key`) and FINGERPRINT */
    std::string finish(const std::string &key)
    {
        if (!key.empty()) {
            set_len(b_.size() - 20 + 24);
            unsigned char mac[20];
            unsigned ml = 0;
            HMAC(EVP_sha1(), key.data(), (int)key.size(), (const unsigned char *)b_.data(), b_.size(), mac, &ml);
            attr(A_MESSAGE_INTEGRITY, std::string((const char *)mac, 20));
        }
        set_len(b_.size() - 20 + 8);
        std::string fp;
        put32(fp, crc32((const unsigned char *)b_.data(), b_.size()) ^ 0x5354554e);
        attr(A_FINGERPRINT, fp);
        return b_;
    }

private:
    void set_len(size_t n)
    {
        b_[2] = (char)(n >> 8);
        b_[3] = (char)n;
    }
    std::string b_;
};

static bool xor_addr_of(const std::string &v, sockaddr_in &out)
{
    if (v.size() != 8 || v[1] != 0x01)
        return false;
    const unsigned char *p = (const unsigned char *)v.data();
    memset(&out, 0, sizeof out);
    out.sin_family = AF_INET;
    out.sin_port = htons((uint16_t)(get16(p + 2) ^ (COOKIE >> 16)));
    out.sin_addr.s_addr = htonl(get32(p + 4) ^ COOKIE);
    return true;
}

static std::string key_of(const sockaddr_in &a)
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
    return std::string(ip) + ":" + std::to_string(ntohs(a.sin_port));
}

static std::string ip_of(const sockaddr_in &a)
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
    return ip;
}

/* ---------------------------------------------------------------- allocations */

struct Allocation {
    sockaddr_in client{};
    int relay = -1;
    unsigned relay_port = 0;
    int64_t expires = 0;
    std::map<std::string, int64_t> permissions; /* peer IP -> expiry */
    std::map<uint16_t, std::pair<sockaddr_in, int64_t>> channels; /* number -> peer, expiry */
    std::map<std::string, uint16_t> channel_of;                  /* "ip:port" -> number */
};

struct Turn::Impl {
    int sock = -1;
    std::map<std::string, Allocation> allocs; /* client "ip:port" -> its allocation */
    std::string nonce;
    int64_t nonce_made = 0;
    sockaddr_in public_ip{};
};

Turn::Turn(const TurnSettings &s) : s_(s), impl_(new Impl) {}

Turn::~Turn()
{
    stop();
    for (auto &[k, a] : impl_->allocs)
        if (a.relay >= 0)
            close(a.relay);
    if (impl_->sock >= 0)
        close(impl_->sock);
    delete impl_;
}

void Turn::set_credentials(const std::string &user, const std::string &pass)
{
    std::lock_guard<std::mutex> g(mu_);
    if (user != user_ || pass != pass_)
        creds_changed_ = true;
    user_ = user, pass_ = pass;
}

static int udp_bind(const std::string &ip, unsigned port, unsigned *bound)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = ip.empty() ? htonl(INADDR_ANY) : inet_addr(ip.c_str());
    if (bind(fd, (sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return -1;
    }
    if (bound) {
        socklen_t l = sizeof a;
        getsockname(fd, (sockaddr *)&a, &l);
        *bound = ntohs(a.sin_port);
    }
    return fd;
}

bool Turn::start(std::string &err)
{
    impl_->sock = udp_bind(s_.bind, s_.port, &port_);
    if (impl_->sock < 0) {
        err = "could not bind UDP port " + std::to_string(s_.port) + " for the relay";
        return false;
    }
    impl_->public_ip.sin_family = AF_INET;
    if (inet_pton(AF_INET, s_.public_ip.c_str(), &impl_->public_ip.sin_addr) != 1) {
        err = "turn.public_ip: not an IPv4 address (" + s_.public_ip + ")";
        return false;
    }
    thread_ = std::thread([this] { run(); });
    return true;
}

void Turn::stop()
{
    stop_ = true;
    if (thread_.joinable())
        thread_.join();
}

void Turn::run()
{
    Impl &I = *impl_;
    std::vector<unsigned char> buf(65536 + 64);
    constexpr int64_t ALLOC_DEFAULT = 600 * 1000, ALLOC_MAX = 3600 * 1000, PERM = 300 * 1000, CHAN = 600 * 1000;
    std::string user, pass, key;

    auto send_to = [&](int fd, const sockaddr_in &to, const std::string &data) {
        sendto(fd, data.data(), data.size(), 0, (const sockaddr *)&to, sizeof to);
    };
    auto drop = [&](const std::string &k) {
        auto it = I.allocs.find(k);
        if (it == I.allocs.end())
            return;
        if (it->second.relay >= 0)
            close(it->second.relay);
        I.allocs.erase(it);
        allocs_ = I.allocs.size();
    };
    auto free_port = [&]() -> std::pair<int, unsigned> {
        for (unsigned p = s_.relay_from; p <= s_.relay_to; p++) {
            bool used = false;
            for (auto &[k, a] : I.allocs)
                used = used || a.relay_port == p;
            if (used)
                continue;
            unsigned bound = 0;
            int fd = udp_bind(s_.bind, p, &bound);
            if (fd >= 0)
                return { fd, bound };
        }
        return { -1, 0 };
    };

    while (!stop_) {
        int64_t now = wall_ms();
        {
            std::lock_guard<std::mutex> g(mu_);
            if (creds_changed_) {
                creds_changed_ = false;
                while (!I.allocs.empty())
                    drop(I.allocs.begin()->first);
            }
            user = user_, pass = pass_;
        }
        if (now - I.nonce_made > 3600 * 1000) {
            I.nonce = random_token();
            I.nonce_made = now;
        }
        if (!user.empty()) {
            std::string up = user + ":" + s_.realm + ":" + pass;
            unsigned char md5[16];
            unsigned ml = 0;
            EVP_Digest(up.data(), up.size(), md5, &ml, EVP_md5(), nullptr);
            key.assign((const char *)md5, 16);
        } else {
            key.clear();
        }
        /* expiries */
        for (auto it = I.allocs.begin(); it != I.allocs.end();) {
            Allocation &a = it->second;
            if (a.expires <= now) {
                if (a.relay >= 0)
                    close(a.relay);
                it = I.allocs.erase(it);
                continue;
            }
            for (auto p = a.permissions.begin(); p != a.permissions.end();)
                p = p->second <= now ? a.permissions.erase(p) : std::next(p);
            for (auto c = a.channels.begin(); c != a.channels.end();) {
                if (c->second.second <= now) {
                    a.channel_of.erase(key_of(c->second.first));
                    c = a.channels.erase(c);
                } else {
                    ++c;
                }
            }
            ++it;
        }
        allocs_ = I.allocs.size();

        std::vector<pollfd> fds;
        std::vector<std::string> owner;
        fds.push_back({ I.sock, POLLIN, 0 });
        owner.push_back("");
        for (auto &[k, a] : I.allocs) {
            fds.push_back({ a.relay, POLLIN, 0 });
            owner.push_back(k);
        }
        if (poll(fds.data(), fds.size(), 200) <= 0)
            continue;

        for (size_t i = 0; i < fds.size(); i++) {
            if (!(fds[i].revents & POLLIN))
                continue;
            sockaddr_in from{};
            socklen_t fl = sizeof from;
            ssize_t n = recvfrom(fds[i].fd, buf.data(), buf.size(), 0, (sockaddr *)&from, &fl);
            if (n <= 0 || from.sin_family != AF_INET)
                continue;

            if (i > 0) { /* from a peer, to a relayed address */
                auto it = I.allocs.find(owner[i]);
                if (it == I.allocs.end())
                    continue;
                Allocation &a = it->second;
                if (!a.permissions.count(ip_of(from)))
                    continue;
                auto ch = a.channel_of.find(key_of(from));
                if (ch != a.channel_of.end()) {
                    std::string out;
                    put16(out, ch->second);
                    put16(out, (uint16_t)n);
                    out.append((const char *)buf.data(), (size_t)n);
                    send_to(I.sock, a.client, out);
                } else {
                    unsigned char tx[12];
                    random_bytes(tx, sizeof tx);
                    Builder b(M_DATA, C_INDICATION, tx);
                    b.xor_addr(A_XOR_PEER_ADDRESS, from);
                    b.attr(A_DATA, std::string((const char *)buf.data(), (size_t)n));
                    send_to(I.sock, a.client, b.finish(""));
                }
                continue;
            }

            /* to the relay's own port: ChannelData, or a STUN message */
            std::string ck = key_of(from);
            if (n >= 4 && buf[0] >= 0x40 && buf[0] <= 0x7F) {
                auto it = I.allocs.find(ck);
                uint16_t num = get16(buf.data()), len = get16(buf.data() + 2);
                if (it == I.allocs.end() || (size_t)len + 4 > (size_t)n)
                    continue;
                auto c = it->second.channels.find(num);
                if (c != it->second.channels.end() && it->second.permissions.count(ip_of(c->second.first)))
                    sendto(it->second.relay, buf.data() + 4, len, 0, (const sockaddr *)&c->second.first, sizeof c->second.first);
                continue;
            }
            Msg m;
            if (!parse(buf.data(), (size_t)n, m))
                continue;

            if (m.method == M_BINDING && m.cls == C_REQUEST) {
                Builder b(M_BINDING, C_SUCCESS, m.txid);
                b.xor_addr(A_XOR_MAPPED_ADDRESS, from);
                send_to(I.sock, from, b.finish(""));
                continue;
            }
            if (m.method == M_SEND && m.cls == C_INDICATION) {
                auto it = I.allocs.find(ck);
                sockaddr_in peer;
                if (it == I.allocs.end() || !m.attrs.count(A_XOR_PEER_ADDRESS) || !m.attrs.count(A_DATA) ||
                    !xor_addr_of(m.attrs[A_XOR_PEER_ADDRESS], peer) || !it->second.permissions.count(ip_of(peer)))
                    continue;
                const std::string &d = m.attrs[A_DATA];
                sendto(it->second.relay, d.data(), d.size(), 0, (const sockaddr *)&peer, sizeof peer);
                continue;
            }
            if (m.cls != C_REQUEST)
                continue;

            /* every request but Binding needs the credentials */
            auto reply_error = [&](int code, const char *reason, bool with_nonce, const std::string &k) {
                Builder b(m.method, C_ERROR, m.txid);
                b.error(code, reason);
                if (with_nonce) {
                    b.attr(A_REALM, s_.realm);
                    b.attr(A_NONCE, I.nonce);
                }
                send_to(I.sock, from, b.finish(k));
            };
            if (key.empty() || !m.integrity_at || !m.attrs.count(A_USERNAME) || !m.attrs.count(A_REALM) || !m.attrs.count(A_NONCE)) {
                reply_error(401, "Unauthorized", true, "");
                continue;
            }
            if (m.attrs[A_USERNAME] != user || m.attrs[A_REALM] != s_.realm) {
                reply_error(401, "Unauthorized", true, "");
                continue;
            }
            {
                std::string head = m.raw.substr(0, m.integrity_at);
                size_t l = m.integrity_at - 20 + 24;
                head[2] = (char)(l >> 8);
                head[3] = (char)l;
                unsigned char mac[20];
                unsigned ml = 0;
                HMAC(EVP_sha1(), key.data(), (int)key.size(), (const unsigned char *)head.data(), head.size(), mac, &ml);
                if (m.attrs[A_MESSAGE_INTEGRITY].size() != 20 || CRYPTO_memcmp(mac, m.attrs[A_MESSAGE_INTEGRITY].data(), 20) != 0) {
                    reply_error(401, "Unauthorized", true, "");
                    continue;
                }
            }
            if (m.attrs[A_NONCE] != I.nonce) {
                reply_error(438, "Stale Nonce", true, "");
                continue;
            }

            auto it = I.allocs.find(ck);
            if (m.method == M_ALLOCATE) {
                if (it != I.allocs.end()) {
                    reply_error(437, "Allocation Mismatch", false, key);
                    continue;
                }
                const std::string &rt = m.attrs.count(A_REQUESTED_TRANSPORT) ? m.attrs[A_REQUESTED_TRANSPORT] : std::string();
                if (rt.size() != 4 || (unsigned char)rt[0] != 17) {
                    reply_error(442, "Unsupported Transport Protocol", false, key);
                    continue;
                }
                auto [fd, port] = free_port();
                if (fd < 0) {
                    reply_error(508, "Insufficient Capacity", false, key);
                    continue;
                }
                Allocation a;
                a.client = from;
                a.relay = fd;
                a.relay_port = port;
                int64_t life = ALLOC_DEFAULT;
                if (m.attrs.count(A_LIFETIME) && m.attrs[A_LIFETIME].size() == 4)
                    life = std::min<int64_t>(ALLOC_MAX, std::max<int64_t>(ALLOC_DEFAULT, (int64_t)get32((const unsigned char *)m.attrs[A_LIFETIME].data()) * 1000));
                a.expires = now + life;
                I.allocs[ck] = a;
                allocs_ = I.allocs.size();
                sockaddr_in relayed = I.public_ip;
                relayed.sin_port = htons((uint16_t)port);
                Builder b(M_ALLOCATE, C_SUCCESS, m.txid);
                b.xor_addr(A_XOR_RELAYED_ADDRESS, relayed);
                b.xor_addr(A_XOR_MAPPED_ADDRESS, from);
                b.u32(A_LIFETIME, (uint32_t)(life / 1000));
                send_to(I.sock, from, b.finish(key));
                continue;
            }
            if (it == I.allocs.end()) {
                reply_error(437, "Allocation Mismatch", false, key);
                continue;
            }
            Allocation &a = it->second;
            if (m.method == M_REFRESH) {
                int64_t life = ALLOC_DEFAULT;
                if (m.attrs.count(A_LIFETIME) && m.attrs[A_LIFETIME].size() == 4)
                    life = std::min<int64_t>(ALLOC_MAX, (int64_t)get32((const unsigned char *)m.attrs[A_LIFETIME].data()) * 1000);
                Builder b(M_REFRESH, C_SUCCESS, m.txid);
                b.u32(A_LIFETIME, (uint32_t)(life / 1000));
                std::string out = b.finish(key);
                if (life == 0)
                    drop(ck);
                else
                    a.expires = now + life;
                send_to(I.sock, from, out);
                continue;
            }
            if (m.method == M_CREATE_PERMISSION) {
                sockaddr_in peer;
                if (!m.attrs.count(A_XOR_PEER_ADDRESS) || !xor_addr_of(m.attrs[A_XOR_PEER_ADDRESS], peer)) {
                    reply_error(400, "Bad Request", false, key);
                    continue;
                }
                a.permissions[ip_of(peer)] = now + PERM;
                Builder b(M_CREATE_PERMISSION, C_SUCCESS, m.txid);
                send_to(I.sock, from, b.finish(key));
                continue;
            }
            if (m.method == M_CHANNEL_BIND) {
                sockaddr_in peer;
                const std::string &cn = m.attrs.count(A_CHANNEL_NUMBER) ? m.attrs[A_CHANNEL_NUMBER] : std::string();
                uint16_t num = cn.size() == 4 ? get16((const unsigned char *)cn.data()) : 0;
                if (num < 0x4000 || num > 0x7FFF || !m.attrs.count(A_XOR_PEER_ADDRESS) || !xor_addr_of(m.attrs[A_XOR_PEER_ADDRESS], peer)) {
                    reply_error(400, "Bad Request", false, key);
                    continue;
                }
                std::string pk = key_of(peer);
                auto bound = a.channels.find(num);
                auto other = a.channel_of.find(pk);
                if ((bound != a.channels.end() && key_of(bound->second.first) != pk) || (other != a.channel_of.end() && other->second != num)) {
                    reply_error(400, "Bad Request", false, key);
                    continue;
                }
                a.channels[num] = { peer, now + CHAN };
                a.channel_of[pk] = num;
                a.permissions[ip_of(peer)] = now + PERM;
                Builder b(M_CHANNEL_BIND, C_SUCCESS, m.txid);
                send_to(I.sock, from, b.finish(key));
                continue;
            }
            reply_error(400, "Bad Request", false, key);
        }
    }
}

} // namespace levee
