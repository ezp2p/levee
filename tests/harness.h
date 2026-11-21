#pragma once

/* What the Levee's tests share: one HTTPS request at a time (the certificate not checked), identities made from fixed seeds
 * with libpuddle-proto, and leveed and leveectl run as programs, the way an operator and a Puddle meet them. */

#include "util.h"

#include <puddle_proto.h>

#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

extern char **environ;

static int failures;
#define CHECK(cond)                                                                                                                        \
    do {                                                                                                                                   \
        if (!(cond)) {                                                                                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                                                \
            failures++;                                                                                                                    \
        }                                                                                                                                  \
    } while (0)

inline int finish(const char *name)
{
    if (failures)
        fprintf(stderr, "%s: %d failure(s)\n", name, failures);
    else
        printf("%s: all good\n", name);
    return failures ? 1 : 0;
}

inline unsigned free_port(int type = SOCK_STREAM)
{
    int fd = socket(AF_INET, type, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd, (sockaddr *)&a, sizeof a);
    socklen_t l = sizeof a;
    getsockname(fd, (sockaddr *)&a, &l);
    close(fd);
    return ntohs(a.sin_port);
}

inline bool until(const std::function<bool()> &cond, int ms = 10000)
{
    for (int i = 0; i < ms / 20; i++) {
        if (cond())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return cond();
}

inline bool port_open(unsigned port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    bool ok = connect(fd, (sockaddr *)&a, sizeof a) == 0;
    close(fd);
    return ok;
}

struct Reply {
    int status = -1;
    std::string body;
    std::map<std::string, std::string> headers; /* lower-case names */
    std::string h(const std::string &name) const
    {
        auto it = headers.find(name);
        return it == headers.end() ? "" : it->second;
    }
};

inline Reply https(unsigned port, const std::string &method, const std::string &target, const std::string &body,
                   const std::vector<std::string> &headers = {}, int timeout_s = 40)
{
    Reply r;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (sockaddr *)&a, sizeof a) != 0) {
        close(fd);
        return r;
    }
    timeval tv = { timeout_s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) == 1) {
        std::string req = method + " " + target + " HTTP/1.1\r\nHost: x\r\nContent-Length: " + std::to_string(body.size()) +
                          "\r\nConnection: close\r\n";
        for (auto &h : headers)
            req += h + "\r\n";
        req += "\r\n" + body;
        SSL_write(ssl, req.data(), (int)req.size());
        std::string all;
        char buf[16384];
        int n;
        while ((n = SSL_read(ssl, buf, sizeof buf)) > 0)
            all.append(buf, (size_t)n);
        if (sscanf(all.c_str(), "HTTP/1.1 %d", &r.status) != 1)
            r.status = -1;
        size_t b = all.find("\r\n\r\n");
        r.body = b == std::string::npos ? "" : all.substr(b + 4);
        for (size_t at = all.find("\r\n"); at != std::string::npos && at < b; at = all.find("\r\n", at + 2)) {
            std::string line = all.substr(at + 2, all.find("\r\n", at + 2) - at - 2);
            size_t c = line.find(':');
            if (c == std::string::npos)
                continue;
            std::string name = line.substr(0, c);
            for (char &ch : name)
                ch = (char)tolower((unsigned char)ch);
            r.headers[name] = line.substr(line.find_first_not_of(' ', c + 1) == std::string::npos ? line.size() : line.find_first_not_of(' ', c + 1));
        }
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return r;
}

/* ---- identities: a Puddle's key chain from fixed seeds ---- */

struct Ident {
    unsigned char sign[32], roll[32], enc_sk[32], enc_pk[32];
    unsigned char pub[32];
    std::string id, chain;
    pp_signer signer;

    explicit Ident(int n)
    {
        for (int i = 0; i < 32; i++) {
            sign[i] = (unsigned char)(n * 3 + i);
            roll[i] = (unsigned char)(n * 5 + 2 * i + 1);
        }
        unsigned char ikm[32];
        for (int i = 0; i < 32; i++)
            ikm[i] = (unsigned char)(n * 7 + i + 9);
        pp_x25519_derive(ikm, 32, enc_sk, enc_pk);
        pp_ed25519_public(sign, pub);
        unsigned char rp[32], commit[32];
        char ch[65], idb[PP_ID_LEN + 1];
        pp_ed25519_public(roll, rp);
        pp_sha256(rp, 32, commit);
        pp_sha256_hex(rp, 32, ch);
        pp_user_id(pub, commit, idb);
        id = idb;
        std::string rec = "{\"type\":\"identity.inception\",\"seq\":0,\"signing\":\"" + levee::base64(pub, 32) + "\",\"encryption\":\"" +
                          levee::base64(enc_pk, 32) + "\",\"next\":\"" + ch + "\",\"ts\":1760000000000}";
        unsigned char sig[64];
        pp_ed25519_sign(sign, rec.data(), rec.size(), sig);
        chain = "{\"record\":" + rec + ",\"sig\":\"" + levee::base64(sig, 64) + "\"}\n";
        pp_signer_from_seed(&signer, id.c_str(), sign);
    }
    Ident(const Ident &) = delete;

    /* X-Puddle-Signature (or the same in another header) for a request to `to` */
    std::string signature(const std::string &method, const std::string &target, const std::string &body, const std::string &to) const
    {
        char out[PP_REQSIG_MAX];
        if (pp_reqsig_sign(&signer, method.c_str(), target.c_str(), body.data(), body.size(), to.c_str(), 0, nullptr, out, sizeof out) != 0)
            return "";
        return out;
    }
};

/* ---- leveed ---- */

inline pid_t spawn(const std::vector<std::string> &argv, const std::string &log)
{
    std::vector<char *> a;
    for (auto &s : argv)
        a.push_back((char *)s.c_str());
    a.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 1, log.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    posix_spawn_file_actions_adddup2(&fa, 1, 2);
    pid_t pid = 0;
    if (posix_spawn(&pid, a[0], &fa, nullptr, a.data(), environ) != 0)
        pid = 0;
    posix_spawn_file_actions_destroy(&fa);
    return pid;
}

inline std::string run_out(const std::string &cmd)
{
    std::string out;
    FILE *p = popen(cmd.c_str(), "r");
    if (!p)
        return out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0)
        out.append(buf, n);
    pclose(p);
    return out;
}

struct LeveeProc {
    std::string dir, yaml;
    unsigned port = 0, turn_port = 0;
    pid_t pid = 0;

    explicit LeveeProc(const std::string &extra = "")
    {
        char tmpl[] = "/tmp/levee-test-XXXXXX";
        dir = mkdtemp(tmpl);
        port = free_port();
        turn_port = free_port(SOCK_DGRAM);
        yaml = dir + "/levee.yaml";
        FILE *f = fopen(yaml.c_str(), "w");
        fprintf(f, "listen: 127.0.0.1\nport: %u\naddress: 127.0.0.1:%u\ndata_dir: %s/data\nthreads: 2\nturn:\n  port: %u\n  relay_ports: %u-%u\n  public_ip: 127.0.0.1\n%s",
                port, port, dir.c_str(), turn_port, 41000 + port % 1000 * 20, 41000 + port % 1000 * 20 + 9, extra.c_str());
        fclose(f);
    }
    std::string ctl(const std::string &args) const { return run_out(std::string(LEVEE_BIN_DIR) + "/leveectl -c " + yaml + " " + args + " 2>&1"); }
    bool start()
    {
        pid = spawn({ std::string(LEVEE_BIN_DIR) + "/leveed", "-c", yaml }, dir + "/leveed.log");
        return pid && until([&] { return port_open(port); });
    }
    void stop()
    {
        if (pid) {
            kill(pid, SIGTERM);
            int st;
            waitpid(pid, &st, 0);
            pid = 0;
        }
    }
    ~LeveeProc()
    {
        stop();
        if (!getenv("LEVEE_KEEP"))
            std::filesystem::remove_all(dir);
        else
            fprintf(stderr, "kept %s\n", dir.c_str());
    }
};
