#include "util.h"

#include <puddle_proto.h>

#include <openssl/rand.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>

namespace levee {

int64_t wall_ms()
{
    return (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

bool random_bytes(unsigned char *out, size_t len)
{
    return RAND_bytes(out, (int)len) == 1;
}

std::string random_token()
{
    unsigned char raw[16];
    if (!random_bytes(raw, sizeof raw))
        return "";
    return base32(raw, sizeof raw);
}

std::string base32(const unsigned char *in, size_t len)
{
    std::string out((len * 8 + 4) / 5 + 1, '\0');
    out.resize(pp_base32_encode(in, len, out.data(), out.size()));
    return out;
}

std::string base64(const unsigned char *in, size_t len)
{
    std::string out((len + 2) / 3 * 4 + 1, '\0');
    out.resize(pp_base64_encode(in, len, out.data(), out.size()));
    return out;
}

bool unbase64(std::string_view in, unsigned char *out, size_t want)
{
    std::string s(in), buf(want + 3, '\0');
    size_t n = 0;
    if (pp_base64_decode(s.c_str(), (unsigned char *)buf.data(), buf.size(), &n) != 0 || n != want)
        return false;
    memcpy(out, buf.data(), want);
    return true;
}

bool unbase64_any(std::string_view in, std::string &out)
{
    std::string s(in);
    out.assign(s.size() / 4 * 3 + 3, '\0');
    size_t n = 0;
    if (pp_base64_decode(s.c_str(), (unsigned char *)out.data(), out.size(), &n) != 0)
        return false;
    out.resize(n);
    return true;
}

bool unbase32(std::string_view in, unsigned char *out, size_t want)
{
    return pp_base32_decode(std::string(in).c_str(), out, want) == 0;
}

std::string hex(const unsigned char *in, size_t len)
{
    std::string out(2 * len + 1, '\0');
    pp_hex_encode(in, (unsigned)len, out.data());
    out.resize(2 * len);
    return out;
}

bool unhex(std::string_view in, unsigned char *out, size_t want)
{
    return in.size() == 2 * want && pp_hex_decode(std::string(in).c_str(), out, want) == 0;
}

std::string sha256_hex(std::string_view data)
{
    char h[65];
    pp_sha256_hex(data.data(), data.size(), h);
    return h;
}

bool read_file(const std::string &path, std::string &out)
{
    FILE *f = fopen(path.c_str(), "rb");
    if (!f)
        return false;
    out.clear();
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        out.append(buf, n);
    bool ok = !ferror(f);
    fclose(f);
    return ok;
}

bool write_file(const std::string &path, std::string_view data, bool secret)
{
    std::string tmp = path + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, secret ? 0600 : 0644);
    if (fd < 0)
        return false;
    size_t at = 0;
    while (at < data.size()) {
        ssize_t w = write(fd, data.data() + at, data.size() - at);
        if (w <= 0) {
            close(fd);
            unlink(tmp.c_str());
            return false;
        }
        at += (size_t)w;
    }
    bool ok = fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (!ok || rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool parse_object(std::string_view text, Json::Value &out)
{
    Json::CharReaderBuilder b;
    b["strictRoot"] = true;
    b["allowComments"] = false;
    b["rejectDupKeys"] = true;
    b["failIfExtra"] = true;
    std::unique_ptr<Json::CharReader> r(b.newCharReader());
    std::string errs;
    Json::Value v;
    if (!r->parse(text.data(), text.data() + text.size(), &v, &errs) || !v.isObject())
        return false;
    out = std::move(v);
    return true;
}

std::string to_json(const Json::Value &v)
{
    Json::StreamWriterBuilder b;
    b["indentation"] = "";
    b["emitUTF8"] = true;
    return Json::writeString(b, v);
}

} // namespace levee
