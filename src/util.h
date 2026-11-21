#pragma once

/* Small things every part of the Levee uses: the clock, randomness, the protocol's encodings as std::string, files written
 * whole or not at all, and JSON (jsoncpp, which Drogon brings). */

#include <json/json.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace levee {

int64_t wall_ms();

/* `len` random bytes; false if the system's source failed. */
bool random_bytes(unsigned char *out, size_t len);
/* 16 random bytes as base32 (26 characters): tokens and credentials. */
std::string random_token();

std::string base32(const unsigned char *in, size_t len);
std::string base64(const unsigned char *in, size_t len);
/* exactly `want` bytes, or false */
bool unbase64(std::string_view in, unsigned char *out, size_t want);
/* base64 of any length; false if malformed */
bool unbase64_any(std::string_view in, std::string &out);
bool unbase32(std::string_view in, unsigned char *out, size_t want);
std::string hex(const unsigned char *in, size_t len);
bool unhex(std::string_view in, unsigned char *out, size_t want);
std::string sha256_hex(std::string_view data);

/* The whole file, or false. */
bool read_file(const std::string &path, std::string &out);
/* Written to a temporary file, synced and renamed over `path`, so a crash leaves the old one or the new one. Mode 0600 when
 * `secret`. */
bool write_file(const std::string &path, std::string_view data, bool secret = false);

/* Strict JSON: one object, nothing after it. */
bool parse_object(std::string_view text, Json::Value &out);
/* Compact JSON. */
std::string to_json(const Json::Value &v);

} // namespace levee
