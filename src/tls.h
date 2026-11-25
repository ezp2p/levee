#pragma once

/* The Levee's TLS certificate: <data_dir>/cert.pem and key.pem. leveed makes a self-signed one the first time if neither is
 * there; the operator may put their own there instead, or put a reverse proxy in front. Nothing depends on which: TLS only
 * carries what is sealed (the protocol's spec/09). */

#include <string>

namespace levee {

/* Make cert.pem and key.pem in `dir` unless both exist. false with the reason in `err` (also if only one exists). */
bool ensure_certificate(const std::string &dir, std::string &err);

} // namespace levee
