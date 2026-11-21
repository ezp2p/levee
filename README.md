# levee

The public side of one Puddle. Your Puddle connects **out** to its Levee and needs no open ports; everyone else reaches
your Puddle at the Levee's address:

- **Friends, phones and new contacts** reach your Puddle at the Levee's address, which stays the same when your home
  network changes.
- **While your Puddle is on**, what they send passes straight through.
- **While it is off**, what they send that needs no answer (messages, profiles, address changes, friend requests) waits at
  the Levee and is handed over when your Puddle comes back. The sender is told it arrived (a custody receipt the Levee signs).
- **What your Puddle sends** goes out through the Levee too, so nobody you talk to learns your home address.
- **Files you send** wait at the Levee, encrypted under keys it never sees, until each friend has fetched them; then they
  are deleted. A friend who asks again later asks your Puddle, which puts the file there again.
- **Calls** go through the Levee's relay (a small TURN server), since nothing can reach your Puddle by UDP either.

**Your chats stay on your Puddle.** Everything the Levee carries is sealed end to end, or encrypted under a key it doesn't
have, and it signs nothing in your name. It does see what any carrier sees: who talks to your Puddle, when and how much.
Run it yourself, or have someone you trust run it.

One Levee serves one Puddle. It is a headless daemon with a config file and a data folder: no database, no app.

## The protocol

A Levee speaks the Puddle Protocol (`ezp2p/protocol`, here as the submodule `third_party/protocol`): part 06 is the
Levee's own, and it uses the protocol's library, **libpuddle-proto** (`third_party/protocol/lib`), for ids, key chains,
signatures, receipts and sealing, as Puddle and Pond do.

## Setting up

You need a server with a public address (a VPS will do), and a name for it (`levee.example.org`).

### With Docker

```sh
git clone https://github.com/ezp2p/levee && cd levee
LEVEE_ADDRESS=levee.example.org docker compose up -d
docker compose exec levee leveectl join
```

`join` prints a link, `levee://levee.example.org?id=…&k=…&token=…`. In your Puddle: **Settings → Levee**, paste it. The
link is good once. From then on your Puddle's address is the Levee's, and your friends are told so.

`compose.yaml` publishes HTTPS on `127.0.0.1:8443` for a reverse proxy on the same server, and the relay's UDP ports
directly (`3478` and `49160-49199`), since a reverse proxy doesn't carry UDP. Open those UDP ports in the server's
firewall.

### Behind a reverse proxy

Any certificate works (Let's Encrypt, the proxy's own): the protocol never looks at certificates. Forward everything for the
Levee's name to leveed's HTTPS port, and let requests wait: your Puddle holds one open for up to 25 seconds, and a friend's
request waits up to 30 seconds for your Puddle's answer.

Apache:

```apache
<VirtualHost *:443>
    ServerName levee.example.org
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.org/privkey.pem

    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    ProxyPreserveHost On
    ProxyTimeout 75
    # a container by name: look the name up again now and then (Apache 2.4.60+), or it keeps the old address after a recreate
    ProxyPass        / https://levee:8443/ nocanon address_ttl=30
    ProxyPassReverse / https://levee:8443/
</VirtualHost>
```

nginx: `proxy_pass https://127.0.0.1:8443;` with `proxy_read_timeout 75s;` and `proxy_request_buffering off;`.

### Without Docker

Build (needs CMake, a C++20 compiler, OpenSSL 3, jsoncpp and yaml-cpp; Drogon is fetched and built the first time):

```sh
git clone --recurse-submodules https://github.com/ezp2p/levee && cd levee
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel 4
```

Copy `levee.yaml.example` to `levee.yaml`, set `address` and `data_dir`, then:

```sh
build/leveectl -c levee.yaml join
build/leveed -c levee.yaml
```

## levee.yaml

| Setting | Default | |
|---|---|---|
| `listen`, `port` | `0.0.0.0`, `8443` | where leveed takes HTTPS |
| `address` | (required) | how others reach your Puddle, `host[:port]`; what its links say |
| `data_dir` | (required) | the Levee's key, certificate and everything it keeps |
| `threads` | 2 | |
| `spool.max_mb`, `spool.keep_days` | 1024, 30 | what waits for your Puddle while it is off; the oldest goes first |
| `files.max_mb`, `files.total_mb`, `files.keep_days` | 100, 4096, 30 | files left for friends |
| `turn.port`, `turn.relay_ports`, `turn.public_ip` | 3478, `49160-49199`, the address's host | the relay for calls (UDP); `turn: false` turns it off |

## leveectl

| | |
|---|---|
| `leveectl init` | make the key and certificate; says the Levee's id |
| `leveectl join` | a link for your Puddle to join with (good once) |
| `leveectl join --replace` | the same, when another Puddle is joined: the one that joins with it replaces it, and everything kept for the old one goes |
| `leveectl status` | who is joined, how much waits |

## The data folder

Plain files, nothing else: `levee.key` (keep it: a new key is a new Levee, and your friends would no longer believe its
custody receipts until your Puddle tells them), `cert.pem`/`key.pem`, `join.json`, `peers.json` (your friends' public keys,
so strangers get nowhere), `spool/` and `files/`.

## Tests

`ctest --test-dir build`: `store` (the data folder), `turn` (the relay, as a TURN client and a peer meet it) and `levee`
(leveed as a Puddle and its friends meet it: joining, spooling, passing through, sending, files, leaving).
