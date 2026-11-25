# levee

The public side of one Puddle. Your Puddle connects **out** to its Levee and needs no open ports. Everyone else
reaches your Puddle at the Levee's address. While your Puddle is on, what they send passes straight through. While it
is off, what needs no answer waits at the Levee and is handed over when it comes back. Everything the Levee carries is
sealed end to end, and it signs nothing in your name.

One Levee serves one Puddle. It is a headless daemon with a config file and a data folder: no database, no app.

## Docs

On the website wiki:

- [Installation](https://www.ezp2p.org/wiki/levee/installation/): with Docker or building it yourself, its ports, and
  running behind a reverse proxy (Apache and nginx)
- [Binding a Levee](https://www.ezp2p.org/wiki/levee/binding/): joining it to your Puddle
- [Reference](https://www.ezp2p.org/wiki/levee/reference/): what it does, every setting in `levee.yaml`, every
  `leveectl` command, the data folder and the tests
- [Protocol part 06](https://www.ezp2p.org/wiki/protocol/levee/): what a Levee says on the wire, and the
  [decisions](https://www.ezp2p.org/wiki/decisions/levee/) behind it

Work still to do is on the [project board](https://github.com/orgs/ezp2p/projects/1).

## Quick start

```sh
git clone https://github.com/ezp2p/levee && cd levee
LEVEE_ADDRESS=levee.example.org docker compose up -d
docker compose exec levee leveectl join     # a levee:// link: paste it into your Puddle, Settings → Levee
```

## Build and test

Needs CMake, a C++20 compiler, OpenSSL 3, jsoncpp and yaml-cpp. Drogon is fetched and built the first time. The
protocol's library, libpuddle-proto, comes from the submodule `third_party/protocol`.

```sh
git clone --recurse-submodules https://github.com/ezp2p/levee && cd levee
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel 4
ctest --test-dir build                       # add -DPUDDLED=<path> at configure time for the end-to-end test
```
