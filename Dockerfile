# leveed and leveectl as a container image (README.md, "With Docker").
#
#   docker compose up -d                          # with LEVEE_ADDRESS set
#   docker compose exec levee leveectl join       # the levee://… link to give your Puddle
#
# Everything the Levee keeps (levee.yaml, its key, its certificate, what waits for the Puddle) is in the /data volume.

FROM debian:trixie-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates \
      libssl-dev libjsoncpp-dev libyaml-cpp-dev uuid-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt ./
COPY patches patches
COPY src src
COPY third_party third_party
COPY tests tests
# Drogon is fetched and built here, at the release CMakeLists.txt names, and linked in
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build --parallel 4 --target leveed leveectl \
 && strip build/leveed build/leveectl

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 libjsoncpp26 libyaml-cpp0.8 libuuid1 zlib1g \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin levee \
 && mkdir /data && chown levee:levee /data && chmod 700 /data
COPY --from=build /src/build/leveed /src/build/leveectl /usr/local/bin/
COPY dist/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY levee.yaml.example /usr/local/share/levee/levee.yaml.example

USER levee
WORKDIR /data
ENV HOME=/data
VOLUME /data
# HTTPS (usually behind a reverse proxy), the relay's own UDP port, and the relayed ports
EXPOSE 8443 3478/udp 49160-49199/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
