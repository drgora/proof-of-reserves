# syntax=docker/dockerfile:1
# Builds the proof-of-reserves Rust services into one image.
#
# Base = Debian *trixie* (glibc 2.41 / GCC 14), NOT bookworm: noir-rs ships a
# PREBUILT Barretenberg object that references glibc >=2.38 symbols
# (`__isoc23_strtoul`, libstdc++ `_M_replace_cold`); bookworm's glibc 2.36 fails
# to link them. Build and runtime must both be trixie.
#
# NOTE: por-zk pulls noir-rs (git) + Barretenberg; needs network egress.

FROM rust:1-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake clang ninja-build libssl-dev pkg-config \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY por ./por
COPY por-zk ./por-zk
# Non-ZK crate: just the separate notary.
RUN cargo build --release --manifest-path por/Cargo.toml --bin zerion_notary
# ZK crate: the independent verifier + the SIWE-gated prover (heavy).
RUN cargo build --release --manifest-path por-zk/Cargo.toml --bin por_verifier --bin por_service

FROM debian:trixie-slim AS runtime
# Runtime libs (incl. Barretenberg's). If a binary fails at startup on a missing
# .so, add it to this list.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 libstdc++6 libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/por/target/release/zerion_notary   /usr/local/bin/zerion_notary
COPY --from=build /src/por-zk/target/release/por_verifier  /usr/local/bin/por_verifier
COPY --from=build /src/por-zk/target/release/por_service   /usr/local/bin/por_service
CMD ["zerion_notary"]
