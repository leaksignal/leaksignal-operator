FROM rust:1.83.0-bullseye AS builder

WORKDIR /build

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo build --target x86_64-unknown-linux-gnu --release -p leaksignal-operator && mv /build/target/x86_64-unknown-linux-gnu/release/leaksignal-operator /build/target/leaksignal-operator

FROM debian:bullseye-slim AS run
WORKDIR /runtime

COPY --from=builder /build/target/leaksignal-operator /runtime/leaksignal-operator

RUN apt-get update && apt-get install libssl1.1 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/leaksignal-operator"]