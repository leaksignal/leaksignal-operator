FROM lukemathwalker/cargo-chef:0.1.62-rust-1.74-slim-buster AS planner
WORKDIR /plan

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

FROM lukemathwalker/cargo-chef:0.1.62-rust-1.74-slim-buster AS builder
ARG BUILD_MODE=release

WORKDIR /build
RUN apt-get update && apt-get install cmake -y

COPY --from=planner /plan/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json -p leaksignal-operator

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo build --release -p leaksignal-operator && mv /build/target/release/leaksignal-operator /build/target/leaksignal-operator

FROM debian:buster-slim
WORKDIR /runtime

COPY --from=builder /build/target/leaksignal-operator /runtime/leaksignal-operator

RUN apt-get update && apt-get install libssl1.1 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/leaksignal-operator"]
