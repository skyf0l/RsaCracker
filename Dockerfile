FROM rust:1.72 as builder
WORKDIR /usr/src/rsacracker
COPY . .
RUN --mount=type=cache,target=/usr/src/rsacracker/target cargo install --path .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/rsacracker /usr/local/bin/rsacracker
WORKDIR /data
ENTRYPOINT ["rsacracker"]
