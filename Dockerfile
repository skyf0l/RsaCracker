FROM rust:1.67 as builder
RUN apt-get update && apt-get install -y clang && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/rsacracker
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/rsacracker /usr/local/bin/rsacracker
WORKDIR /data
ENTRYPOINT ["rsacracker"]
