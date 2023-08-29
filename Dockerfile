FROM rust:1.72 as builder
WORKDIR /usr/src/rsacracker
COPY . .
RUN --mount=type=cache,target=/usr/src/rsacracker/target cargo install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/rsacracker /usr/local/bin/rsacracker
WORKDIR /data
ENTRYPOINT ["rsacracker"]
