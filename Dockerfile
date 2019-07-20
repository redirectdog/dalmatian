FROM alpine:3.9 AS builder
RUN apk add --no-cache rust cargo openssl-dev
WORKDIR /usr/src/dalmatian
COPY Cargo.* ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.9
RUN apk add --no-cache libgcc openssl
COPY --from=builder /usr/src/dalmatian/target/release/dalmatian /usr/bin/
CMD ["dalmatian"]
