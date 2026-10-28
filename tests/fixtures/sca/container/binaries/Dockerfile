# Builds the binaries in this directory (gzipped): Go 1.21.0 with gopkg.in/yaml.v2 replaced by v2.2.7,
# and Rust with smallvec 1.6.0 through cargo auditable; the ground truth is `go version -m` and
# `rust-audit-info`. tests/test_sca_container.py rebuilds it live.
FROM golang:1.21.0-bookworm AS go
WORKDIR /src
COPY go/ .
RUN go mod tidy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/svc-go . && go version -m /out/svc-go > /out/go-version-m.txt

FROM rust:1.82-bookworm AS rust
RUN cargo install cargo-auditable --version 0.6.6 --locked && cargo install rust-audit-info --version 0.5.4 --locked
WORKDIR /src
COPY rust/ .
RUN cargo generate-lockfile && cargo auditable build --release && strip target/release/svc \
    && cp target/release/svc /out-svc-rust && rust-audit-info /out-svc-rust > /audit.json

FROM debian:12-slim
COPY --from=go /out/svc-go /usr/local/bin/svc-go
COPY --from=go /out/go-version-m.txt /truth/go-version-m.txt
COPY --from=rust /out-svc-rust /usr/local/bin/svc-rust
COPY --from=rust /audit.json /truth/rust-audit-info.json
