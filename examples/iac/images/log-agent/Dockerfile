FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/log-agent ./cmd/agent

FROM debian:12-slim
COPY --from=build /out/log-agent /usr/local/bin/log-agent
RUN useradd --system agent
USER agent
# reads /var/log on the node, which only root can
USER root
ENTRYPOINT ["/usr/local/bin/log-agent"]
