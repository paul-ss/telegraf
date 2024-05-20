FROM ubuntu:jammy AS build

ARG GOLANG_VERSION=1.22.3
ARG GOOS=linux
ARG GOARCH=amd64

RUN apt update && apt install --yes make ca-certificates git curl && \
  /usr/bin/git config --global --add safe.directory /data && \
  curl -L https://go.dev/dl/go${GOLANG_VERSION}.${GOOS}-${GOARCH}.tar.gz | tar -C /usr/local -xvzf -

# FROM --platform=linux/arm64 golang:1.22.3-bullseye AS build

WORKDIR /data

COPY . .

ENV PATH="/usr/local/go/bin:$PATH"

RUN go build -o telegraf ./cmd/telegraf

FROM ubuntu:jammy

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iputils-ping snmp procps lm-sensors libcap2-bin telnet curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /data/telegraf /usr/local/bin/telegraf

CMD ["telegraf"]