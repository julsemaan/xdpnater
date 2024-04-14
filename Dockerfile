FROM ubuntu:22.04

RUN apt update
RUN apt install -yqq make llvm clang linux-headers-$(uname -r) libc6-dev-i386 libbpf-dev ca-certificates

ADD https://go.dev/dl/go1.22.2.linux-amd64.tar.gz go.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz

ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /src

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN make all

COPY xdp-nater /usr/local/bin/xdp-nater

