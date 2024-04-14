
.PHONY: all
all: generate build

generate:
	cd xdpnater && \
		go generate -v

build:
	cd cli && \
		go build -v -o ../xdp-nater

run: all
	./xdp-nater run
