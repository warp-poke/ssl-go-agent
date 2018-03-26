BUILD_DIR=build

CC=go build
GITHASH=$(shell git rev-parse HEAD)
DFLAGS=-race
CFLAGS=-X github.com/warp-poke/ssl-go-agent/cmd.githash=$(GITHASH)
CROSS=GOOS=linux GOARCH=amd64

rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
VPATH= $(BUILD_DIR)

.SECONDEXPANSION:

init:
	go get -u github.com/alecthomas/gometalinter
	gometalinter --install --update

dep:
	dep ensure

build: poke-ssl-agent.go $$(call rwildcard, ./cmd, *.go) $$(call rwildcard, ./core, *.go)
	$(CC) $(DFLAGS) -ldflags "$(CFLAGS)" -o $(BUILD_DIR)/poke-ssl-agent poke-ssl-agent.go

.PHONY: release
release: warp-poke.go $$(call rwildcard, ./cmd, *.go) $$(call rwildcard, ./core, *.go)
	$(CC) -ldflags "$(CFLAGS)" -o $(BUILD_DIR)/poke-ssl-agent poke-ssl-agent.go

.PHONY: dist
dist: warp-poke.go $$(call rwildcard, ./cmd, *.go) $$(call rwildcard, ./core, *.go)
	$(CROSS) $(CC) -ldflags "$(CFLAGS) -s -w" -o $(BUILD_DIR)/poke-ssl-agent poke-ssl-agent.go

.PHONY: lint
lint:
	@command -v gometalinter >/dev/null 2>&1 || { echo >&2 "gometalinter is required but not available please follow instructions from https://github.com/alecthomas/gometalinter"; exit 1; }
	gometalinter --deadline=180s --disable-all --enable=gofmt ./cmd/... ./core/... ./models/... ./
	gometalinter --deadline=180s --disable-all --enable=vet ./cmd/... ./core/... ./models/... ./
	gometalinter --deadline=180s --disable-all --enable=golint ./cmd/... ./core/... ./models/... ./
	gometalinter --deadline=180s --disable-all --enable=ineffassign ./cmd/... ./core/... ./models/... ./
	gometalinter --deadline=180s --disable-all --enable=misspell ./cmd/... ./core/... ./models/... ./
	gometalinter --deadline=180s --disable-all --enable=staticcheck ./cmd/... ./core/... ./models/... ./

.PHONY: format
format:
	gofmt -w -s ./cmd ./core ./models poke-ssl-agent.go

.PHONY: dev
dev: format lint build

.PHONY: clean
clean:
	rm -rf $BUILD_DIR
