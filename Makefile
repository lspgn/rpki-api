EXTENSION ?= 
DIST_DIR ?= dist/
GOOS ?= linux
ARCH ?= $(shell uname -m)
BUILDINFOSDET ?= 

DOCKER_REPO := lspgn/
NAME        := rpki-api
FLAG_VERSION  := $(shell git describe --tags $(git rev-list --tags --max-count=1))
BUILDINFOS    :=  ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS       := '-X main.version=$(FLAG_VERSION) -X main.buildinfos=$(BUILDINFOS)'

OUPUT := $(DIST_DIR)rpki-api-$(FLAG_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

.PHONY: vet
vet:
	go vet

.PHONY: test
test:
	go test

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)

.PHONY: build
build: prepare
	go build -ldflags $(LDFLAGS) -o $(OUPUT)
