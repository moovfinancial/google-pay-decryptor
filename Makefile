

PLATFORM=$(shell uname -s | tr '[:upper:]' '[:lower:]')
PWD := $(shell pwd)

ifndef VERSION
	VERSION := $(shell git describe --tags --abbrev=0)
endif

COMMIT_HASH :=$(shell git rev-parse --short HEAD)
DEV_VERSION := dev-${COMMIT_HASH}

USERID := $(shell id -u $$USER)
GROUPID:= $(shell id -g $$USER)

export PROJECT_ROOT := $(PWD)
export GOPRIVATE=github.com/moovfinancial

all: install update build

.PHONY: install
install:
	go mod tidy
	go install github.com/markbates/pkger/cmd/pkger@latest
	go mod vendor

update:
	go mod vendor

build:
	go build -ldflags "-X github.com/moovfinancial/google-pay-decryptor.Version=${VERSION}" -o bin/google-pay-decryptor github.com/moovfinancial/google-pay-decryptor/cmd/google-pay-decryptor


.PHONY: check
check: test

# Extra utilities not needed for building

run: update build
	./bin/google-pay-decryptor

test: update
	go test -cover github.com/moovfinancial/google-pay-decryptor/...

.PHONY: clean
clean:
ifeq ($(OS),Windows_NT)
	@echo "Skipping cleanup on Windows, currently unsupported."
else
	@rm -rf cover.out coverage.txt misspell* staticcheck*
	@rm -rf ./bin/
endif