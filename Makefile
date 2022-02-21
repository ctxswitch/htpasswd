# VERSION := $(shell git describe --tags)
# BUILD := $(shell git rev-parse --short HEAD)
# PROJECT := $(shell basename "$(PWD)")
# LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"
MAKEFLAGS += --silent

test:
	go test -race -cover ./...

clean:
	rm bin/$(PROJECT)
	go clean
