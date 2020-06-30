SHELL := /bin/bash
NAME := crypto
PKG := github.com/transferwise/$(NAME)

GO_LDFLAGS=-ldflags "-w $(CTIMEVAR)"
GO_LDFLAGS_STATIC=-ldflags "-w $(CTIMEVAR) -extldflags -static"

GO := go

all: clean build fmt lint staticcheck vet test

.PHONY: build
build: $(NAME)

$(NAME): $(wildcard *.go) $(wildcard */*.go)
	@echo "+ $@"
	$(GO) build -tags "$(BUILDTAGS)" ${GO_LDFLAGS} -o $(NAME) .

.PHONY: test
test: ## Runs the go tests
	@echo "+ $@"
	@$(GO) test -v -tags "$(BUILDTAGS) cgo" $(shell $(GO) list ./... | grep -v vendor)

.PHONY: fmt
fmt: ## Verifies all files have been `gofmt`ed.
	@echo "+ $@"
	@if [[ ! -z "$(gofmt -s -l . | grep -v '.pb.go:' | grep -v '.twirp.go:' | grep -v vendor | tee /dev/stderr)" ]]; then \
		exit 1; \
	fi

.PHONY: lint
lint: ## Verifies `golint` passes.
	@echo "+ $@"
	@if [[ ! -z "$(golint ./... | grep -v '.pb.go:' | grep -v '.twirp.go:' | grep -v vendor | tee /dev/stderr)" ]]; then \
		exit 1; \
	fi

.PHONY: vet
vet: ## Verifies `go vet` passes.
	@echo "+ $@"
	@if [[ ! -z "$($(GO) vet $(shell $(GO) list ./... | grep -v vendor) | tee /dev/stderr)" ]]; then \
		exit 1; \
	fi

.PHONY: staticcheck
staticcheck: ## Verifies `staticcheck` passes.
	@echo "+ $@"
	@if [[ ! -z "$(staticcheck $(shell $(GO) list ./... | grep -v vendor) | tee /dev/stderr)" ]]; then \
		exit 1; \
	fi

.PHONY: clean
clean: ## Cleanup any build binaries or packages.
	@echo "+ $@"
	$(RM) $(NAME)
