APP_NAME := credctl
APP_BUNDLE := build/$(APP_NAME).app
BINARY := $(APP_BUNDLE)/Contents/MacOS/$(APP_NAME)
SIGNING_IDENTITY ?= Developer ID Application: CRZY LTD (P7TXLAS2QY)

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -X github.com/credctl/credctl/internal/cli.Version=$(VERSION) \
           -X github.com/credctl/credctl/internal/cli.Commit=$(COMMIT)

.PHONY: build build-linux build-linux-arm64 clean install package test test-integration test-linux coverage

build:
	@mkdir -p $(APP_BUNDLE)/Contents/MacOS
	@cp xcode/credctl/Info.plist $(APP_BUNDLE)/Contents/Info.plist
	@cp embedded.provisionprofile $(APP_BUNDLE)/Contents/embedded.provisionprofile
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/credctl
	@codesign --sign "$(SIGNING_IDENTITY)" \
		--entitlements entitlements.plist \
		--options runtime \
		--force $(APP_BUNDLE)
	@echo "Built: $(BINARY)"

package: build
	@mkdir -p dist
	@tar -czf dist/$(APP_NAME)-$(VERSION)-darwin-arm64.tar.gz -C build $(APP_NAME).app
	@cd dist && shasum -a 256 $(APP_NAME)-$(VERSION)-darwin-arm64.tar.gz > checksums.txt
	@echo "Package: dist/$(APP_NAME)-$(VERSION)-darwin-arm64.tar.gz"

clean:
	rm -rf build/ dist/

install: build
	@ln -sf $(CURDIR)/$(BINARY) /usr/local/bin/$(APP_NAME)
	@echo "Installed: /usr/local/bin/$(APP_NAME) -> $(BINARY)"

test:
	go test -race -count=1 ./...

test-integration:
	go test -race -count=1 -tags=integration ./...

build-linux:
	@mkdir -p build
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o build/$(APP_NAME)-linux-amd64 ./cmd/credctl
	@echo "Built: build/$(APP_NAME)-linux-amd64"

build-linux-arm64:
	@mkdir -p build
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o build/$(APP_NAME)-linux-arm64 ./cmd/credctl
	@echo "Built: build/$(APP_NAME)-linux-arm64"

test-linux:
	GOOS=linux go test -race -count=1 ./...

coverage:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1
