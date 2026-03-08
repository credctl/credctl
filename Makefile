APP_NAME := credctl
APP_BUNDLE := build/$(APP_NAME).app
BINARY := $(APP_BUNDLE)/Contents/MacOS/$(APP_NAME)
SIGNING_IDENTITY ?= Developer ID Application: CRZY LTD (P7TXLAS2QY)

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS := -X github.com/credctl/credctl/internal/cli.Version=$(VERSION) \
           -X github.com/credctl/credctl/internal/cli.Commit=$(COMMIT)

.PHONY: build clean install package test test-integration coverage

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

coverage:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1
