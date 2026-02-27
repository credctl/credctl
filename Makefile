APP_NAME := credctl
APP_BUNDLE := build/$(APP_NAME).app
BINARY := $(APP_BUNDLE)/Contents/MacOS/$(APP_NAME)
SIGNING_IDENTITY := Apple Development: mat@crzy.co.uk (DX4M4W436Y)

.PHONY: build clean install

build:
	@mkdir -p $(APP_BUNDLE)/Contents/MacOS
	@cp xcode/credctl/Info.plist $(APP_BUNDLE)/Contents/Info.plist
	@cp embedded.provisionprofile $(APP_BUNDLE)/Contents/embedded.provisionprofile
	CGO_ENABLED=1 go build -o $(BINARY) ./cmd/credctl
	@codesign --sign "$(SIGNING_IDENTITY)" --entitlements entitlements.plist --force $(APP_BUNDLE)
	@echo "Built: $(BINARY)"

clean:
	rm -rf build/

install: build
	@ln -sf $(CURDIR)/$(BINARY) /usr/local/bin/$(APP_NAME)
	@echo "Installed: /usr/local/bin/$(APP_NAME) -> $(BINARY)"
