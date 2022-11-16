NAMES=iamtf josso
VERSION=$(shell git describe --tags --always --dirty)

PLATFORMS=darwin linux windows openbsd
ARCHITECTURES=amd64 386 arm64 arm

default: build

dep: # Download required dependencies
	go mod tidy
	go mod vendor


install:
	go install ./...

build: fmtcheck
	go install ./...
	

fmtcheck: dep
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

dist:
	$(foreach NAME,$(NAMES),\
		$(foreach GOOS,$(PLATFORMS),\
			$(foreach GOARCH,$(ARCHITECTURES),\
				$(shell export GOOS=$(GOOS);\
					export BINARY=$(NAME)ctl;\
					export GOARCH=$(GOARCH);\
					OUT_DIR='./.tmp/$(NAME)/$(GOOS)/$(GOARCH)/$(VERSION)';\
					go build -v -o $${OUT_DIR%.}/$(BINARY) ./$(NAME)ctl; \
					if test -f $${OUT_DIR}/$${BINARY} ; then cd $${OUT_DIR} ; zip -q ../../../$${BINARY}-$(GOOS)-$(GOARCH)-$(VERSION).zip $${BINARY} ; fi; \
					if test -f $${OUT_DIR}/$${BINARY}.exe ; then cd $${OUT_DIR} ; zip -q ../../../$${BINARY}-$(GOOS)-$(GOARCH)-$(VERSION).zip $${BINARY}.exe ; fi \
					))))