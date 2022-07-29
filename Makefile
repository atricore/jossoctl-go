default: build

dep: # Download required dependencies
	go mod tidy
	go mod vendor

build: fmtcheck
	:

fmtcheck: dep
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"