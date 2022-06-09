default: build

dep: # Download required dependencies
	go mod tidy
	go mod vendor

build: fmtcheck
	go install ./...

fmtcheck: dep
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"