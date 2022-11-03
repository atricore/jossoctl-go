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