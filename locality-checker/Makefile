.PHONY: build
build: bin/locality-checker

.PHONY: bin/locality-checker
bin/locality-checker:
	go build -v -o $@ .

.PHONY: mod/vendor
mod/vendor:
	$(call target)
	go mod vendor -v
