# tah — typed activity history POC
GO ?= go

.PHONY: build test vet install demo clean bootstrap
build:
	$(GO) build -o bin/tah ./cmd/tah
test:
	$(GO) test ./...
vet:
	$(GO) vet ./...
install: build
	install -m 0755 bin/tah /usr/local/bin/tah
# End-to-end demo on the bundled fixture (no macOS needed).
demo: build
	@rm -f /tmp/tah-demo.db
	@cat internal/store/testdata/eslogger_sample.ndjson | ./bin/tah collect --db /tmp/tah-demo.db --stdin
	@./bin/tah report --db /tmp/tah-demo.db --since 100000h
# macOS first-run setup (Go, build, Presidio). See scripts/bootstrap.sh.
bootstrap:
	./scripts/bootstrap.sh
clean:
	rm -rf bin *.db *.db-wal *.db-shm
