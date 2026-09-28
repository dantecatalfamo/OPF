DEV := dev/run

.PHONY: build test dev dev-reset mock openbsd

build:
	go build -o opf ./cmd/opf

test:
	go vet ./...
	go test -race ./...

# Run against a scratch copy of dev/seed with system commands logged
# instead of executed.
dev: $(DEV)/root
	go run ./cmd/opf -dry -root $(DEV)/root -state $(DEV)/state -confirm-timeout 30s

$(DEV)/root:
	mkdir -p $(DEV)
	cp -R dev/seed $(DEV)/root

# The web UI against a mock backend: the real generators, parser and
# staging engine on a sample model, with commands logged instead of run.
# UI on http://localhost:5173.
mock:
	./scripts/mock.sh

dev-reset:
	rm -rf $(DEV)

openbsd:
	GOOS=openbsd GOARCH=amd64 go build -o opf.openbsd-amd64 ./cmd/opf
