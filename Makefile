DEV := dev/run

.PHONY: build test dev dev-reset openbsd

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

dev-reset:
	rm -rf $(DEV)

openbsd:
	GOOS=openbsd GOARCH=amd64 go build -o opf.openbsd-amd64 ./cmd/opf
