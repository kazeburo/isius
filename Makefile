VERSION=0.0.1
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION} "

all: isius

.PHONY: isius

isius: main.go check*.go
	go build $(LDFLAGS) -o isius  check*.go main.go

linux: main.go check*.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o isius  check*.go main.go

check:
	go test ./...

fmt:
	go fmt ./...

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin main
