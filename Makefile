VERSION=0.0.9
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION} "

all: isius

.PHONY: isius

isius: main.go
	go build $(LDFLAGS) -o isius main.go

linux: main.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o isius main.go

check:
	go test ./...

fmt:
	go fmt ./...

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin main
