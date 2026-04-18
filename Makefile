BINARY = syn-probe

.PHONY: all clean

all: $(BINARY)-linux-amd64 $(BINARY)-linux-arm64

$(BINARY)-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $@ .

$(BINARY)-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $@ .

clean:
	rm -f $(BINARY)-linux-amd64 $(BINARY)-linux-arm64
