build: 
	@go build -o bin/blocker

run: build
	@./bin/blocker

test:
	@go test -v ./...

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	--go-grpc_out=. --go-grpc_out=paths=source_relative \
	proto/*.proto

.PHONY: proto