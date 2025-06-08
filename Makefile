build: 
	@go build -o bin/blocker

run: build
	@./bin/blocker

test:
	@go test -v ./...