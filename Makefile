TEST?=./...
NAME?=matt
.DEFAULT_GOAL := ci
VERSION?=0.0.5
FFI_VERSION=0.3.15

ci:: deps clean bin test

bin:
	go build -o build/$(NAME)

clean:
	rm -rf build

deps:
	@echo "--- 🐿  Fetching build dependencies "
	cd /tmp; \
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28 ;\
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2 ;\
	cd -

test: deps
	go test $(TEST)

proto:
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		io_pact_plugin/pact_plugin.proto

install_local: bin write_config
	@echo "Creating a local phony plugin install so we can test locally"
	mkdir -p ~/.pact/plugins/$(NAME)-$(VERSION)
	cp ./build/$(NAME) ~/.pact/plugins/$(NAME)-$(VERSION)/
	cp pact-plugin.json ~/.pact/plugins/$(NAME)-$(VERSION)/

write_config:
	@cp pact-plugin.json pact-plugin.json.new
	@cat pact-plugin.json | jq '.version = "'$(VERSION)'" | .name = "'$(NAME)'"' | tee pact-plugin.json.new
	@mv pact-plugin.json.new pact-plugin.json

.PHONY: bin test clean write_config
