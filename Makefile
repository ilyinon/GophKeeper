GOCACHE ?= $(shell go env GOCACHE)
GOPROXY ?= $(shell go env GOPROXY)
GOSUMDB ?= $(shell go env GOSUMDB)
GRPC_GATEWAY_DIR ?= $(shell GOPROXY=$(GOPROXY) GOSUMDB=$(GOSUMDB) go list -m -f '{{.Dir}}' github.com/grpc-ecosystem/grpc-gateway/v2)
.PHONY: proto swagger test functional cover build up

proto:
	protoc --proto_path=api/proto --proto_path=third_party/googleapis --proto_path=$(GRPC_GATEWAY_DIR) --go_out=. --go_opt=module=github.com/oilyin/gophkeeper --go-grpc_out=. --go-grpc_opt=module=github.com/oilyin/gophkeeper api/proto/gophkeeper/v1/gophkeeper.proto

swagger:
	mkdir -p .tools/bin docs/swagger
	GOCACHE=$(GOCACHE) GOPROXY=$(GOPROXY) GOSUMDB=$(GOSUMDB) go build -o .tools/bin/protoc-gen-openapiv2 github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2
	PATH="$(CURDIR)/.tools/bin:$(PATH)" protoc --proto_path=api/proto --proto_path=third_party/googleapis --proto_path=$(GRPC_GATEWAY_DIR) --openapiv2_out=docs/swagger --openapiv2_opt=allow_merge=true,merge_file_name=gophkeeper,json_names_for_fields=true api/proto/gophkeeper/v1/gophkeeper.proto

test:
	GOCACHE=$(GOCACHE) GOPROXY=$(GOPROXY) GOSUMDB=$(GOSUMDB) go test ./...

functional:
	PYTHONDONTWRITEBYTECODE=1 GOCACHE=$(GOCACHE) python3 -B -m unittest discover -s tests/functional -v

cover:
	GOCACHE=$(GOCACHE) GOPROXY=$(GOPROXY) GOSUMDB=$(GOSUMDB) go test ./... -coverprofile=coverage.out
	GOCACHE=$(GOCACHE) go tool cover -func=coverage.out

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) GOPROXY=$(GOPROXY) GOSUMDB=$(GOSUMDB) go build -o bin/gophkeeper-server ./cmd/gophkeeper-server
	GOCACHE=$(GOCACHE) GOPROXY=$(GOPROXY) GOSUMDB=$(GOSUMDB) go build -o bin/gophkeeper-client ./cmd/gophkeeper-client

up:
	docker-compose up -d
