# 查找 api 目录下所有的 proto 文件。
API_PROTO_FILES=$(shell find api -not -path "api/third_party/*" -name *.proto)

# 查找 internal/conf 目录下所有的 proto 文件。
INTERNAL_CONF_PROTO_FILES=$(shell find internal/conf -name *.proto)

# 日志文件存储目录。
LOG_DIR=logs

# Docker 镜像名称，格式为：用户名/项目名。
IMAGE_NAME=fsyyft/kratos-layout

# 获取当前日期，格式为年月日（YYMMDD）。
BUILD_DATE=$(shell date +%y%m%d)

# 编译时间。
BUILD_TIME=$(shell date "+%Y%m%d%H%M%S")

# 获取 git 提交哈希值。
GIT_COMMIT=$(shell git rev-parse HEAD)

# 获取 GOPATH 和 GOROOT。
BUILD_GOPATH=$(shell go env GOPATH)
BUILD_GOROOT=$(shell go env GOROOT)

## 默认目标，显示帮助信息。
.PHONY: help
help:
	@echo "使用方法:"
	@echo "  make [目标]"
	@echo ""
	@echo "目标:"
	@echo "  api              生成 API 相关的 Protocol Buffers 代码"
	@echo "  build            构建多平台可执行文件"
	@echo "  clean            清理项目"
	@echo "  config           生成配置相关的 Protocol Buffers 代码"
	@echo "  generate         执行代码生成任务"
	@echo "  help             显示此帮助信息"
	@echo "  image            构建 Docker 镜像"
	@echo "  init             初始化项目所需的工具链"
	@echo "  lint             执行基本的代码质量检查"
	@echo "  lint-strict      执行严格的代码质量检查"
	@echo "  run-task         运行 Docker 容器"
	@echo "  test             运行所有测试"
	@echo ""
	@echo "详细信息请查看 Makefile 文件中的注释"

# 初始化项目所需的工具链。
.PHONY: init
init:
	# 安装漏洞检查工具。
	go install golang.org/x/vuln/cmd/govulncheck@latest
	# 安装 Protocol Buffers 的 Go 语言代码生成器。
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	# 安装 gRPC 的 Go 语言代码生成器。
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	# 安装 Kratos 命令行工具。
	go install github.com/go-kratos/kratos/cmd/kratos/v2@latest
	# 安装 Kratos HTTP 服务代码生成器。
	go install github.com/go-kratos/kratos/cmd/protoc-gen-go-http/v2@latest
	# 安装 Protocol Buffers 验证代码生成器。
	go install github.com/envoyproxy/protoc-gen-validate@latest
	# 安装 Kratos 错误代码生成器。
	go install github.com/go-kratos/kratos/cmd/protoc-gen-go-errors/v2@latest
	# 安装 OpenAPI（Swagger）文档生成器。
	go install github.com/google/gnostic/cmd/protoc-gen-openapi@latest
	# 安装 Go 语言代码质量检查工具。
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	# 安装依赖注入代码生成工具。
	go install github.com/google/wire/cmd/wire@latest

# 生成配置相关的 Protocol Buffers 代码。
.PHONY: config
config:
	protoc --proto_path=. \
	       --proto_path=./api/third_party \
 	       --go_out=paths=source_relative:. \
	       $(INTERNAL_CONF_PROTO_FILES)

# 生成 API 相关的 Protocol Buffers 代码。
.PHONY: api
api:
	protoc --proto_path=. \
	       --proto_path=./api/third_party \
 	       --go_out=paths=source_relative:. \
 	       --go-http_out=paths=source_relative:. \
 	       --go-grpc_out=paths=source_relative:. \
 	       --openapi_out==paths=source_relative:./api \
	       $(API_PROTO_FILES)

# 生成验证相关的 Protocol Buffers 代码。
.PHONY: validate
validate:
	protoc --proto_path=. \
           --proto_path=./api/third_party \
           --go_out=paths=source_relative:. \
           --validate_out=paths=source_relative,lang=go:. \
           $(API_PROTO_FILES)

# 执行代码生成任务。
.PHONY: generate
generate:
	# 更新并整理项目依赖。
	go mod tidy
	# 执行所有 go:generate 注释标记的代码生成命令。
	go generate ./...

# 执行基本的代码质量检查。
.PHONY: lint
lint:
	# 使用 golangci-lint 进行静态代码分析，设置 3 分钟超时时间。
	golangci-lint run --timeout=3m

# 执行严格的代码质量检查。
.PHONY: lint-strict
lint-strict:
	# 启用大部分 linter，增加检查严格程度，设置 10 分钟超时时间。
	golangci-lint run --timeout=10m --enable=govet,errcheck,staticcheck,ineffassign,unused,gosec,misspell,revive --disable=lll,exhaustruct,ireturn,nonamedreturns,varnamelen,wrapcheck

# 运行所有测试。
# 使用 -v 标志显示详细的测试输出。
# 使用 -race 标志检测数据竞争。
test:
	mkdir -p $(LOG_DIR)
	go test -v -race ./...

# 构建多平台可执行文件。
.PHONY: build
build:
	# 构建 Linux ARM64 版本。
	mkdir -p bin/linux_arm64   && CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o bin/linux_arm64/   ./...
	# 构建 Linux AMD64 版本。
	mkdir -p bin/linux_amd64   && CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o bin/linux_amd64/   ./...
	# 构建 macOS ARM64 版本。
	mkdir -p bin/darwin_arm64  && CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o bin/darwin_arm64/  ./...
	# 构建 macOS AMD64 版本。
	mkdir -p bin/darwin_amd64  && CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -o bin/darwin_amd64/  ./...
	# 构建 Windows ARM64 版本。
	mkdir -p bin/windows_arm64 && CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o bin/windows_arm64/ ./...
	# 构建 Windows AMD64 版本。
	mkdir -p bin/windows_amd64 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/windows_amd64/ ./...
	# 使用 UPX 压缩所有 Linux 和 Windows 平台的可执行文件。
	mkdir -p logs && rm -rf logs/upx.log && for exec in ./bin/linux_*/* ./bin/windows_*/*; do upx -9 $$exec >> logs/upx.log || break ; done

# 构建 Docker 镜像。
image:
	# 构建任务镜像，并设置日期标签和最新标签。
	docker build \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-f docker/Dockerfile \
		--target task \
		-t $(IMAGE_NAME)-task:$(BUILD_DATE) \
		-t $(IMAGE_NAME)-task:latest \
		.

# 运行 Docker 容器。
.PHONY: run-task
run-task:
	# 创建日志目录。
	mkdir -p $(LOG_DIR)
	# 运行容器，并将容器内的日志目录挂载到主机。
	docker run \
		-v $(PWD)/$(LOG_DIR)/container:/app/logs \
		$(IMAGE_NAME)-task

# 清理项目。
# 注意：如果使用 OrbStack 运行项目，请不要使用此命令，否则会影响 OrbStack 的日志输出。
.PHONY: clean
clean:
	rm -rf bin/*
	rm -rf cmd/task/logs
	rm -rf logs/container/*.log
	rm -rf logs/*.log
	mkdir -p $(LOG_DIR)
