# Copyright 2025 fsyyft-go
# 
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

# 使用官方 Go 镜像作为构建环境。
# https://hub.docker.com/_/golang/tags?name=1.24
FROM golang:1.24.2-alpine AS builder

# 定义构建参数。
# git 提交哈希值，从环境变量中获取，就不需要再容器内安装 git 工具了。
ARG GIT_COMMIT
# 编译时间。
ARG BUILD_TIME

# 设置工作目录。
WORKDIR /app

# 复制项目文件。
COPY . .

# 设置 GOPROXY 并下载依赖。
RUN go env -w GOPROXY=https://goproxy.cn,direct && \
    go mod download

# 构建应用。
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags " \
    -X github.com/fsyyft-go/kit/go/build.gitVersion=${GIT_COMMIT} \
    -X github.com/fsyyft-go/kit/go/build.buildTimeString=${BUILD_TIME} \
    -X github.com/fsyyft-go/kit/go/build.buildGopathDirectory=$(go env GOPATH) \
    -X github.com/fsyyft-go/kit/go/build.buildGorootDirectory=$(go env GOROOT) \
    " -o task ./cmd/task

# 使用精简的 alpine 镜像作为运行时环境。
FROM alpine:3.19 AS task

# 设置工作目录。
WORKDIR /app

# 复制配置文件。
COPY configs/config.yaml ./configs/config.yaml
COPY docker/entrypoint.sh ./entrypoint.sh

# 创建日志目录。
RUN mkdir -p /app/logs && \
    chmod 755 /app/logs && \
    chmod +x ./entrypoint.sh

# 从构建阶段复制可执行文件。
COPY --from=builder /app/task .

# 暴露端口。
EXPOSE 32788

# 声明日志卷。
VOLUME ["/app/logs"]

# 启动应用。
ENTRYPOINT ["./entrypoint.sh"]
CMD ["./task", "--config=configs/config.yaml"]