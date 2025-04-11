#!/bin/sh
set -e

# 打印环境变量。
env

# 执行主程序。
exec "$@"
