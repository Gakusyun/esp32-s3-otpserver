#!/bin/bash
# 主机侧编译并运行 TOTP 自检（用 RFC 6238 官方测试向量）。
# 不烧板子、不需要 PlatformIO，只验证算法实现没被改错。
set -euo pipefail
cd "$(dirname "$0")/.."

out=$(mktemp -d)/totp_selftest
g++ -std=c++17 -O2 -Wall -Wextra -o "$out" \
    tools/totp_selftest.cpp src/tinyotp/tinyotp_totp.cpp src/tinyotp/tinyotp_sha1.cpp
"$out"
