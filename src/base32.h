#pragma once
#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

// secret 文本 -> 二进制密钥。
// 支持两种输入（认证器 App 里复制出来的多是第一种）：
//   * Base32（RFC 4648）：大小写不敏感，忽略空格/连字符，padding 可省；
//   * hex：仅当文本里出现 0/1/8/9（Base32 字母表里没有）或 0x 前缀时才按 hex 解释，
//     这样手写测试用例也方便。
// 短于 8 字节的密钥直接拒绝（RFC 4226 要求至少 128 bit；过短的密钥没有实用意义）。
bool otp_decode_secret(const String& in, uint8_t* out, size_t out_cap, size_t& out_len, String& err);

// 反向编码，只用于写 LittleFS（API 永不导出 secret）。
String otp_encode_secret(const uint8_t* key, size_t len);
