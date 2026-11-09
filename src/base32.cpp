#include "base32.h"

namespace {

const char kB32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// 返回 Base32 字母表下标；不是合法字符时返回 -1
int b32_val(char c) {
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    const char* p = strchr(kB32Alphabet, c);
    return (p && c) ? (int)(p - kB32Alphabet) : -1;
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// 去掉所有空白、连字符和 '=' padding（App 里复制的 secret 常带空格分组）
String normalize(const String& in) {
    String out;
    out.reserve(in.length());
    for (size_t i = 0; i < in.length(); ++i) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-' || c == '_' || c == '=') continue;
        out += c;
    }
    return out;
}

bool all_hex(const String& s) {
    if (s.length() == 0) return false;
    for (size_t i = 0; i < s.length(); ++i) {
        if (hex_val(s[i]) < 0) return false;
    }
    return true;
}

bool all_b32(const String& s) {
    if (s.length() == 0) return false;
    for (size_t i = 0; i < s.length(); ++i) {
        if (b32_val(s[i]) < 0) return false;
    }
    return true;
}

bool decode_b32(const String& s, uint8_t* out, size_t cap, size_t& out_len) {
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < s.length(); ++i) {
        int v = b32_val(s[i]);
        if (v < 0) return false;
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return false;
            out[n++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    out_len = n;
    return true;
}

bool decode_hex(const String& s, uint8_t* out, size_t cap, size_t& out_len) {
    if (s.length() % 2 != 0) return false;
    size_t n = 0;
    for (size_t i = 0; i + 1 < s.length(); i += 2) {
        int hi = hex_val(s[i]), lo = hex_val(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        if (n >= cap) return false;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    out_len = n;
    return true;
}

} // namespace

bool otp_decode_secret(const String& in, uint8_t* out, size_t out_cap, size_t& out_len, String& err) {
    String s = normalize(in);
    if (s.length() == 0) {
        err = "secret is empty";
        return false;
    }

    bool ok = false;
    bool hex_prefixed = false;
    if (s.startsWith("0x") || s.startsWith("0X")) {
        s = s.substring(2);
        hex_prefixed = true;
    }

    if (hex_prefixed) {
        ok = decode_hex(s, out, out_cap, out_len);
        if (!ok) {
            err = "invalid hex secret";
            return false;
        }
    } else if (all_b32(s)) {
        ok = decode_b32(s, out, out_cap, out_len);
        if (!ok) {
            err = "secret too long";
            return false;
        }
    } else if (all_hex(s) && (s.length() % 2 == 0)) {
        // 含 0/1/8/9 这些 Base32 字母表之外的字符 -> 按 hex 处理
        ok = decode_hex(s, out, out_cap, out_len);
        if (!ok) {
            err = "secret too long";
            return false;
        }
    } else {
        err = "secret must be Base32 (A-Z, 2-7) or hex (use 0x prefix for ambiguous hex)";
        return false;
    }

    if (out_len < 8) {
        err = "secret too short (need >= 8 bytes = >= 13 Base32 chars)";
        return false;
    }
    return true;
}

String otp_encode_secret(const uint8_t* key, size_t len) {
    String out;
    out.reserve((len * 8 + 4) / 5);
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 8) | key[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += kB32Alphabet[(acc >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out += kB32Alphabet[(acc << (5 - bits)) & 0x1F];
    }
    return out;
}
