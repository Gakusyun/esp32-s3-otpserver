#pragma once
#include <stdint.h>

// TOTP (RFC 6238) / HOTP (RFC 4226) 的最小实现。
// 移植自 siren186/tinyotp（MIT），改动：
//   * 去掉 std::vector（避免堆分配与异常开关依赖），密钥改固定缓冲；
//   * 时间戳/步数改为 uint64_t 显式类型；
//   * get_code*() 改为 const，可重复调用。
// 只支持 HMAC-SHA1 —— 这是几乎所有 TOTP 服务端的默认算法，也是"最小可用"的全部。

namespace tinyotp {

class totp {
public:
    static const unsigned char kMaxKeyLen = 128;

    /**
     * @brief 用原始密钥字节初始化（不是 Base32/hex 文本，调用方先解码）
     * @param key 密钥字节
     * @param len 密钥长度（字节），超过 kMaxKeyLen 会被截断
     * @param seconds 时间步长（秒），RFC 默认 30
     */
    totp(const void* key, unsigned char len, uint64_t seconds = 30);

    /// 按 UTC 时间戳（秒）取码
    unsigned int get_code(uint64_t ts) const;

    /// 按步数取码：TOTP 的 step = ts / period，HOTP 的 step = 计数器
    unsigned int get_code_by_step(uint64_t step) const;

    uint64_t period() const { return m_seconds; }

private:
    unsigned char m_key[kMaxKeyLen];
    unsigned char m_key_len;
    uint64_t m_seconds;
};

} // namespace tinyotp
