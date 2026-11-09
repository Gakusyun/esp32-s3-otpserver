#include <string.h>

#include "tinyotp_totp.h"
#include "tinyotp_sha1.h"

namespace tinyotp {

totp::totp(const void* key, unsigned char len, uint64_t seconds)
{
    m_seconds = seconds ? seconds : 30;
    if (len > kMaxKeyLen) len = kMaxKeyLen;
    m_key_len = len;
    memcpy(m_key, key, len);
}

unsigned int totp::get_code(uint64_t ts) const
{
    return get_code_by_step(ts / m_seconds);
}

unsigned int totp::get_code_by_step(uint64_t step) const
{
    // STEP 0：把步数写成 8 字节大端计数器（RFC 4226 的 C 值）
    unsigned char counter[8];
    for (int i = 7; i >= 0; --i) {
        counter[i] = (unsigned char)(step & 0xFF);
        step >>= 8;
    }

    // STEP 1：HMAC-SHA1(secret, counter)
    sha1 h;
    h.init_hmac(m_key, m_key_len);
    h.write_array(counter, sizeof(counter));
    unsigned char* digest = h.result_hmac();

    // STEP 2：动态截断（RFC 4226 5.3），低位 4 bit 作为偏移
    unsigned char offset = digest[19] & 0x0F;
    uint32_t truncated = 0;
    for (unsigned char j = 0; j < 4; ++j) {
        truncated <<= 8;
        truncated |= digest[offset + j];
    }
    truncated &= 0x7FFFFFFF;

    // STEP 3：取模得到数字码（6 位 = 1e6）
    return truncated % 1000000u;
}

} // namespace tinyotp
