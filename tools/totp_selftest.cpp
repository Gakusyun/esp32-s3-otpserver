// 主机侧自检：用 RFC 6238 官方测试向量验证 tinyotp 的 TOTP 实现。
// 不依赖 Arduino；由 tools/run_selftest.sh 用 g++ 编译运行。
//
//   RFC 6238 附录 B（SHA1 列，seed = "12345678901234567890"）给出的 8 位码：
//     T=59          94287082 -> 6 位 287082
//     T=1111111109  07081804 -> 6 位 081804
//     T=1111111111  14050471 -> 6 位 050471
//     T=1234567890  89005924 -> 6 位 005924
//     T=2000000000  69279037 -> 6 位 279037
//     T=20000000000 65353130 -> 6 位 353130

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/tinyotp/tinyotp_totp.h"

int main() {
    const char seed[] = "12345678901234567890";

    struct {
        unsigned long long t;
        unsigned int expect;
    } vectors[] = {
        {59ULL, 287082},      {1111111109ULL, 81804},  {1111111111ULL, 50471},
        {1234567890ULL, 5924}, {2000000000ULL, 279037}, {20000000000ULL, 353130},
    };

    int failed = 0;
    for (unsigned i = 0; i < sizeof(vectors) / sizeof(vectors[0]); ++i) {
        tinyotp::totp otp(seed, (unsigned char)strlen(seed), 30);
        unsigned int code = otp.get_code(vectors[i].t);
        bool ok = (code == vectors[i].expect);
        printf("T=%-12llu got %06u expect %06u  %s\n", vectors[i].t, code, vectors[i].expect,
               ok ? "OK" : "FAIL");
        if (!ok) ++failed;
    }

    // 同一步长内多次取值应稳定（get_code 是 const，不修改状态）
    tinyotp::totp otp(seed, (unsigned char)strlen(seed), 30);
    unsigned int a = otp.get_code(1700000000ULL);
    unsigned int b = otp.get_code(1700000000ULL);
    if (a != b) {
        printf("FAIL: 重复取码结果不一致 (%06u vs %06u)\n", a, b);
        ++failed;
    }

    printf(failed ? "\n%d 项失败\n" : "\n全部通过\n", failed);
    return failed ? 1 : 0;
}
