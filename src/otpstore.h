#pragma once
#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

// 密钥表：整个表常驻 RAM（32 条 × ~170B ≈ 5.4KB），改动时整表写回 LittleFS。
// 写回是"写临时文件 + 删除旧文件 + rename"，掉电不会留下半个文件。

#define OTP_MAX_ENTRIES 32
#define OTP_NAME_MAX 32 // 不含结尾 NUL
#define OTP_KEY_MAX 128

struct OtpEntry {
    char name[OTP_NAME_MAX + 1];
    uint8_t key[OTP_KEY_MAX];
    uint8_t key_len;
};

class OtpStore {
public:
    bool begin(); // 挂载 LittleFS 并载入密钥表（首次运行会格式化）

    int count() const { return n_; }
    const OtpEntry* at(int i) const { return (i < 0 || i >= n_) ? nullptr : &e_[i]; }
    const OtpEntry* find(const char* name) const;

    bool add(const char* name, const uint8_t* key, size_t key_len, String& err);
    bool remove(const char* name);

    static bool nameValid(const char* name, String& err);

private:
    bool load();
    bool save();

    OtpEntry e_[OTP_MAX_ENTRIES];
    int n_ = 0;
};
