#include "otpstore.h"

#include <ArduinoJson.h>
#include <LittleFS.h>

#include "base32.h"

namespace {
constexpr const char* kDir = "/otp";
constexpr const char* kPath = "/otp/secrets.json";
constexpr const char* kTmp = "/otp/secrets.new";
constexpr int kFormatVersion = 1;

bool isNameChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '_' || c == '-';
}
} // namespace

bool OtpStore::nameValid(const char* name, String& err) {
    if (!name) {
        err = "name is required";
        return false;
    }
    size_t len = strlen(name);
    if (len == 0 || len > OTP_NAME_MAX) {
        err = "name must be 1..32 chars";
        return false;
    }
    for (size_t i = 0; i < len; ++i) {
        if (!isNameChar(name[i])) {
            err = "name may only contain A-Z a-z 0-9 . _ -";
            return false;
        }
    }
    if (name[0] == '.') {
        err = "name must not start with '.'";
        return false;
    }
    return true;
}

bool OtpStore::begin() {
    if (!LittleFS.begin(true)) {
        Serial.println("[store] LittleFS 挂载失败");
        return false;
    }
    if (!LittleFS.exists(kDir) && !LittleFS.mkdir(kDir)) {
        Serial.println("[store] 无法创建 /otp");
        return false;
    }
    return load();
}

bool OtpStore::load() {
    n_ = 0;
    if (!LittleFS.exists(kPath)) {
        Serial.println("[store] 密钥表不存在，从空表开始");
        return true;
    }
    File f = LittleFS.open(kPath, "r");
    if (!f) {
        Serial.println("[store] 打不开密钥表");
        return false;
    }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    if (err) {
        // 文件损坏时不覆盖它（宁可拒绝服务，也别把用户导入的密钥抹掉）
        Serial.printf("[store] 密钥表解析失败: %s\n", err.c_str());
        return false;
    }

    JsonArray arr = doc["entries"].as<JsonArray>();
    for (JsonObject o : arr) {
        const char* name = o["name"] | "";
        const char* secret = o["secret"] | "";
        String why;
        if (!nameValid(name, why)) {
            Serial.printf("[store] 跳过非法条目 %s: %s\n", name, why.c_str());
            continue;
        }
        uint8_t key[OTP_KEY_MAX];
        size_t key_len = 0;
        if (!otp_decode_secret(String(secret), key, sizeof(key), key_len, why)) {
            Serial.printf("[store] 跳过 %s: %s\n", name, why.c_str());
            continue;
        }
        if (n_ >= OTP_MAX_ENTRIES) {
            Serial.println("[store] 条目数超过上限，其余忽略");
            break;
        }
        strncpy(e_[n_].name, name, OTP_NAME_MAX);
        e_[n_].name[OTP_NAME_MAX] = '\0';
        memcpy(e_[n_].key, key, key_len);
        e_[n_].key_len = (uint8_t)key_len;
        ++n_;
    }
    Serial.printf("[store] 已载入 %d 条密钥\n", n_);
    return true;
}

bool OtpStore::save() {
    File f = LittleFS.open(kTmp, "w");
    if (!f) {
        Serial.println("[store] 写临时文件失败");
        return false;
    }
    JsonDocument doc;
    doc["version"] = kFormatVersion;
    JsonArray arr = doc["entries"].to<JsonArray>();
    for (int i = 0; i < n_; ++i) {
        JsonObject o = arr.add<JsonObject>();
        o["name"] = e_[i].name;
        o["secret"] = otp_encode_secret(e_[i].key, e_[i].key_len);
    }
    size_t written = serializeJson(doc, f);
    f.close();
    if (written == 0) {
        LittleFS.remove(kTmp);
        return false;
    }
    LittleFS.remove(kPath);
    if (!LittleFS.rename(kTmp, kPath)) {
        Serial.println("[store] rename 失败");
        return false;
    }
    return true;
}

const OtpEntry* OtpStore::find(const char* name) const {
    for (int i = 0; i < n_; ++i) {
        if (strcmp(e_[i].name, name) == 0) return &e_[i];
    }
    return nullptr;
}

bool OtpStore::add(const char* name, const uint8_t* key, size_t key_len, String& err) {
    if (!nameValid(name, err)) return false;
    if (key_len == 0 || key_len > OTP_KEY_MAX) {
        err = "secret length out of range";
        return false;
    }
    if (find(name)) {
        err = "name already exists";
        return false;
    }
    if (n_ >= OTP_MAX_ENTRIES) {
        err = "entry limit reached (32)";
        return false;
    }

    OtpEntry& e = e_[n_];
    strncpy(e.name, name, OTP_NAME_MAX);
    e.name[OTP_NAME_MAX] = '\0';
    memcpy(e.key, key, key_len);
    e.key_len = (uint8_t)key_len;
    ++n_;

    if (!save()) {
        --n_; // 回滚，内存与磁盘保持一致
        err = "failed to persist (filesystem error)";
        return false;
    }
    return true;
}

bool OtpStore::remove(const char* name) {
    for (int i = 0; i < n_; ++i) {
        if (strcmp(e_[i].name, name) != 0) continue;
        for (int j = i; j < n_ - 1; ++j) e_[j] = e_[j + 1];
        --n_;
        if (!save()) {
            Serial.println("[store] 删除后落盘失败，回读磁盘状态");
            load();
            return false;
        }
        return true;
    }
    return false;
}
