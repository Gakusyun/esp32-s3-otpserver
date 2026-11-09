#include "timekeeper.h"

#include <Preferences.h>
#include <time.h>

namespace {
constexpr uint64_t kValidAfter = 1600000000ULL; // 2020-09-13，早于此的时间一定是没对上时
constexpr uint32_t kPersistIntervalMs = 600000; // 每 10 分钟落盘一次，重启后估算起点才够新
Preferences prefs;
} // namespace

void TimeKeeper::begin() {
    prefs.begin("otp", false);
    persisted_epoch_ = prefs.getULong64("ts", 0);
    if (persisted_epoch_ > 0) {
        // 断网重启时从这里开始估算（漂移无从得知，只能信任开机瞬间）
        sync_epoch_ = persisted_epoch_;
        sync_millis_ = millis();
        time_t last = (time_t)persisted_epoch_;
        Serial.printf("[time] NVS 里的上次对时: %llu (%s)\n", (unsigned long long)persisted_epoch_,
                      asctime(gmtime(&last)));
    } else {
        Serial.println("[time] NVS 里没有对时记录，等待 SNTP");
    }
    last_persist_millis_ = millis() - kPersistIntervalMs;
}

void TimeKeeper::startSntp(const char* s1, const char* s2) {
    configTime(0, 0, s1, s2); // 时区偏移 0：TOTP 只用 UTC
    ntp_started_ = true;
    Serial.printf("[time] SNTP: %s / %s\n", s1, s2);
}

void TimeKeeper::poll() {
    time_t t = time(nullptr);
    if (t < (time_t)kValidAfter) return; // 还没对上时

    uint64_t now = (uint64_t)t;
    uint32_t ms = millis();

    if (!synced_) {
        synced_ = true;
        sync_epoch_ = now;
        sync_millis_ = ms;
        Serial.printf("[time] 对时成功: %llu\n", (unsigned long long)now);
        persist(now);
        return;
    }

    // 系统时钟被 SNTP 校正过（与"本地流逝"不符）时，更新基准
    uint64_t expect = sync_epoch_ + (ms - sync_millis_) / 1000;
    if (now + 1 < expect || now > expect + 1) {
        sync_epoch_ = now;
        sync_millis_ = ms;
    }

    if (ms - last_persist_millis_ >= kPersistIntervalMs) persist(now);
}

uint64_t TimeKeeper::epoch() const {
    if (synced_) {
        time_t t = time(nullptr);
        if (t >= (time_t)kValidAfter) return (uint64_t)t;
    }
    // 估算：上次可信时间 + 开机后经过的秒数
    return sync_epoch_ + (millis() - sync_millis_) / 1000;
}

const char* TimeKeeper::source() const {
    if (synced_) return "ntp";
    if (persisted_epoch_ > 0) return "estimate";
    return "none";
}

void TimeKeeper::persist(uint64_t epoch) {
    if (epoch == persisted_epoch_) return;
    prefs.putULong64("ts", epoch);
    persisted_epoch_ = epoch;
    last_persist_millis_ = millis();
}
