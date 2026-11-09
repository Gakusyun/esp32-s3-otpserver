#pragma once
#include <Arduino.h>
#include <stdint.h>

// TOTP 依赖准确的 UTC 时间，而板子没有 RTC 电池：每次上电时间都从 1970 开始。
//
// 策略（按需求确定）：
//   1) 联网后用 SNTP 对时，对时成功后 API 正常出码（source = "ntp"）；
//   2) 对时失败时回退到"上次对时的时间 + 开机后经过的秒数"估算（source = "estimate"），
//      上次对时时间存在 NVS 里，所以断网重启也能出码，只是会漂；
//   3) 连一次都没对过时（source = "none"），API 返回 503，宁可不给也不给错的。
class TimeKeeper {
public:
    void begin();                                  // 从 NVS 读上次对时时间
    void startSntp(const char* s1, const char* s2); // 配置 SNTP（异步）
    void poll();                                   // 主循环里调，负责同步检测与落盘

    bool valid() const { return synced_ || persisted_epoch_ > 0; }
    bool synced() const { return synced_; }
    uint64_t epoch() const;
    uint64_t lastSyncEpoch() const { return sync_epoch_; }
    const char* source() const;

private:
    void persist(uint64_t epoch);

    bool synced_ = false;
    uint64_t sync_epoch_ = 0;      // 最近一次"可信"的 UTC 秒
    uint32_t sync_millis_ = 0;     // 得到 sync_epoch_ 时的 millis()
    uint64_t persisted_epoch_ = 0; // NVS 里的值（重启后作为估算起点）
    uint32_t last_persist_millis_ = 0;
    bool ntp_started_ = false;
};
