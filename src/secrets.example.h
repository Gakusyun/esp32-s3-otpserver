// 复制本文件为 src/secrets.h 并填写真实凭据。
// src/secrets.h 已被 .gitignore 忽略 —— 密码永远不进版本库。
#pragma once

// 局域网 IoT 网络（ESP32-S3 只支持 2.4GHz）
#define OTP_WIFI_SSID "Xiaomi_91C1"
#define OTP_WIFI_PASSWORD "在这里填密码"

// NTP 服务器（本地时区无关，TOTP 只用 UTC 时间戳）
#define OTP_NTP_SERVER_1 "ntp.aliyun.com"
#define OTP_NTP_SERVER_2 "cn.pool.ntp.org"
