// otpserver — 局域网内的 TOTP 服务
//
// 设计约束（来自需求）：
//   * 只做 GET 代码 / 导入 / 删除，**不导出** secret（接口层面根本无法取回明文密钥）；
//   * 只支持 TOTP：30 秒周期、6 位数字、HMAC-SHA1（其余参数一律拒绝）；
//   * 无鉴权，局域网内任意设备可直接调用（AGENTS.md 记录的 4.x 段是受控网段）。
//
// 可信边界要说清：密钥以明文存在板子的 LittleFS 上，能物理接触板子并 read_flash 的人
// 依然能读出来。"无法通过 API 导出"防的是软件/网络侧，不是物理侧。

#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESPmDNS.h>
#include <LittleFS.h>
#include <WebServer.h>
#include <WiFi.h>

#include "base32.h"
#include "otpstore.h"
#include "timekeeper.h"
#include "tinyotp/tinyotp_totp.h"

#if __has_include("secrets.h")
#include "secrets.h"
#else
#warning "缺少 src/secrets.h —— 复制 src/secrets.example.h 并填写 Wi-Fi 凭据（文件不入库）"
#define OTP_WIFI_SSID ""
#define OTP_WIFI_PASSWORD ""
#define OTP_NTP_SERVER_1 "pool.ntp.org"
#define OTP_NTP_SERVER_2 "time.google.com"
#endif

namespace {

constexpr const char* kVersion = "0.1.0";
constexpr uint32_t kPeriod = 30; // TOTP 步长（秒），固定
constexpr uint32_t kDigits = 6;  // 固定 6 位
constexpr const char* kMdnsName = "otpserver";

WebServer server(80);
OtpStore store;
TimeKeeper clockkeeper;

// ---------- 小工具 ----------

String urlDecode(const String& in) {
    String out;
    out.reserve(in.length());
    auto hexv = [](char h) -> int {
        if (h >= '0' && h <= '9') return h - '0';
        if (h >= 'a' && h <= 'f') return h - 'a' + 10;
        if (h >= 'A' && h <= 'F') return h - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < in.length(); ++i) {
        char c = in[i];
        if (c == '+') {
            out += ' ';
        } else if (c == '%' && i + 2 < in.length()) {
            int hi = hexv(in[i + 1]), lo = hexv(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
            out += c;
        } else {
            out += c;
        }
    }
    return out;
}

void sendJson(int code, const String& body) {
    server.sendHeader("Cache-Control", "no-store");
    server.send(code, "application/json", body);
}

void sendError(int code, const char* msg) {
    JsonDocument doc;
    doc["error"] = msg;
    String out;
    serializeJson(doc, out);
    sendJson(code, out);
}

void sendNotAllowed(const char* allow) {
    server.sendHeader("Allow", allow);
    sendError(405, "method not allowed");
}

// 形状统一的取码结果：成功时把这些字段塞进响应对象
struct CodeInfo {
    bool ok = false;
    char code[8] = {0};
    uint32_t remaining = 0;
    uint64_t step = 0;
};

CodeInfo makeCode(const OtpEntry& e) {
    CodeInfo r;
    if (!clockkeeper.valid()) return r;
    uint64_t now = clockkeeper.epoch();
    r.step = now / kPeriod;
    r.remaining = (uint32_t)(kPeriod - (now % kPeriod));
    tinyotp::totp otp(e.key, e.key_len, kPeriod);
    snprintf(r.code, sizeof(r.code), "%06u", otp.get_code_by_step(r.step) % 1000000u);
    r.ok = true;
    return r;
}

void addTimeFields(JsonObject o, const CodeInfo& c) {
    o["code"] = c.code;
    o["remaining"] = c.remaining;
    o["period"] = kPeriod;
    o["digits"] = kDigits;
}

bool requireClock() {
    if (clockkeeper.valid()) return true;
    sendError(503, "time not synchronized yet (no SNTP sync and no stored sync time)");
    return false;
}

// ---------- otpauth:// URI 解析 ----------

bool parseOtpauth(const String& uri, String& name, String& secret, String& err) {
    if (!uri.startsWith("otpauth://")) {
        err = "not an otpauth URI";
        return false;
    }
    const int start = 10; // strlen("otpauth://")
    int slash = uri.indexOf('/', start);
    if (slash < 0) {
        err = "otpauth URI has no label";
        return false;
    }
    String type = uri.substring(start, slash);
    type.toLowerCase();
    if (type != "totp") {
        err = "only otpauth://totp is supported";
        return false;
    }

    int qmark = uri.indexOf('?', slash);
    String label = (qmark < 0) ? uri.substring(slash + 1) : uri.substring(slash + 1, qmark);
    label = urlDecode(label);
    int colon = label.lastIndexOf(':');
    if (colon >= 0) label = label.substring(colon + 1);
    label.trim();

    String issuer;
    if (qmark >= 0) {
        String query = uri.substring(qmark + 1);
        int pos = 0;
        while (pos < (int)query.length()) {
            int amp = query.indexOf('&', pos);
            if (amp < 0) amp = query.length();
            String pair = query.substring(pos, amp);
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String k = pair.substring(0, eq);
                String v = urlDecode(pair.substring(eq + 1));
                k.toLowerCase();
                if (k == "secret") {
                    secret = v;
                } else if (k == "issuer") {
                    issuer = v;
                } else if (k == "period") {
                    if (v.toInt() != (int)kPeriod) {
                        err = "only period=30 is supported";
                        return false;
                    }
                } else if (k == "digits") {
                    if (v.toInt() != (int)kDigits) {
                        err = "only digits=6 is supported";
                        return false;
                    }
                } else if (k == "algorithm") {
                    String a = v;
                    a.toUpperCase();
                    if (a != "SHA1") {
                        err = "only algorithm=SHA1 is supported";
                        return false;
                    }
                }
            }
            pos = amp + 1;
        }
    }

    if (secret.length() == 0) {
        err = "otpauth URI has no secret= parameter";
        return false;
    }
    if (name.length() == 0) name = label; // 只在调用方没给 name 时才用 label
    (void)issuer;
    return true;
}

// ---------- 路由处理 ----------

void handleRoot() {
    JsonDocument doc;
    doc["service"] = "otpserver";
    doc["version"] = kVersion;
    doc["entries"] = store.count();
    doc["period"] = kPeriod;
    doc["digits"] = kDigits;
    doc["algorithm"] = "SHA1";
    JsonArray eps = doc["endpoints"].to<JsonArray>();
    eps.add("GET    /otp");
    eps.add("GET    /otp/{name}");
    eps.add("POST   /otp        {name, secret} | {name, otpauth} | raw otpauth:// URI");
    eps.add("DELETE /otp/{name}");
    eps.add("GET    /status");
    doc["note"] = "secrets cannot be exported, only imported and deleted";
    String out;
    serializeJson(doc, out);
    sendJson(200, out);
}

void handleStatus() {
    JsonDocument doc;
    doc["uptime_s"] = (uint32_t)(millis() / 1000);
    doc["version"] = kVersion;

    JsonObject wifi = doc["wifi"].to<JsonObject>();
    bool connected = (WiFi.status() == WL_CONNECTED);
    wifi["connected"] = connected;
    if (connected) {
        wifi["ssid"] = WiFi.SSID();
        wifi["ip"] = WiFi.localIP().toString();
        wifi["rssi"] = WiFi.RSSI();
        wifi["mac"] = WiFi.macAddress();
    }

    JsonObject t = doc["time"].to<JsonObject>();
    t["source"] = clockkeeper.source();
    t["synced"] = clockkeeper.synced();
    t["last_sync_epoch"] = clockkeeper.lastSyncEpoch();
    if (clockkeeper.valid()) t["epoch"] = clockkeeper.epoch();
    t["remaining"] = clockkeeper.valid() ? (uint32_t)(kPeriod - (clockkeeper.epoch() % kPeriod)) : 0;

    JsonObject s = doc["store"].to<JsonObject>();
    s["entries"] = store.count();
    s["capacity"] = OTP_MAX_ENTRIES;
    s["fs_used"] = (uint32_t)LittleFS.usedBytes();
    s["fs_total"] = (uint32_t)LittleFS.totalBytes();

    String out;
    serializeJson(doc, out);
    sendJson(200, out);
}

void handleList() {
    if (!requireClock()) return;
    JsonDocument doc;
    doc["period"] = kPeriod;
    doc["digits"] = kDigits;
    doc["count"] = store.count();
    JsonArray arr = doc["entries"].to<JsonArray>();
    for (int i = 0; i < store.count(); ++i) {
        const OtpEntry* e = store.at(i);
        CodeInfo c = makeCode(*e);
        JsonObject o = arr.add<JsonObject>();
        o["name"] = e->name;
        addTimeFields(o, c);
    }
    String out;
    serializeJson(doc, out);
    sendJson(200, out);
}

void handleGet(const String& name) {
    if (!requireClock()) return;
    const OtpEntry* e = store.find(name.c_str());
    if (!e) {
        sendError(404, "no such entry");
        return;
    }
    CodeInfo c = makeCode(*e);
    JsonDocument doc;
    doc["name"] = e->name;
    addTimeFields(doc.as<JsonObject>(), c);
    doc["step"] = c.step;
    String out;
    serializeJson(doc, out);
    sendJson(200, out);
}

void handleDelete(const String& name) {
    if (!store.find(name.c_str())) {
        sendError(404, "no such entry");
        return;
    }
    if (!store.remove(name.c_str())) {
        sendError(500, "failed to delete");
        return;
    }
    Serial.printf("[api] 删除 %s\n", name.c_str());
    server.sendHeader("Cache-Control", "no-store");
    server.send(204);
}

void handleImport() {
    String body = server.arg("plain");
    body.trim();

    String name;
    String secret;
    String uri;
    String err;

    if (body.startsWith("otpauth://")) {
        uri = body; // 直接把 URI 当请求体也可以（curl --data-binary 最省事）
    } else if (body.length() > 0) {
        JsonDocument doc;
        DeserializationError derr = deserializeJson(doc, body);
        if (derr) {
            sendError(400, "body is neither JSON nor an otpauth:// URI");
            return;
        }
        name = (const char*)(doc["name"] | "");
        secret = (const char*)(doc["secret"] | "");
        uri = (const char*)(doc["otpauth"] | "");
    } else {
        // 空请求体：允许用 query 参数，方便 curl 一行搞定
        name = server.arg("name");
        secret = server.arg("secret");
        uri = server.arg("otpauth");
    }

    if (uri.length() > 0) {
        if (!parseOtpauth(uri, name, secret, err)) {
            sendError(400, err.c_str());
            return;
        }
    }
    if (name.length() == 0) {
        sendError(400, "name is required (could not derive it from the otpauth label)");
        return;
    }
    if (secret.length() == 0) {
        sendError(400, "secret is required");
        return;
    }

    uint8_t key[OTP_KEY_MAX];
    size_t key_len = 0;
    if (!otp_decode_secret(secret, key, sizeof(key), key_len, err)) {
        sendError(400, err.c_str());
        return;
    }
    if (!store.add(name.c_str(), key, key_len, err)) {
        int code = (err.indexOf("already exists") >= 0) ? 409 : 400;
        sendError(code, err.c_str());
        return;
    }
    memset(key, 0, sizeof(key)); // 明文密钥不在栈上多留

    Serial.printf("[api] 导入 %s (%u bytes)\n", name.c_str(), (unsigned)key_len);

    JsonDocument doc;
    doc["name"] = name;
    if (clockkeeper.valid()) {
        const OtpEntry* e = store.find(name.c_str());
        CodeInfo c = makeCode(*e);
        addTimeFields(doc.as<JsonObject>(), c);
    }
    String out;
    serializeJson(doc, out);
    sendJson(201, out);
}

void dispatch() {
    const String path = server.uri();
    HTTPMethod m = server.method();

    if (path == "/") {
        if (m == HTTP_GET) return handleRoot();
        return sendNotAllowed("GET");
    }
    if (path == "/status") {
        if (m == HTTP_GET) return handleStatus();
        return sendNotAllowed("GET");
    }
    if (path == "/otp" || path == "/otp/") {
        if (m == HTTP_GET) return handleList();
        if (m == HTTP_POST) return handleImport();
        return sendNotAllowed("GET, POST");
    }
    if (path.startsWith("/otp/")) {
        String name = path.substring(5);
        if (name.endsWith("/")) name = name.substring(0, name.length() - 1);
        if (name.length() == 0) return sendError(404, "not found");
        if (m == HTTP_GET) return handleGet(name);
        if (m == HTTP_DELETE) return handleDelete(name);
        return sendNotAllowed("GET, DELETE");
    }
    sendError(404, "not found");
}

// ---------- Wi-Fi ----------

bool sntp_started = false;
bool mdns_started = false;
bool was_connected = false;
uint32_t last_wifi_attempt = 0;

void wifiEnsure() {
    if (strlen(OTP_WIFI_SSID) == 0) return;
    if (WiFi.status() == WL_CONNECTED) return;
    uint32_t now = millis();
    if (now - last_wifi_attempt < 10000) return;
    last_wifi_attempt = now;
    Serial.printf("[wifi] 连接 %s ...\n", OTP_WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.begin(OTP_WIFI_SSID, OTP_WIFI_PASSWORD);
}

void onWifiUp() {
    Serial.printf("[wifi] 已连接 %s, IP %s, RSSI %d\n", WiFi.SSID().c_str(),
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());
    if (!sntp_started) {
        clockkeeper.startSntp(OTP_NTP_SERVER_1, OTP_NTP_SERVER_2);
        sntp_started = true;
    }
    if (!mdns_started) {
        if (MDNS.begin(kMdnsName)) {
            MDNS.addService("http", "tcp", 80);
            Serial.printf("[mdns] http://%s.local/\n", kMdnsName);
            mdns_started = true;
        } else {
            Serial.println("[mdns] 启动失败（不影响 IP 直连）");
        }
    }
    Serial.println("[api] 例子: curl http://" + WiFi.localIP().toString() + "/otp");
}

} // namespace

void setup() {
    Serial.begin(115200);
    delay(300);
    Serial.println();
    Serial.println("=== otpserver " + String(kVersion) + " ===");

    if (!store.begin()) {
        Serial.println("[store] 初始化失败：密钥表不可用，API 会返回错误");
    }
    clockkeeper.begin();

    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.setHostname(kMdnsName);

    server.onNotFound(dispatch);
    server.enableDelay(false);
    server.begin();
    Serial.println("[api] HTTP 80 已监听");

    Serial.printf("[boot] my MAC: %s\n", WiFi.macAddress().c_str());
}

void loop() {
    wifiEnsure();

    bool connected = (WiFi.status() == WL_CONNECTED);
    if (connected && !was_connected) onWifiUp();
    if (!connected && was_connected) Serial.println("[wifi] 连接断开，准备重连");
    was_connected = connected;

    server.handleClient();
    clockkeeper.poll();
    delay(2);
}
