# otpserver

跑在 ESP32-S3 上的**最小可用 TOTP 服务**：局域网里的其他设备（尤其是 AI agent）通过 REST API 取 6 位动态码。

- 只做 TOTP —— **30 秒周期、6 位数字、HMAC-SHA1**（RFC 6238），其余参数一律拒绝
- 只支持 **导入 / 列表 / 取码 / 删除**：secret 导入后**无法通过任何 API 取回**，只能删掉重导
- 无鉴权，局域网内任意设备可直接调用（见「安全模型」）

算法移植自 [siren186/tinyotp](https://github.com/siren186/tinyotp)（MIT），并保留了 RFC 6238 官方向量自检。

---

## 1. 硬件与工程

| 项目 | 值 |
|---|---|
| 板子 | ESP32-S3 N16R8（16MB Flash + 8MB Octal PSRAM） |
| 框架 | PlatformIO `espressif32@8.0.0` + Arduino core 3.x |
| 串口 | 板上 CH343 → `/dev/ttyACM0`（115200，上传 460800） |
| 分区 | 双 OTA 槽（各 2MB）+ 1MB LittleFS（`spiffs` 子类型）+ 64KB coredump |
| Flash 占用 | 应用约 55%（1.15MB / 2MB），RAM 约 17% |

依赖只有 ArduinoJson（JSON 编解码），TOTP/SHA1/Base32/HTTP 路由全部手写。

---

## 2. 快速开始

```bash
# 1) 填 Wi-Fi 凭据（文件不入库）
cp src/secrets.example.h src/secrets.h
$EDITOR src/secrets.h

# 2) 编译 + 烧写
pio run -e s3 -t upload --upload-port /dev/ttyACM0

# 3) 抓启动日志（可选）
cd /root/esp32 && python3 mprepl.py --reset
```

板子的 IP 由路由器 DHCP 绑定下发（**代码里不写死 IP**，换地址只改路由器）。启动日志会打印实际 IP，也可以用 mDNS：

```bash
curl http://otpserver.local/status
```

---

## 3. API

所有响应都是 JSON。**任何响应都不包含 secret**（没有导出接口，这是设计而非疏漏）。
`GET /otp*` 在时间未同步时返回 `503`（宁可不给，也不给错的）。

### `GET /` — 服务信息

```json
{"service":"otpserver","version":"0.1.0","entries":3,"period":30,"digits":6,
 "algorithm":"SHA1","endpoints":["GET    /otp", "..."],
 "note":"secrets cannot be exported, only imported and deleted"}
```

### `GET /status` — 运行状态

```json
{"uptime_s":38,"version":"0.1.0",
 "wifi":{"connected":true,"ssid":"Xiaomi_91C1","ip":"192.168.4.4","rssi":-44,"mac":"30:30:F9:5C:A0:B4"},
 "time":{"source":"ntp","synced":true,"last_sync_epoch":1794221300,"epoch":1794221311,"remaining":29},
 "store":{"entries":3,"capacity":32,"fs_used":16384,"fs_total":1048576}}
```

`time.source` 三种取值，含义见「时间源」一节。

### `GET /otp` — 一次拿全部当前码

```json
{"period":30,"digits":6,"count":2,
 "entries":[{"name":"github","code":"915300","remaining":9,"period":30,"digits":6},
            {"name":"mail","code":"204817","remaining":9,"period":30,"digits":6}]}
```

给 agent 用最省事：一句话就能拿到所有码，不用逐个请求。

### `GET /otp/{name}` — 取单个码

```json
{"name":"github","code":"915300","remaining":9,"period":30,"digits":6,"step":59807377}
```

- `code` 是 **字符串**，保证前导零不丢（`"005924"` 而不是 `5924`）
- `remaining` = 该码还剩几秒过期（1..30）

### `POST /otp` — 导入

三种写法都支持，服务端自己归一化：

```bash
# a) JSON（推荐，注意 Content-Type）
curl -X POST http://otpserver.local/otp -H 'Content-Type: application/json' \
     -d '{"name":"github","secret":"JBSWY3DPEHPK3PXP"}'

# b) 直接贴 otpauth:// URI（从 App / 二维码复制的原样内容）
curl -X POST http://otpserver.local/otp -H 'Content-Type: text/plain' \
     -d 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30&digits=6'

# c) 表单或 query（不写 header 也能用）
curl -X POST 'http://otpserver.local/otp?name=github&secret=JBSWY3DPEHPK3PXP'
```

成功返回 `201`：

```json
{"name":"github","code":"915300","remaining":9,"period":30,"digits":6}
```

secret 的接受格式：

| 输入 | 说明 |
|---|---|
| Base32 `JBSWY3DP...` | 认证器 App 里复制出来的那串；大小写不敏感，忽略空格/连字符，padding 可省 |
| Base32 小写 / 带空格分组 | 同样接受（例：`jbsw y3dp ehpk 3pxp`） |
| hex `0xdeadbeef...` | 手写测试用；**没有 `0x` 前缀**时按 Base32 解析（除非里面含 `0 1 8 9`） |

长度要求 ≥ 8 字节（13 个 Base32 字符），否则拒绝。

Google Authenticator 的「导出账户」给的是 `otpauth-migration://offline?data=<protobuf>`，
一次打包多条，服务端**不直接吃**这种格式；用 `tools/import_migration.py` 在主机侧拆开再逐条导入：

```bash
python3 tools/import_migration.py --base http://192.168.4.4 uris.txt
```

`otpauth://` URI 里如果带了 `period` / `digits` / `algorithm`，服务端会校验必须等于 `30` / `6` / `SHA1`，不符直接 `400`（HOTP 也不支持）。URI 的 label 只在**请求里没给 `name`** 时才用作条目名，且非法字符会被替换成 `-`。

### `DELETE /otp/{name}` — 删除

```bash
curl -X DELETE http://otpserver.local/otp/github    # 204，无响应体
```

删除是**唯一**的清理手段：没有修改接口，也没有"改 secret"接口——要换密钥就删掉重导。

### 错误码

| 状态 | 场景 |
|---|---|
| `400` | JSON 解析失败 / 参数不合法 / 非 TOTP 参数 / secret 太短或格式错 |
| `404` | 条目或路径不存在 |
| `405` | 方法不支持（带 `Allow` 头） |
| `409` | 重名导入 |
| `503` | 时间未同步（既没对过时，NVS 里也没历史对时记录） |

---

## 4. agent 用法示例

```bash
# 一次性拿全部码，挑自己要的
curl -s http://otpserver.local/otp | jq -r '.entries[] | "\(.name)\t\(.code)\t\(.remaining)s"'

# 只要一个
code=$(curl -s http://otpserver.local/otp/github | jq -r .code)

# 先看时间可不可信，再看码
curl -s http://otpserver.local/status | jq '.time'
```

给 agent 的三条建议：

1. 取码前不在意 503 —— 那是「还没对上时」，重试几秒即可
2. `remaining` 很小时（比如 < 5s）等一下再取，避免拿到即将过期的码去登录
3. `GET /otp` 一次拿全部比逐个 `GET /otp/{name}` 更省事；接口都用短连接，没有状态

---

## 5. 时间源

TOTP 完全取决于 UTC 时间是否准确，而板子**没有 RTC 电池**，每次上电都从 1970 开始：

| `time.source` | 含义 | 行为 |
|---|---|---|
| `ntp` | SNTP 对时成功 | 正常出码，最可信 |
| `estimate` | 对时没成功，但有历史对时记录 | 用「NVS 里上次对时 + 开机后经过的秒数」估算；能出码但**可能漂**，`/status` 里带 `warning` 字段 |
| `none` | 从没对过时 | `GET /otp*` 返回 `503` |

细节：

- SNTP 服务器在 `src/secrets.h` 里配（默认 `ntp.aliyun.com` / `cn.pool.ntp.org`）
- 对时成功的时刻每 **60 秒**落盘一次（NVS `otp/ts`），所以断网重启后估算起点最多旧 1 分钟
- SNTP 停掉后系统时钟会继续走，但长时间不同步会累积漂移；`/status` 的 `synced` 能让你判断该不该信
- ⚠️ 估算模式的隐藏前提：**断电时间不能长**。`last_sync + uptime` 不知道关机期间过了多久，
  断电几小时/几天后估算会偏几小时/几天（不是几秒）。这种场景应该等对时成功再用，
  或者把设备接在一个能通 NTP 的网络里。

---

## 6. 存储

- 路径：LittleFS 上的 `/otp/secrets.json`（明文 Base32）
- 格式：`{"version":1,"entries":[{"name":"...","secret":"..."}]}`
- 整表常驻 RAM（32 条上限 × ~180B）
- 写回是「写临时文件 → 删旧文件 → rename」，掉电不会留下半个文件
- 文件损坏时**拒绝服务而不是覆盖**（宁可 503，也不静默抹掉你导入的密钥）

⚠️ `pio run -t uploadfs` 会重建整个 LittleFS，**密钥表会被清掉**。刷写只烧 app（`-t upload`）就够了。

---

## 7. 安全模型（务必读完）

1. **无鉴权**：局域网内任何设备 / 任何 agent 都能读到你的所有 OTP。前提是 4.x 段受控（见 `/root/esp32/AGENTS.md`）。需要边界的话，下一步是加 Bearer Token——故意没做，保持"最小"。
2. **不能导出 ≠ 不能读取**：API 层拿不到 secret，但 secret 是**明文**存在 Flash 里的。能物理接触板子并 `esptool read_flash` 的人依然能读出来。要防这个得上 eFuse 加密分区，成本高得多，没做。
3. **能导入的人 = 能删你的人**：没有分级权限。
4. 板子不向外网暴露；Wi-Fi 只支持 2.4GHz。

---

## 8. 测试

```bash
# 算法层：RFC 6238 官方测试向量，主机侧 g++ 编译运行（不用板子）
./tools/run_selftest.sh

# 端到端：对设备跑全套 API 断言（含与独立 Python 实现的逐秒比对）
python3 tools/e2e_test.py http://192.168.4.4
```

`tools/import_migration.py` 是 Google Authenticator 迁移包导入器（见 API 一节），
每条导入后会用本地 TOTP 实现核对设备返回的码，导入即验证。

`e2e_test.py` 覆盖：RFC 向量出码一致性、6 位补零、`remaining` 范围、列表/导入/删除/404/409、
非 TOTP 参数拒绝、三种导入写法，以及"响应里没有 secret"。

---

## 9. 已知限制

- 只支持 TOTP / SHA1 / 30 秒 / 6 位（故意不做可配置，减少出错面）
- 条目上限 32，名字 1..48 字节，允许 `A-Z a-z 0-9 . _ - @ +`
- 名字里的 `@ + %` 等字符在 URL 里要做百分号编码（服务端会解码路径段，但不会把 `+` 当空格）
- 没有鉴权、没有 HTTPS（局域网内明文 HTTP）
- 没有 OTA 上传入口（分区已预留双槽，将来可加）
- 不带 `Content-Type: application/json` 的纯 JSON 请求体拿不到原始字节（Arduino WebServer 会把
  form-urlencoded 的 body 拆成参数），这种情况请用表单/query 写法，或补上 header

---

## 10. 目录

```
platformio.ini          工具链 / 目标板
partitions.csv          16MB 分区表（双 OTA + LittleFS + coredump）
src/main.cpp            Wi-Fi / SNTP / HTTP 路由
src/otpstore.{h,cpp}    密钥表（RAM + LittleFS 原子写回）
src/base32.{h,cpp}      Base32/hex 解码、Base32 编码（仅存储用）
src/timekeeper.{h,cpp}  SNTP + 估算回退
src/tinyotp/            tinyotp 移植（SHA1 / HMAC / 动态截断）
tools/run_selftest.sh   RFC 6238 自检
tools/e2e_test.py       端到端 API 验证
tools/import_migration.py  Google Authenticator 导出包导入器
src/secrets.h           Wi-Fi 凭据（不入库，见 .gitignore）
```
