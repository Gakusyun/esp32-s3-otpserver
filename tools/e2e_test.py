#!/usr/bin/env python3
"""otpserver 端到端验证脚本（主机侧跑，不占用串口）。

用法：
    python3 tools/e2e_test.py                       # 默认 http://192.168.4.4
    python3 tools/e2e_test.py http://otpserver.local

验的东西：
  * TOTP 结果与独立实现（RFC 6238，纯 hmac）逐秒对齐
  * 6 位补零、30 秒周期翻转
  * 导入 / 列表 / 删除 / 404 / 409 语义
  * 任何响应都不含 secret（导入后不可导出）
  * 非 TOTP 参数被拒绝（HOTP / SHA256 / 8 位 / 60 秒）
"""

import base64
import hashlib
import hmac
import json
import struct
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://192.168.4.4"

# RFC 4226 附录 D 的种子（20 字节 ASCII），用 Base32 编码后喂给设备
SEED = b"12345678901234567890"
SEED_B32 = base64.b32encode(SEED).decode()

failures = []


def check(cond, label, extra=""):
    print(("  OK   " if cond else "  FAIL ") + label + (f"  {extra}" if extra else ""))
    if not cond:
        failures.append(label)


def call(method, path, body=None, raw=None):
    data = None
    headers = {}
    if raw is not None:
        data = raw.encode()
        headers["Content-Type"] = "text/plain"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            payload = r.read()
            return r.status, payload, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def get_json(method, path, body=None, raw=None):
    status, payload, _ = call(method, path, body, raw)
    try:
        return status, json.loads(payload) if payload.strip() else None
    except json.JSONDecodeError:
        return status, payload.decode(errors="replace")


def ref_totp(key: bytes, ts: int, period: int = 30, digits: int = 6) -> str:
    counter = int(ts) // period
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def wait_for_sync(timeout=45):
    """设备重启后要等 Wi-Fi + SNTP；没同步前 API 走估算模式，比的码会错。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st, status = get_json("GET", "/status")
            if st == 200 and status["time"]["synced"]:
                return status
        except Exception:
            pass
        time.sleep(1)
    return None


def cleanup(prefix="e2e-"):
    """删掉上次跑测试留下的条目，保证脚本可重复运行。"""
    try:
        st, lst = get_json("GET", "/otp")
        if st == 200:
            for e in lst.get("entries", []):
                if e["name"].startswith(prefix) or e["name"] == "dbg1":
                    call("DELETE", "/otp/" + e["name"])
    except Exception:
        pass


def main():
    print(f"目标: {BASE}\n")
    cleanup()

    print("[0] 等待 SNTP 对时")
    st = wait_for_sync()
    check(st is not None, "时间已通过 SNTP 同步",
          f"source={st['time']['source'] if st else 'n/a'}")

    print("\n[1] 服务信息 / 状态")
    st, root = get_json("GET", "/")
    check(st == 200 and root.get("service") == "otpserver", "GET / 返回服务信息", str(root)[:80])
    st, status = get_json("GET", "/status")
    check(st == 200 and status["time"]["synced"] is True, "GET /status 时间已同步",
          f"source={status['time']['source']} entries={status['store']['entries']}")

    name = "e2e-rfc"
    print(f"\n[2] 导入 Base32 secret（{SEED_B32}）")
    st, body = get_json("POST", "/otp", {"name": name, "secret": SEED_B32})
    check(st == 201, "POST /otp 返回 201", str(body))
    check("secret" not in json.dumps(body), "导入响应里没有 secret")

    print("\n[3] 取码并与独立实现比对（连续 6 秒）")
    mismatched = 0
    for _ in range(6):
        got = None
        expect = None
        for _try in range(3):
            now = int(time.time())
            st, got = get_json("GET", f"/otp/{name}")
            expect = ref_totp(SEED, now)
            # 跨秒/跨步长边界时重取一次，保证比较的是同一段时间
            if got.get("code") == expect:
                break
            time.sleep(0.3)
        if got.get("code") != expect:
            mismatched += 1
            print(f"       t={int(time.time())} device={got.get('code')} ref={expect}")
        time.sleep(1)
    check(mismatched == 0, "设备出码与 RFC 6238 参考实现一致")
    check(len(got.get("code", "")) == 6 and got["code"].isdigit(), "6 位数字且补零",
          got.get("code"))
    check(1 <= got.get("remaining", 0) <= 30, "remaining 在 1..30", str(got.get("remaining")))

    print("\n[4] 列表接口")
    st, lst = get_json("GET", "/otp")
    names = [e["name"] for e in lst.get("entries", [])]
    check(st == 200 and name in names, "GET /otp 能看到条目", str(names))
    check("secret" not in json.dumps(lst), "列表响应里没有 secret")

    print("\n[5] 重复导入 / 非法参数")
    st, _ = get_json("POST", "/otp", {"name": name, "secret": SEED_B32})
    check(st == 409, "重名返回 409", str(st))
    for label, payload in [
        ("HOTP 拒绝", {"name": "e2e-hotp", "otpauth": f"otpauth://hotp/x?secret={SEED_B32}"}),
        ("SHA256 拒绝", {"name": "e2e-sha256",
                         "otpauth": f"otpauth://totp/x?secret={SEED_B32}&algorithm=SHA256"}),
        ("8 位拒绝", {"name": "e2e-d8", "otpauth": f"otpauth://totp/x?secret={SEED_B32}&digits=8"}),
        ("60 秒拒绝", {"name": "e2e-p60", "otpauth": f"otpauth://totp/x?secret={SEED_B32}&period=60"}),
        ("短密钥拒绝", {"name": "e2e-short", "secret": "ABCDEFGH"}),
        ("非法名拒绝", {"name": "bad name!", "secret": SEED_B32}),
        ("非法 base32 拒绝", {"name": "e2e-bad", "secret": "0189!!!!"}),
    ]:
        st, body = get_json("POST", "/otp", payload)
        check(st == 400, label, f"status={st} {str(body)[:60]}")

    print("\n[6] otpauth URI 导入（label 里有 '@'，且用裸 URI 当请求体）")
    uri = f"otpauth://totp/Example:alice@google.com?secret={SEED_B32}&issuer=Example"
    st, body = get_json("POST", "/otp", None, raw=uri)
    check(st == 201 and body.get("name") == "alice@google.com", "裸 otpauth URI 当请求体",
          str(body)[:80])
    st, _ = get_json("DELETE", "/otp/alice@google.com")
    check(st == 204, "清理 URI 导入的条目", str(st))

    print("\n[7] 表单 / query 两种省事写法")
    form = f"name=e2e-form&secret={SEED_B32}"
    req = urllib.request.Request(BASE + "/otp", data=form.encode(), method="POST",
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as r:
        ok_form = r.status == 201
    check(ok_form, "表单字段导入", "")
    st, body = get_json("POST", f"/otp?name=e2e-query&secret={SEED_B32}")
    check(st == 201, "query 参数导入", str(st))
    st, got = get_json("GET", "/otp/e2e-form")
    check(got.get("code") == ref_totp(SEED, int(time.time())) or
          got.get("code") == ref_totp(SEED, int(time.time()) - 1), "表单导入的条目能出码",
          str(got.get("code")))
    for n in ("e2e-form", "e2e-query"):
        get_json("DELETE", f"/otp/{n}")

    print("\n[8] 删除语义")
    st, payload, _ = call("DELETE", f"/otp/{name}")
    check(st == 204, "DELETE 返回 204（无响应体）", str(st))
    check(payload == b"", "204 响应体为空")
    st, _ = get_json("DELETE", f"/otp/{name}")
    check(st == 404, "重复删除返回 404", str(st))
    st, _ = get_json("GET", f"/otp/{name}")
    check(st == 404, "删除后取码 404", str(st))

    print("\n[9] 其他 HTTP 语义")
    st, _ = get_json("PUT", f"/otp/{name}", {"x": 1})
    check(st in (404, 405), "PUT 不提供写接口", str(st))
    st, _ = get_json("GET", "/nope")
    check(st == 404, "未知路径 404", str(st))

    print()
    if failures:
        print(f"{len(failures)} 项失败: {failures}")
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
