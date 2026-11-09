#!/usr/bin/env python3
"""把 Google Authenticator 的导出包（otpauth-migration:// URI）导入 otpserver。

用法：
    python3 tools/import_migration.py uris.txt                 # 文件里每行一个 URI
    python3 tools/import_migration.py --base http://x uris.txt
    python3 tools/import_migration.py --dry-run uris.txt        # 只解码，不导入

为什么要这个脚本：otpserver 只接受 otpauth://totp/... 或 JSON，而 Google Authenticator
的"导出账户"给出的是 otpauth-migration://offline?data=<protobuf>，里面一次打包多条。
这里用 30 行手写 protobuf 解析把它拆成逐条 secret，再走正常 POST /otp 导入。

条目名只能是 ASCII（服务端规则），所以名字按 `issuer-账号` 生成：
非 ASCII 的 issuer 走下面的 PINYIN 词表（可以自己加一行），账号里的空格等字符变成 '-'。
重名会自动加 -2/-3 后缀。
"""

import argparse
import base64
import hashlib
import hmac
import json
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# issuer 里的中文 -> 拼音（不够就自己加）
PINYIN = {
    "坚果云": "jianguoyun",
    "火山引擎": "huoshan",
    "动视": "dongshi",
    "腾讯": "tencent",
    "阿里云": "aliyun",
    "百度云": "baiducloud",
    "百度": "baidu",
    "华为": "huawei",
    "飞书": "feishu",
    "网易": "netease",
    "京东": "jd",
    "小米": "xiaomi",
    "知乎": "zhihu",
    "微博": "weibo",
    "哔哩哔哩": "bilibili",
    "快手": "kuaishou",
    "抖音": "douyin",
    "拼多多": "pinduoduo",
    "美团": "meituan",
    "携程": "ctrip",
    "钉钉": "dingtalk",
    "支付宝": "alipay",
    "企业微信": "wxwork",
}

ALG = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}
DIG = {0: "6", 1: "6", 2: "8"}
TYP = {0: "TOTP", 1: "HOTP", 2: "TOTP"}


# ---------- protobuf ----------

def _varint(b, i):
    r = s = 0
    while True:
        if i >= len(b):
            raise ValueError("varint overrun")
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, i
        s += 7


def _fields(b):
    i = 0
    while i < len(b):
        key, i = _varint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 2:
            ln, i = _varint(b, i)
            if i + ln > len(b):
                raise ValueError("length overrun")
            v = b[i:i + ln]
            i += ln
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        else:
            raise ValueError(f"bad wire type {wt}")
        yield f, v


def decode_uri(uri):
    """otpauth-migration:// URI -> [(secret_bytes, issuer, name, algo, digits, type)]"""
    if "data=" not in uri:
        raise ValueError("not an otpauth-migration URI")
    payload = urllib.parse.unquote(uri.split("data=", 1)[1]).rstrip("=")
    raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True)
    out = []
    for f, v in _fields(raw):
        if f != 1:
            continue  # 2/3/4/5 是 version / batch_size / batch_index / batch_id
        d = {ff: vv for ff, vv in _fields(v)}
        out.append((
            d.get(1, b""),
            d.get(3, b"").decode("utf-8", "replace"),
            d.get(2, b"").decode("utf-8", "replace"),
            ALG.get(d.get(4, 0), "?"),
            DIG.get(d.get(5, 0), "?"),
            TYP.get(d.get(6, 0), "?"),
        ))
    return out


# ---------- 命名 ----------

def slug(text, pinyin_map=PINYIN):
    for zh, py in sorted(pinyin_map.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(zh, "-" + py + "-")
    text = re.sub(r"[账号帐號]+", "-", text)
    text = text.replace("：", "-").replace(":", "-")
    out = []
    for ch in text:
        if ch.isascii() and (ch.isalnum() or ch in "._@+"):
            out.append(ch)
        elif ch.isascii() or ch in " \t":
            out.append("-")
        # 其余字符（未收录的中文等）直接丢掉
    s = re.sub(r"-+", "-", "".join(out)).strip("-._")
    return s.lower()


def make_name(issuer, account, taken):
    head = slug(issuer)
    tail = slug(account) or "otp"
    base = f"{head}-{tail}" if head else tail
    base = base[:47].strip("-._") or "otp"
    name, n = base, 1
    while name in taken:
        n += 1
        name = f"{base[:46]}-{n}"
    taken.add(name)
    return name


# ---------- 与设备比对 ----------

def ref_totp(key, ts, period=30, digits=6):
    mac = hmac.new(key, struct.pack(">Q", ts // period), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def post(base, path, body):
    req = urllib.request.Request(
        base + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://192.168.4.4")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("file", help="每行一个 otpauth-migration:// URI")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    uris = [l.strip() for l in open(args.file) if l.strip().startswith("otpauth-migration://")]
    entries, bad = [], []
    for i, u in enumerate(uris, 1):
        try:
            for e in decode_uri(u):
                entries.append(e)
            print(f"[batch {i}] 解出 {len(decode_uri(u))} 条")
        except Exception as ex:  # 粘贴丢字符时 protobuf 会错位，直接报出来
            bad.append((i, str(ex)))
            print(f"[batch {i}] !! 解码失败：{ex}")

    taken, skipped, plan = set(), [], []
    for secret, issuer, account, algo, digits, typ in entries:
        if typ != "TOTP" or algo != "SHA1" or digits != "6":
            skipped.append((issuer, account, algo, digits, typ))
            continue
        plan.append((secret, issuer, account, make_name(issuer, account, taken)))

    # 已存在的条目名也要避开
    st, lst = get(base, "/otp")
    if st == 200:
        for e in lst.get("entries", []):
            taken.add(e["name"])

    print(f"\n{'条目名':34} {'来源':38} 结果")
    print("-" * 92)
    failed = 0
    for secret, issuer, account, name in plan:
        b32 = base64.b32encode(secret).decode().rstrip("=")
        src = f"{issuer or '(无 issuer)'}:{account}" if issuer else account
        if args.dry_run:
            print(f"{name:34} {src:38} dry-run")
            continue
        code, body = post(base, "/otp", {"name": name, "secret": b32})
        existed = (code == 409)
        if code not in (200, 201) and not existed:
            print(f"{name:34} {src:38} 失败 {code} {body.get('error')}")
            failed += 1
            continue
        # 用本地实现核对设备返回的码（顺带验证 base32 解码与落盘都对）
        _, got = get(base, "/otp/" + name)
        expect = ref_totp(secret, int(time.time()))
        mark = "OK" if got.get("code") in (expect, ref_totp(secret, int(time.time()) - 1)) else \
            f"码不符 设备={got.get('code')} 本地={expect}"
        if not mark.startswith("OK"):
            failed += 1
        print(f"{name:34} {src:38} {'已存在' if existed else '201'} {mark}")

    for issuer, account, algo, digits, typ in skipped:
        print(f"跳过 {issuer}:{account} —— 只支持 SHA1/6 位/TOTP，实际是 {algo}/{digits}/{typ}")
    for i, why in bad:
        print(f"batch {i} 有损坏，未导入：{why}")

    print(f"\n共 {len(plan)} 条，成功 {len(plan) - failed}，失败 {failed}，跳过 {len(skipped)}，"
          f"损坏批次 {len(bad)}")
    return 1 if failed or bad else 0


if __name__ == "__main__":
    sys.exit(main())
