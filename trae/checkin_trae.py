# -*- coding: utf-8 -*-
"""Trae CN 客户端 每日自动签到（多账号）

通过 HTTP API 调用官方签到接口（读取本地登录态，无需打开客户端）。
- 只读登录态与设备 ID 文件，不修改客户端文件
- 多账号：各客户端目录的登录态会汇总到同目录 accounts.json（按 userId 归并），
  之后每天对 accounts.json 里的所有账号依次签到
- 自动吸收登录态：每次运行都会重新扫描本机客户端的 storage.json，
  新登录（或切换过）的账号会自动登记；开着 --watch 时切换账号可即时捕获
- 命令行登录：--login 会起本地回调并打开浏览器完成登录，不依赖 Trae 客户端；
  优先复用客户端已注册的设备号 + 设备密钥，登录出来的账号和自己打开客户端登录一致
- token 过期不硬撑：续期请求需要设备证明，服务端按设备绑定校验，
  脚本不模拟；过期后重新 --login（或打开 Trae 客户端）即可
- 请求头与官方客户端一致（x-device-id / x-machine-id）
- 随机延时启动 1~15 分钟，避开整点高峰限流（9074）；账号之间再随机间隔几秒
- 单次运行限时 25 分钟（计划任务里两个产品错开 30 分钟启动）：预算用完就不再开新账号、
  也不再硬等限流重试，剩下的留给下午的补签任务，保证两边的日志按时间段能分开
- 不打印 token；accounts.json 内含 token，已在 .gitignore 中忽略
- 日志写入仓库根目录 checkin.log（与 WorkBuddy 共用一份，每行带 [Trae] 前缀区分）；
  账号状态写入同目录 accounts.md（每签完一个账号刷新，含当前积分余额）

登录态格式兼容：
  · 明文 JSON（新客户端，`{...}` 开头）→ 直接解析
  · tc 加密（旧客户端，`dGMFEAAA...` 开头）→ base64 + AES-128-CBC 解密

命令行参数：
  --login         命令行加账号：打开浏览器登录，成功后直接写入 accounts.json
  --forget <账号> 删除账号（按账号名或 userId），并加入忽略列表
  --no-delay      跳过随机延时，立即请求（手动验证 / 补签用）
  --status-only   只查签到状态，不发起领取（安全的只读验证）
  --capture       只抓取本机登录态进 accounts.json，不签到
  --list          查看已捕获账号
  --watch [分钟]  监听登录态变化，自动捕获期间登录 / 切换的账号
"""
import base64
import hashlib
import json
import os
import platform
import random
import secrets
import sys
import time
import uuid
import webbrowser
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Util.Padding import unpad

# ---- 配置 ----
AUTH_KEY = "iCubeAuthInfo://icube.cloudide"

# 签到接口路径（host 由账号 host 字段提供；取不到时回退到 CN 域名）
CHECKIN_PATH = "/trae/api/v2/ug/checkin_credits"
DEFAULT_HOST = "https://api.trae.cn"

# 积分余额（用量）接口：客户端读的是同一个，返回 usage_summary.total_amount / consumed_amount
USAGE_PATH = "/trae/api/v2/pay/ide_user_ent_usage"

# ---- 命令行登录（浏览器 OAuth，与官方客户端同一套协议）----
LOGIN_HOST = "https://www.trae.cn"               # 授权页（product.json 的 authDomain）
API_BASE = DEFAULT_HOST                          # 登录后拿到的 token 走 api.trae.cn
CLIENT_ID = "ono9krqynydwx5"                     # Trae IDE stable 的 client_id
EXCHANGE_PATH = "/trae/api/v3/oauth/ExchangeToken"
USERINFO_PATH = "/cloudide/api/v3/trae/GetUserInfo"
LOGIN_TIMEOUT = 300                              # 等待浏览器登录回调的最长秒数

# 客户端版本号（启动时从本机 Trae 客户端的 product.json 读取，保证与官方一致）
def detect_versions() -> tuple:
    for base in (Path(r"D:\AiPrograms\Trae CN"),
                 Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Trae CN"):
        p = base / "resources" / "app" / "product.json"
        try:
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("version"):
                    return str(data["version"]), str(data.get("tronBuildVersion") or "local")
        except Exception:
            pass
    return "1.107.1", "local"


APP_VERSION, TRON_BUILD_VERSION = detect_versions()

# 客户端把注册到服务端的设备号持久化在该前缀的键名下（键名后缀即设备号）
ICUBE_DC_KEY_PREFIX = "iCubeAuthInfo://icube-dc:"

# iCube 登录态 tc 解密常量（仅旧格式需要）
HDR_LEN = 6
KEY_LEN = 32
HMAC_LEN = 64
URE = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37])
DRE = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])

# %APPDATA% 下的应用数据目录名（不存在的会静默跳过）
# 本机只保留 Trae CN；其它 Trae 变体已卸载，相关目录已清理
APP_DIRS = [
    r"Trae CN",        # CN IDE
]

# 手动添加路径（可选，支持目录或直接指向 storage.json）
EXTRA_PATHS = [
]

# 手动指定设备号 / 机器码（可选，留空则从客户端本地文件自动读取）
DEVICE_ID_FALLBACK = ""
MACHINE_ID_FALLBACK = ""

# 领取接口的 req_source：Trae IDE 为 1
REQ_SOURCE_MAP = {
    "Trae CN": 1,
}
DEFAULT_REQ_SOURCE = 1

# 重试计划：第 N 次请求所用的设备号来源（real=客户端真实设备号 / random=随机设备号）
# 与发起该次请求前的随机等待区间（秒）
# 9074 = 服务端「当前参与用户太多」的限流响应，等待时间逐级放大
RETRY_PLAN = (
    ("real", None),         # 第 1 次：立即请求
    ("real", (3, 8)),       # 第 2 次
    ("real", (10, 20)),     # 第 3 次
    ("random", (15, 30)),   # 第 4 次
    ("random", (20, 40)),   # 第 5 次
    ("random", (30, 60)),   # 第 6 次
)

# 随机延时启动区间（秒）
STARTUP_DELAY_RANGE = (60, 900)

# 本次运行的时间预算（分钟）：计划任务里 WorkBuddy 和 Trae 错开 30 分钟启动，
# 单个产品必须在半小时内跑完，日志才不会互相穿插（排查时按时间段就能分清）
RUN_BUDGET_MINUTES = 25
RUN_DEADLINE = 0.0       # main() 里初始化；0 表示不限时（--list / --watch 等命令）

# 多账号之间的随机间隔（秒），避免多个请求挤在同一秒
ACCOUNT_GAP_RANGE = (5, 15)

# --watch 的轮询间隔（秒）
WATCH_INTERVAL = 5

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR.parent / "checkin.log"   # 日志统一放仓库根目录（与 WorkBuddy 共用一份）
LOG_TAG = "Trae"                             # 每行日志的产品前缀，两个产品共用日志时用来区分
STORE_FILE = BASE_DIR / "accounts.json"   # 多账号登录态仓库（含 token，注意保密）
ACCOUNTS_MD = BASE_DIR / "accounts.md"    # 账号状态文档（每签完一个账号刷新）


def log(msg: str) -> None:
    # 每一行都带产品标签：账号相关的行就是 "[Trae] [账号名] ..."，
    # 和 WorkBuddy 的日志合在根目录同一个 checkin.log 里也能一眼分清是谁的
    tag = f"[{LOG_TAG}]"
    if msg.startswith(tag):
        msg = msg[len(tag):].lstrip()
    if msg and not msg.startswith("="):          # 纯分隔线不加前缀，免得碍眼
        msg = f"{tag} {msg}"
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def now_ms() -> int:
    return int(time.time() * 1000)


def time_left() -> float:
    """本次运行的时间预算还剩多少秒（没设预算时返回无穷大）"""
    return RUN_DEADLINE - time.time() if RUN_DEADLINE else float("inf")


def to_ms(value):
    """把 ISO 时间串转成毫秒时间戳，失败返回 0"""
    if not value:
        return 0
    if isinstance(value, (int, float)):
        v = int(value)
        return v * 1000 if 0 < v < 10 ** 12 else v      # 秒级时间戳自动换算成毫秒
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        return 0


def fmt_ts(ms) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "未知"


def read_json(path: Path) -> dict:
    """只读解析 JSON 文件，不存在或失败返回空 dict"""
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def read_text(path: Path) -> str:
    """只读读取文本文件并去空白，不存在或失败返回空串"""
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return ""


def decrypt_auth(b64_text: str) -> dict:
    """解密旧格式（tc 加密）iCubeAuthInfo 串，返回含 token / userRegion 的 dict"""
    t = base64.b64decode(b64_text)
    key = t[HDR_LEN:HDR_LEN + KEY_LEN]
    sha = hashlib.sha512(key).digest()
    xor = bytes(a ^ b for a, b in zip(URE, DRE))
    h = hashlib.sha512(sha + xor).digest()
    aes_key, iv = h[:16], h[16:32]
    ct = t[HDR_LEN + KEY_LEN:]
    plain = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
    return json.loads(plain[HMAC_LEN:].decode("utf-8"))


def parse_auth(enc: str) -> dict:
    """解析 iCubeAuthInfo://icube.cloudide 的值，自动识别两种格式"""
    s = enc.strip()
    if s.startswith("{"):
        return json.loads(s)          # 新格式：明文 JSON
    return decrypt_auth(s)            # 旧格式：tc 加密


def scan_targets() -> list:
    """扫描目标 [(名称, storage.json 路径, 应用数据目录)]，按路径去重"""
    appdata = os.environ.get("APPDATA", "")
    targets = [(n, Path(appdata) / n / "User" / "globalStorage" / "storage.json",
                Path(appdata) / n) for n in APP_DIRS]
    for raw in EXTRA_PATHS:
        p = Path(os.path.expandvars(raw)).expanduser()
        if p.suffix.lower() == ".json":
            app_dir = p.parents[2] if len(p.parents) > 2 else p.parent
            targets.append((p.parent.name, p, app_dir))
        else:
            targets.append((p.name, p / "User" / "globalStorage" / "storage.json", p))
    seen, uniq = set(), []
    for t in targets:
        key = str(t[1]).lower()
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq


def region_of(auth: dict) -> str:
    """取账号区域码（cn/sg…），用于 X-User-Region 头"""
    region = auth.get("userRegion") or "cn"
    if isinstance(region, dict):          # 新版为 {'region': 'CN', ...}
        region = region.get("region") or "cn"
    return str(region).lower() or "cn"


def parse_expired_at(auth: dict) -> int:
    return to_ms(auth.get("expiredAt"))


def scan_accounts() -> list:
    """扫描本机所有客户端的登录态，返回账号记录（不含 token 输出）"""
    found = []
    for name, path, app_dir in scan_targets():
        try:
            storage = read_json(path)
            enc = storage.get(AUTH_KEY)
            if not enc:
                continue
            auth = parse_auth(enc)
            token = auth.get("token")
            user_id = str(auth.get("userId") or "")
            if not token or not user_id:
                continue
            account = auth.get("account") or {}
            device = device_headers(app_dir, storage)
            found.append({
                "userId": user_id,
                "username": account.get("username") or account.get("email") or user_id,
                "token": token,
                "refreshToken": auth.get("refreshToken") or "",
                "host": (str(auth.get("host") or DEFAULT_HOST).rstrip("/")),
                "region": region_of(auth),
                "reqSource": REQ_SOURCE_MAP.get(name, DEFAULT_REQ_SOURCE),
                "expiresAt": parse_expired_at(auth),
                "refreshExpiresAt": to_ms(auth.get("refreshExpiredAt")),
                "deviceId": device.get("x-device-id", ""),
                "machineId": device.get("x-machine-id", ""),
                "source": str(path),
            })
        except Exception as e:
            log(f"[{name}] 登录态解析失败：{e}")
    return found


# ---- 多账号仓库 ----

def load_store() -> dict:
    data = read_json(STORE_FILE) if STORE_FILE.exists() else None
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("accounts"), dict):
        data = {"version": 1, "accounts": {}}
    if not isinstance(data.get("ignored"), list):
        data["ignored"] = []          # 已删除的账号，下次扫描客户端时不再收回来
    return data


def save_store(store: dict) -> None:
    store["version"] = 1
    tmp = STORE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, STORE_FILE)


def account_label(rec: dict) -> str:
    return rec.get("username") or rec.get("userId") or "?"


def status_row(rec: dict) -> tuple:
    """返回 (今日是否签到, 积分)；只认今天的数据"""
    st = rec.get("lastStatus") or {}
    if st.get("date") != datetime.now().strftime("%Y-%m-%d"):
        return False, None
    return bool(st.get("checked_in")), st.get("credit")


def fmt_credits(value) -> str:
    """积分数字：整数不带小数，其余保留两位"""
    if value is None:
        return "—"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{v:.0f}" if abs(v - round(v)) < 0.005 else f"{v:.2f}"


def balance_cell(rec: dict) -> str:
    """余额列：剩余 / 总额；还没读到过余额时显示 —"""
    bal = rec.get("balance") or {}
    left, total = bal.get("left"), bal.get("total")
    if left is None:
        return "—"
    if not total:
        return fmt_credits(left)
    return f"{fmt_credits(left)} / {fmt_credits(total)}"


def render_accounts_md(store: dict) -> None:
    """生成 accounts.md：账号 / userId / 今日签到 / 今日积分 / 剩余积分 + 合计"""
    accounts = sorted(store.get("accounts", {}).values(), key=account_label)
    lines = [
        "# Trae 账号签到状态",
        "",
        f"最后更新：{datetime.now():%Y-%m-%d %H:%M}",
        "",
        "| 账号 | userId | 今日签到 | 今日积分 | 积分余额（剩余/总额） |",
        "| --- | --- | --- | --- | --- |",
    ]
    total, done, left_sum, balance_known = 0, 0, 0.0, 0
    for rec in accounts:
        checked, credit = status_row(rec)
        if checked:
            done += 1
        if credit is not None:
            total += credit
        bal = rec.get("balance") or {}
        if bal.get("left") is not None:
            left_sum += float(bal["left"])
            balance_known += 1
        lines.append(
            "| {name} | `{uid}` | {checked} | {credit} | {balance} |".format(
                name=account_label(rec),
                uid=rec.get("userId", ""),
                checked="✅" if checked else "—",
                credit=credit if credit is not None else "—",
                balance=balance_cell(rec),
            )
        )
    lines += [
        "",
        f"今日已签到 **{done}/{len(accounts)}** 个账号，今日获得 **{fmt_credits(total)}** 积分。",
        f"账号积分余额合计 **{fmt_credits(left_sum)}**"
        f"（{balance_known}/{len(accounts)} 个账号读取成功）。",
        "",
    ]
    tmp = ACCOUNTS_MD.parent / "accounts.md.tmp"
    tmp.write_text("\n".join(lines), encoding="utf-8")
    os.replace(tmp, ACCOUNTS_MD)


def merge_into_store(store: dict, entries: list) -> list:
    """把扫描到的登录态并入仓库（按 userId），保留过期时间更晚的那份"""
    updated, accounts = [], store["accounts"]
    ignored = {str(x) for x in (store.get("ignored") or [])}
    for e in entries:
        uid = e.get("userId")
        if not uid or str(uid) in ignored:
            continue
        old = accounts.get(uid) or {}
        new_exp, old_exp = e.get("expiresAt") or 0, old.get("expiresAt") or 0
        use_new = not old.get("token") or new_exp >= old_exp
        rec = {
            "userId": uid,
            "username": e.get("username") or old.get("username") or uid,
            "token": e.get("token") if use_new else old.get("token"),
            "refreshToken": (e.get("refreshToken") if use_new else old.get("refreshToken")) or "",
            "host": (e.get("host") if use_new else old.get("host")) or DEFAULT_HOST,
            "region": (e.get("region") if use_new else old.get("region")) or "cn",
            "reqSource": (e.get("reqSource") if use_new else old.get("reqSource")) or DEFAULT_REQ_SOURCE,
            "expiresAt": (new_exp if use_new else old_exp) or 0,
            "refreshExpiresAt": (e.get("refreshExpiresAt") if use_new else old.get("refreshExpiresAt")) or 0,
            "deviceId": (e.get("deviceId") if use_new else old.get("deviceId")) or "",
            "machineId": (e.get("machineId") if use_new else old.get("machineId")) or "",
            "source": (e.get("source") if use_new else old.get("source")) or "",
            "updatedAt": now_ms(),
        }
        # 登录时生成的设备密钥只对“当前这份 token”有效；客户端刷新出新 token 后就不再用它
        if old.get("lastStatus") and old.get("token") == rec["token"]:
            rec["lastStatus"] = old["lastStatus"]
        if old.get("refreshedAt") and old.get("token") == rec["token"]:
            rec["refreshedAt"] = old["refreshedAt"]
        same = all(old.get(k) == rec[k] for k in
                   ("token", "refreshToken", "host", "expiresAt", "username"))
        if same:
            continue
        accounts[uid] = rec
        updated.append(rec)
    if updated:
        store["updatedAt"] = now_ms()
    return updated


# ---- 设备标识 ----

def random_device_id() -> str:
    """生成随机 16 位数字设备号"""
    return str(random.randint(10 ** 15, 10 ** 16 - 1))


def device_headers(app_dir: Path, storage: dict = None) -> dict:
    """构造与官方客户端一致的设备标识请求头（只读）
    - x-device-id：客户端已注册的本机设备号
    - x-machine-id：客户端 telemetry.machineId（64 位十六进制机器码）
    取不到时依次回退：telemetry.devDeviceId → machineid 文件 → 随机 16 位数字
    """
    if storage is None:
        storage = read_json(app_dir / "User" / "globalStorage" / "storage.json")
    device_id = DEVICE_ID_FALLBACK
    if not device_id:
        for key in storage:
            if key.startswith(ICUBE_DC_KEY_PREFIX):
                device_id = key[len(ICUBE_DC_KEY_PREFIX):].strip()
                break
    machine_id = MACHINE_ID_FALLBACK or str(storage.get("telemetry.machineId") or "")
    machine_file = read_text(app_dir / "machineid") or read_text(app_dir / "machineId")
    if not device_id:
        device_id = str(storage.get("telemetry.devDeviceId") or "") or machine_file
    if not machine_id:
        machine_id = machine_file
    if not device_id:
        device_id = random_device_id()
    headers = {"x-device-id": device_id}
    if machine_id:
        headers["x-machine-id"] = machine_id
    return headers


# ---- 命令行登录（浏览器 OAuth）----

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def generate_keypair() -> tuple:
    """生成设备密钥对（EC P-256），返回 (私钥 PKCS#8 PEM, 公钥 SPKI PEM)"""
    key = ECC.generate(curve="P-256")
    return key.export_key(format="PEM"), key.public_key().export_key(format="PEM")


def build_device_info(public_pem: str, device_id: str, machine_id: str,
                      device_name: str = "") -> dict:
    """构造 ExchangeToken / 续期用的 DeviceInfo（字段与官方客户端一致）"""
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
    return {
        "DeviceID": device_id,
        "MachineID": machine_id,
        "PlatformCode": "IDE_PC",
        "DeviceType": "PC",
        "DeviceName": device_name or f"{user}{secrets.token_hex(4)}",
        "DeviceModel": platform.machine() or "",
        "ClientVersion": APP_VERSION,
        "DevicePublicKey": public_pem,
        "DeviceBrand": "PC",
        "DeviceCPU": platform.processor() or "",
        "OSInfo": f"{platform.system()} {platform.release()}".strip(),
        "OSVersion": platform.version(),
    }


def client_device_credentials() -> tuple:
    """取客户端已注册的设备号 + 设备密钥对（与官方客户端同一设备）
    返回 (device_id, machine_id, private_pem, public_pem)，取不到返回空串"""
    for _name, path, app_dir in scan_targets():
        storage = read_json(path)
        if not storage:
            continue
        headers = device_headers(app_dir, storage)
        for key in storage:
            if not key.startswith(ICUBE_DC_KEY_PREFIX):
                continue
            device_id = key[len(ICUBE_DC_KEY_PREFIX):].strip()
            try:
                keypair = decrypt_auth(str(storage[key]))
            except Exception:
                continue
            if keypair.get("privateKeyPEM") and keypair.get("publicKeyPEM"):
                return (device_id, headers.get("x-machine-id", ""),
                        keypair["privateKeyPEM"], keypair["publicKeyPEM"])
    return "", "", "", ""


def exchange_token(auth_code: str, code_verifier: str, device: dict) -> dict:
    """用浏览器回调里的授权码换 token（客户端同款接口）"""
    body = {
        "ClientID": CLIENT_ID,
        "AuthCode": auth_code,
        "CodeVerifier": code_verifier,
        "DeviceInfo": device,
        "IDEVersion": APP_VERSION,
    }
    r = requests.post(f"{API_BASE}{EXCHANGE_PATH}", json=body, timeout=30,
                      headers={"Content-Type": "application/json", "x-cloudide-token": ""})
    try:
        data = r.json()
    except ValueError:
        raise RuntimeError(f"HTTP {r.status_code}：{r.text[:200]}")
    result = data.get("Result") or {}
    if not result.get("Token"):
        err = ((data.get("ResponseMetadata") or {}).get("Error") or {}).get("Message") \
            or data.get("Message") or data.get("msg") or str(data)[:200]
        raise RuntimeError(f"HTTP {r.status_code}：{err}")
    return result


def get_user_info(token: str, device: dict) -> dict:
    """取用户名（ScreenName），失败不影响登录本身"""
    try:
        r = requests.post(
            f"{API_BASE}{USERINFO_PATH}",
            json={"ReqSource": "IDE", "IDEVersion": APP_VERSION},
            headers={"Content-Type": "application/json", "x-cloudide-token": token,
                     "x-device-id": device.get("DeviceID", "")},
            timeout=30,
        )
        return (r.json().get("Result") or {})
    except Exception:
        return {}


def parse_callback(query: dict, default_verifier: str) -> tuple:
    """从回调参数里取授权码 / PKCE 校验串：优先 authCodeInfo.AuthCode"""
    code = ""
    info = query.get("authCodeInfo") or ""
    if info:
        try:
            data = json.loads(info)
            code = str(data.get("AuthCode") or data.get("authCode") or "")
        except Exception:
            pass
    if not code:
        code = query.get("code") or query.get("auth_code") or ""
    return code, query.get("codeVerifier") or default_verifier


def cmd_login(timeout: float = LOGIN_TIMEOUT) -> int:
    """命令行加账号：本地起回调 → 浏览器登录 → ExchangeToken → 写入 accounts.json"""
    code_verifier = b64url(secrets.token_bytes(48))
    code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())
    # 优先用客户端已注册的设备号 + 设备密钥，登录结果与官方客户端同设备
    device_id, machine_id, _private_pem, public_pem = client_device_credentials()
    if public_pem:
        log(f"[Trae] 复用客户端设备：{device_id}")
    else:
        device_id, machine_id = str(uuid.uuid4()), secrets.token_hex(32)
        _private_pem, public_pem = generate_keypair()
        log("[Trae] 没有找到客户端设备密钥，本次登录使用新的虚拟设备")
    device = build_device_info(public_pem, device_id, machine_id)

    received = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):        # 静音默认访问日志
            pass

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path != "/authorize":
                self.send_response(404)
                self.end_headers()
                return
            for key, value in parse_qs(parsed.query, keep_blank_values=True).items():
                received[key] = value[0]
            page = ("<!doctype html><html><head><meta charset='utf-8'><title>Trae 登录</title>"
                    "</head><body style='font-family:sans-serif;padding:48px'>"
                    "<h2>已收到登录信息</h2><p>可以关闭此页面，回到命令行查看结果。</p>"
                    "</body></html>")
            data = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = HTTPServer(("127.0.0.1", 0), CallbackHandler)
    server.timeout = 1
    port = server.server_address[1]

    params = {
        "login_version": 1,
        "auth_from": "trae",
        "login_channel": "native_ide",
        "plugin_version": TRON_BUILD_VERSION,
        "auth_type": "local",
        "client_id": CLIENT_ID,
        "redirect": 0,
        "login_trace_id": str(uuid.uuid4()),
        "auth_callback_url": f"http://127.0.0.1:{port}/authorize",
        "machine_id": machine_id,
        "device_id": device_id,
        "x_device_id": device_id,
        "x_machine_id": machine_id,
        "x_device_brand": device["DeviceModel"],
        "x_device_type": device["OSInfo"],
        "x_os_version": device["OSVersion"],
        "x_app_version": APP_VERSION,
        "x_app_type": "stable",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    login_url = f"{LOGIN_HOST}/authorization?{urlencode(params)}"

    log("=" * 50)
    log("[Trae] 命令行登录：请在弹出的浏览器里登录 Trae 账号")
    log("=" * 50)
    try:
        webbrowser.open(login_url)
    except Exception:
        pass
    log(f"[Trae] 浏览器没有自动打开的话，手动访问这个地址：\n{login_url}")
    log(f"[Trae] 等待登录回调（最多 {int(timeout // 60)} 分钟）…")

    deadline = time.time() + timeout
    try:
        while not received and time.time() < deadline:
            server.handle_request()
    finally:
        server.server_close()

    if not received:
        log("[Trae] 登录超时：没有收到浏览器回调，请重试")
        return 1

    auth_code, verifier = parse_callback(received, code_verifier)
    if not auth_code:
        log(f"[Trae] 回调里没有授权码（收到字段：{'、'.join(received)}）")
        return 1

    log("[Trae] 已收到授权码，正在换取登录态…")
    try:
        result = exchange_token(auth_code, verifier, device)
    except Exception as e:
        log(f"[Trae] 换取登录态失败：{e}")
        return 1

    user_info = get_user_info(result["Token"], device)
    user_id = str(user_info.get("UserID") or result.get("UserID") or "")
    if not user_id:
        log(f"[Trae] 服务端没有返回 UserID，登录未完成"
            f"（ExchangeToken 字段：{'、'.join(result)}；GetUserInfo 字段：{'、'.join(user_info) or '空'}）")
        return 1

    username = (user_info.get("ScreenName") or user_info.get("NonPlainTextEmail")
                or received.get("userTag") or user_id)

    store = load_store()
    old = store["accounts"].get(user_id) or {}
    rec = {
        "userId": user_id,
        "username": username,
        "token": result["Token"],
        "refreshToken": result.get("RefreshToken") or "",
        "host": API_BASE,
        "region": str(user_info.get("AIRegion") or result.get("AIRegion") or "cn").lower(),
        "reqSource": 1,
        "expiresAt": to_ms(result.get("TokenExpireAt"))
                     or (now_ms() + int(result.get("TokenExpireDuration") or 0) * 1000),
        "refreshExpiresAt": to_ms(result.get("RefreshExpireAt")),
        "deviceId": device["DeviceID"],
        "machineId": device["MachineID"],
        "source": "login",
        "loggedInAt": now_ms(),
        "updatedAt": now_ms(),
    }
    if old.get("lastStatus"):
        rec["lastStatus"] = old["lastStatus"]
    # 顺便读一次积分余额，accounts.md 里立刻能看到这个账号还有多少积分
    bal = fetch_balance(rec)
    if bal:
        rec["balance"] = bal
    store["accounts"][user_id] = rec
    store["updatedAt"] = now_ms()
    save_store(store)
    render_accounts_md(store)
    log(f"[Trae] 登录成功：{username}（userId={user_id}），"
        f"token 到期 {fmt_ts(rec['expiresAt'])}，已写入 accounts.json")
    if bal:
        log(f"[Trae] 当前积分余额 {fmt_credits(bal['left'])} / {fmt_credits(bal['total'])}")
    return 0


# ---- 接口 ----

def api_base(rec: dict) -> str:
    host = str(rec.get("host") or "").strip().rstrip("/") or DEFAULT_HOST
    return host + CHECKIN_PATH


def api(path: str, rec: dict, device_id: str = None) -> dict:
    """调用签到相关接口（status / claim），请求体与官方客户端一致"""
    token = rec["token"]
    headers = {
        "Authorization": token if token.startswith("Cloud-IDE-JWT") else f"Cloud-IDE-JWT {token}",
        "X-User-Region": rec.get("region") or "cn",
        "Content-Type": "application/json",
        "x-device-id": device_id or rec.get("deviceId") or random_device_id(),
    }
    if rec.get("machineId"):
        headers["x-machine-id"] = rec["machineId"]
    r = requests.post(f"{api_base(rec)}/{path}", headers=headers,
                      json={"req_source": rec.get("reqSource") or DEFAULT_REQ_SOURCE}, timeout=30)
    return r.json()


def read_checked_in(status: dict):
    """从 status 响应里判断是否已签到、取积分。兼容顶层与 data 层。"""
    if not status:
        return False, None
    data = status.get("data") or {}
    for layer in (status, data):
        for k in ("checked_in", "today_checked_in", "is_checked_in", "checkedIn"):
            if isinstance(layer.get(k), bool) and layer[k]:
                credit = (layer.get("credits") or layer.get("credit")
                          or layer.get("total_credits"))
                return True, credit
    credit = data.get("credits") or status.get("credits")
    return False, credit


def fetch_balance(rec: dict):
    """读取账号当前的积分余额（客户端「用量」面板同款接口）。

    返回 {left, total, used, updatedAt}；失败返回 None。
    Trae 的积分按「积分包」发放：usage_summary.total_amount 是本期总额度、
    consumed_amount 是已消耗，相减即客户端显示的剩余积分。"""
    name = f"{account_label(rec)} {rec.get('userId', '')}"
    token = rec.get("token") or ""
    host = str(rec.get("host") or "").strip().rstrip("/") or DEFAULT_HOST
    headers = {
        "Content-Type": "application/json",
        "Authorization": token if token.startswith("Cloud-IDE-JWT") else f"Cloud-IDE-JWT {token}",
        "X-User-Region": rec.get("region") or "cn",
        "x-device-id": rec.get("deviceId") or random_device_id(),
    }
    if rec.get("machineId"):
        headers["x-machine-id"] = rec["machineId"]

    try:
        r = requests.post(f"{host}{USAGE_PATH}", headers=headers,
                          json={"require_usage": True,
                                "req_source": rec.get("reqSource") or DEFAULT_REQ_SOURCE},
                          timeout=30)
        data = r.json()
    except Exception as e:
        log(f"[{name}] 查询积分余额失败：{type(e).__name__}")
        return None

    summary = data.get("usage_summary") or {}
    try:
        total = float(summary.get("total_amount") or 0)
        consumed = float(summary.get("consumed_amount") or 0)
    except (TypeError, ValueError):
        total, consumed = 0.0, 0.0

    if not total:
        # 兜底：自己按积分包累加（额度 - 已用）
        for pack in data.get("user_entitlement_pack_list") or []:
            quota = ((pack.get("entitlement_base_info") or {}).get("quota") or {})
            try:
                total += float(quota.get("credits_limit") or 0)
                consumed += float((pack.get("usage") or {}).get("credits_amount") or 0)
            except (TypeError, ValueError):
                continue

    if not total:
        msg = data.get("message") or data.get("msg") or f"code={data.get('code')}"
        log(f"[{name}] 查询积分余额失败：{msg}")
        return None

    return {
        "left": round(max(total - consumed, 0.0), 2),
        "total": round(total, 2),
        "used": round(consumed, 2),
        "updatedAt": now_ms(),
    }


# ---- 签到 ----

def checkin_api(rec: dict, status_only: bool = False) -> tuple:
    """HTTP API 签到，返回 (结果, 状态信息)，结果为 True / False / "skip"(登录态过期)"""
    name = f"{account_label(rec)} {rec.get('userId', '')}"
    exp = rec.get("expiresAt") or 0
    if exp and exp < now_ms():
        log(f"[{name}] 登录态已过期（{fmt_ts(exp)}），请运行 trae.bat --login 重新登录，"
            f"或用该账号打开一次 Trae 客户端（客户端会自动续期，脚本下次运行自动抓取）")
        return "skip", None

    log(f"[{name}] 使用设备号 {rec.get('deviceId') or '-'}"
        + (f"，机器码 {rec.get('machineId', '')[:8]}…" if rec.get("machineId") else "")
        + f"（req_source={rec.get('reqSource')}，区域={rec.get('region')}，接口={api_base(rec)}）")

    try:
        status = api("status", rec)
    except Exception as e:
        log(f"[{name}] 查询签到状态失败（继续尝试领取）：{e}")
        status = {}
    already, credit = read_checked_in(status)
    if status_only:
        log(f"[{name}] (status-only) " + ("今日已签到" if already else "今日尚未签到")
            + (f"，积分 {credit}" if credit else ""))
        return True, None
    if already:
        log(f"[{name}] (API) 今日已签到" + (f"，积分 {credit}" if credit else ""))
        return True, {"date": datetime.now().strftime("%Y-%m-%d"),
                      "checked_in": True, "credit": credit}

    for attempt, (source, wait) in enumerate(RETRY_PLAN, start=1):
        if wait:
            delay = random.uniform(*wait)
            # 重试等待可能很长，剩余预算不够就别硬等，直接收工留给补签
            if time_left() < delay + 30:
                log(f"[{name}] 剩余时间不足以再重试，本次跳过（留给下午的补签任务）")
                return False, None
            log(f"[{name}] {delay:.1f}s 后发起第 {attempt} 次请求"
                f"（{'沿用真实设备号' if source == 'real' else '改用随机设备号'}）")
            time.sleep(delay)
        dev = None if source == "real" else random_device_id()
        try:
            body = api("claim", rec, dev)
        except Exception as e:
            log(f"[{name}] 签到请求失败：{e}")
            return False, None
        code = body.get("code", -1)
        if code == 0 or body.get("checked_in"):
            got = body.get("credits") or body.get("credit") or credit
            log(f"[{name}] (API) 签到成功" + (f"，获得积分：{got}" if got else ""))
            return True, {"date": datetime.now().strftime("%Y-%m-%d"),
                          "checked_in": True, "credit": got}
        msg = str(body.get("message") or body.get("msg") or str(body)[:200])
        if "已" in msg and "签" in msg:
            log(f"[{name}] (API) 今日已签到")
            return True, {"date": datetime.now().strftime("%Y-%m-%d"),
                          "checked_in": True, "credit": credit}
        if code != 9074:
            log(f"[{name}] (API) 签到失败：code={code}，{msg}")
            return False, None
        log(f"[{name}] 第 {attempt} 次请求命中限流 9074：{msg}")
    log(f"[{name}] (API) 已重试 {len(RETRY_PLAN)} 次仍被限流 9074，本次签到未成功")
    return False, None


# ---- 命令 ----

def do_capture(reason: str = "") -> tuple:
    """扫描本机登录态并入仓库，返回 (store, 新增/更新列表)"""
    store = load_store()
    updated = merge_into_store(store, scan_accounts())
    if updated:
        save_store(store)
        render_accounts_md(store)
        names = "、".join(account_label(r) for r in updated)
        log(f"[Trae] 已保存 {len(updated)} 个账号的登录态：{names}{reason}")
    elif reason:
        log(f"[Trae] 登录态无变化{reason}")
    return store, updated


def cmd_forget(target: str) -> int:
    """删除账号并加入忽略列表，避免下次扫描客户端时又被收回来"""
    store = load_store()
    matches = [uid for uid, rec in store["accounts"].items()
               if uid == target or account_label(rec) == target]
    if not matches:
        log(f"[Trae] 没有找到账号：{target}")
        return 1
    for uid in matches:
        rec = store["accounts"].pop(uid)
        if uid not in store["ignored"]:
            store["ignored"].append(uid)
        log(f"[Trae] 已删除：{account_label(rec)}（userId={uid}），并加入忽略列表")
    store["updatedAt"] = now_ms()
    save_store(store)
    render_accounts_md(store)
    return 0


def print_overview(store: dict) -> None:
    accounts = store.get("accounts") or {}
    log(f"[Trae] 已捕获账号（accounts.json，共 {len(accounts)} 个）：")
    if not accounts:
        log("  （空）")
    for rec in sorted(accounts.values(), key=account_label):
        state = "已过期" if (rec.get("expiresAt") or 0) and rec["expiresAt"] < now_ms() else "可用"
        log(f"  - {account_label(rec)}  userId={rec.get('userId')}  状态={state}  "
            f"token 到期={fmt_ts(rec.get('expiresAt'))}  "
            f"续期凭证到期={fmt_ts(rec.get('refreshExpiresAt'))}  "
            f"区域={rec.get('region')}  来源={Path(rec.get('source', '')).stem or '—'}")


def watch(minutes: float) -> int:
    """监听客户端登录态，自动捕获期间登录/切换的账号"""
    log("=" * 50)
    log(f"[Trae] 监听登录态 {minutes:g} 分钟（每 {WATCH_INTERVAL}s 检查一次，Ctrl+C 结束）")
    log("=" * 50)
    store, _ = do_capture()
    seen = set(store["accounts"])
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        time.sleep(WATCH_INTERVAL)
        store, updated = do_capture()
        for rec in updated:
            if rec["userId"] not in seen:
                seen.add(rec["userId"])
                log(f"[Trae] 捕获到新账号：{account_label(rec)}（已捕获 {len(store['accounts'])} 个）")
    log(f"[Trae] 监听结束，当前已捕获 {len(store['accounts'])} 个账号")
    return 0


def startup_delay() -> None:
    """随机延时启动：等随机一段时间后再请求，避开整点高峰（--no-delay 可跳过）"""
    if "--no-delay" in sys.argv:
        log("[Trae] 检测到 --no-delay，跳过随机延时启动")
        return
    delay = random.uniform(*STARTUP_DELAY_RANGE)
    # 别把预算全花在等待上，否则签到本身没时间跑
    if RUN_DEADLINE:
        delay = min(delay, max(time_left() * 0.5, 60))
    eta = datetime.now() + timedelta(seconds=delay)
    log(f"[Trae] 随机延时启动 {int(delay) // 60} 分 {int(delay) % 60:02d} 秒"
        f"（{delay:.0f}s），预计 {eta:%H:%M:%S} 开始领取")
    time.sleep(delay)


def main() -> int:
    global RUN_DEADLINE
    argv = sys.argv[1:]
    # 计划任务给每个产品留的是 30 分钟槽位，这里按 25 分钟收口：
    # 超时就不再开新账号，宁可留给下午的补签任务，也别把日志和 WorkBuddy 的混在一起
    RUN_DEADLINE = time.time() + RUN_BUDGET_MINUTES * 60

    if "--login" in argv:
        return cmd_login()

    if "--forget" in argv:
        i = argv.index("--forget")
        if i + 1 >= len(argv):
            log("[Trae] 用法：--forget <账号名或 userId>")
            return 1
        return cmd_forget(argv[i + 1])

    if "--list" in argv:
        store, _ = do_capture()
        print_overview(store)
        return 0

    if "--watch" in argv:
        minutes = 30.0
        i = argv.index("--watch")
        if i + 1 < len(argv):
            try:
                minutes = float(argv[i + 1])
            except ValueError:
                pass
        return watch(minutes)

    status_only = "--status-only" in argv
    capture_only = "--capture" in argv
    if not status_only and not capture_only:
        startup_delay()

    log("=" * 50)
    log("[Trae] 开始每日积分" + ("状态查询（只读）" if status_only else "领取"))
    log("=" * 50)

    store, _ = do_capture()
    if capture_only:
        log(f"[Trae] --capture 完成，当前已捕获 {len(store['accounts'])} 个账号")
        print_overview(store)
        return 0

    accounts = sorted(store["accounts"].values(), key=account_label)
    if not accounts:
        log("ERROR: 没有可用登录态，请打开对应 Trae 客户端并登录")
        return 1

    results = []
    for idx, rec in enumerate(accounts):
        if time_left() <= 0:
            log(f"[Trae] 已用满 {RUN_BUDGET_MINUTES} 分钟预算，"
                f"剩下 {len(accounts) - idx} 个账号留给下午的补签任务")
            break
        if idx and "--no-delay" not in argv and time_left() > 60:
            gap = random.uniform(*ACCOUNT_GAP_RANGE)
            log(f"[Trae] {gap:.1f}s 后处理下一个账号")
            time.sleep(gap)
        ok, info = checkin_api(rec, status_only)
        if info:
            rec["lastStatus"] = info
        # 签到后刷新该账号的积分余额（和客户端「用量」读的是同一个接口）
        if ok != "skip":
            bal = fetch_balance(rec)
            if bal:
                rec["balance"] = bal
                log(f"[{account_label(rec)} {rec.get('userId', '')}] 当前积分余额 "
                    f"{fmt_credits(bal['left'])} / {fmt_credits(bal['total'])}")
        save_store(store)
        render_accounts_md(store)
        results.append(ok)

    log(f"[Trae] 完成：成功 {sum(1 for r in results if r is True)} / {len(accounts)} 个账号"
        + (f"（跳过 {sum(1 for r in results if r == 'skip')} 个登录态已过期）"
           if any(r == "skip" for r in results) else "")
        + ("" if len(results) == len(accounts) else "（预算用完，提前收尾）"))
    return 0 if all(r is not False for r in results) else 1


if __name__ == "__main__":
    code = main()
    try:
        if sys.stdin and sys.stdin.isatty() and "--watch" not in sys.argv:
            input("\n按回车键退出...")
    except Exception:
        pass
    sys.exit(code)
