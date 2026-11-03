# -*- coding: utf-8 -*-
"""切换 WorkBuddy 的当前登录账号（共享登录态 + 桌面端一起切）

签到脚本只读登录态、不碰客户端文件；这个脚本反过来，专门负责「切换账号」：
把 accounts.json 里某个账号的 token 写回
  %LOCALAPPDATA%\\CodeBuddyExtension\\Data\\Public\\auth\\Tencent-Cloud.coding-copilot.info
WorkBuddy 客户端读同一份文件，下次启动或刷新即用这个账号。

WorkBuddy 桌面端读的是自己的加密登录态（workbuddy-desktop.info）：token 字段套了
AES-256-GCM 信封，密钥不落盘。脚本会向本机装的 WorkBuddy 客户端要一次密钥
（以 ELECTRON_RUN_AS_NODE 模式跑它的 exe，调用它自己的原生绑定），解开旧字段、
把新账号按同样的方式重新密封写回，桌面端下次启动就是新账号。
做法参考开源插件 dingminhua/dsh-connect-workbuddy（MIT）。拿不到密钥
（没装桌面端等）时退化为只切共享登录态。

要点：
- 桌面端正在运行时不能直接写：它退出/刷新会用内存里的旧登录态覆盖。
  脚本会交互式确认关闭，或用 --wait 等它退出 / --force 强行写入
- 切成功后自动启动桌面端：交互终端里切完就把它拉起来（刚才为了写文件被关掉的还给你），
  --no-launch 可关掉，环境变量 SWITCH_NO_LAUNCH=1 全局关闭；--quiet / --json 一律不启动
- 不落备份、不写日志文件：切换结果只在终端输出；顺带读到的积分余额会写回 accounts.json
- 切号前会实时读一次每个账号的积分余额（只读接口），读不到才退回缓存值并标注时间
- token 快过期时先自动续期，避免切过去就是个过期账号
- 顺手把 accounts.json 里没有的资料（uin / 手机号等）从当前登录态文件快照到 profiles.json
- 原文件里的其它字段保持不动，只替换 account / auth / accounts 三块

用法（入口统一放在仓库根目录的 switch.bat，w = WorkBuddy，t = Trae）：
  switch.bat w                           # 交互式：列出账号，敲序号切换
  switch.bat                             # 先选产品（WorkBuddy / Trae）再选账号
  switch.bat w --list                    # 只看账号列表（含当前可用积分余额），不切换
  switch.bat w --verify                  # 校验客户端实际读到的账号 / token 是否有效
  switch.bat w Edwin                     # 按账号名切换（也支持 uid / uid 前缀 / 序号）
  switch.bat w 1                         # 按列表序号切换
  switch.bat w 1c3d9f4e                  # 按 uid 前缀切换
  switch.bat w Edwin --refresh           # 强制先续期再切换
  switch.bat w Edwin --wait              # 等 WorkBuddy 桌面端退出后再切（默认 120 秒）
  switch.bat w Edwin --no-launch         # 切成功也不启动桌面端
  switch.bat w Edwin --quiet             # 只出错才输出（给其它程序调用）
  switch.bat w Edwin --json              # 输出机器可读结果
  switch.bat w Edwin --dry-run           # 只演练，不写文件

退出码：0 成功；1 一般错误；2 找不到账号；3 token 过期且续期失败；
4 写入校验失败；5 桌面端正在运行且未同意关闭（或等待超时）
"""
import argparse
import base64
import copy
import csv
import hashlib
import io
import json
import math
import os
import subprocess
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

try:
    from Crypto.Cipher import AES              # pycryptodome，桌面端字段加解密用
except Exception:
    AES = None

BASE_DIR = Path(__file__).resolve().parent
STORE_FILE = BASE_DIR / "accounts.json"        # 多账号登录态仓库（与签到脚本共用）
PROFILE_FILE = BASE_DIR / "profiles.json"      # 账号资料快照（uin / 手机号等，切换时补全字段用）
TARGET_NAME = "Tencent-Cloud.coding-copilot.info"      # 其它应用读的那份共享登录态
DESKTOP_NAME = "workbuddy-desktop.info"        # WorkBuddy 桌面端自己的加密登录态
APP_EXE_NAMES = ("WorkBuddy.exe", "WorkBuddyAI.exe")   # 桌面端国内版 / 国际版
APP_EXE_ENV = "WORKBUDDY_APP_EXECUTABLE"       # 手动指定桌面端 exe 的环境变量
NO_LAUNCH_ENV = "SWITCH_NO_LAUNCH"             # 设成 1 就彻底关掉「切完自动启动」
KEY_FETCH_TIMEOUT = 15                         # 向桌面端要密钥的超时（秒）
REFRESH_AHEAD_MS = 6 * 3600 * 1000            # 剩余有效期小于 6 小时就先续期
CLOSE_POLITE_SEC = 2.0                         # 发完关闭请求等它自己退的时长（托盘常驻应用基本等不到）
CLOSE_FORCE_SEC = 10.0                         # 强杀后等进程彻底消失的时长

# 复用签到脚本的仓库读写 / 续期实现，避免两份逻辑跑偏
sys.path.insert(0, str(BASE_DIR))
try:
    import checkin_workbuddy as wb
    WB_IMPORT_ERROR = None
except Exception as exc:                                # 只拷了 switch 脚本也能跑，只是不能续期
    wb = None
    WB_IMPORT_ERROR = exc

AUTH_DIR = (wb.AUTH_DIR if wb else
            Path(os.environ.get("LOCALAPPDATA", "")) / "CodeBuddyExtension" / "Data" / "Public" / "auth")

QUIET = False
NO_BALANCE = False          # --no-balance：只看 accounts.json 里的缓存余额，不联网
LAUNCHED = []               # 本次运行实际启动的桌面端 exe（交互循环据此收工）


def log(msg: str) -> None:
    if not QUIET:
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")


def now_ms() -> int:
    return int(time.time() * 1000)


def fmt_ts(ms) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "未知"


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_json_atomic(path: Path, data, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False,
                      separators=(",", ":") if compact else None,
                      indent=None if compact else 2)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def label(rec: dict) -> str:
    return rec.get("nickname") or (rec.get("uid") or "")[:8]


# ---- 仓库 / 账号解析 ----

def load_store() -> dict:
    if wb:
        return wb.load_store()
    data = read_json(STORE_FILE) if STORE_FILE.exists() else None
    if not isinstance(data, dict) or not isinstance(data.get("accounts"), dict):
        data = {"version": 1, "accounts": {}}
    return data


def save_store(store: dict) -> None:
    if wb:
        wb.save_store(store)
    else:
        write_json_atomic(STORE_FILE, store)


def load_profiles() -> dict:
    data = read_json(PROFILE_FILE)
    return data if isinstance(data, dict) else {}


def save_profiles(profiles: dict) -> None:
    write_json_atomic(PROFILE_FILE, profiles)


def resolve(selector: str, accounts: list):
    """按 uid / 序号 / 账号名（含模糊）找账号，找不到返回 None"""
    sel = (selector or "").strip()
    if not sel:
        return None
    low = sel.casefold()

    for rec in accounts:                                   # 完整 uid
        if (rec.get("uid") or "").casefold() == low:
            return rec

    if sel.isdigit() and 1 <= int(sel) <= len(accounts):   # 列表序号
        return accounts[int(sel) - 1]

    if len(sel) >= 4:                                      # uid 前缀
        for rec in accounts:
            if (rec.get("uid") or "").casefold().startswith(low):
                return rec

    exact = [r for r in accounts if label(r).casefold() == low]
    if len(exact) == 1:
        return exact[0]
    part = [r for r in accounts if low in label(r).casefold()]
    return part[0] if len(part) == 1 else None


# ---- 积分余额 ----
#
# 切号前先看一眼「切过去还能用多少积分」：联网读一次只读接口（和客户端「账户用量」
# 面板同款），读到就用新值并顺手写回 accounts.json；读不到（token 过期 / 断网）
# 就退回上次签到留下的缓存值，并在列表里标出缓存时间，免得误以为是实时余额。

BALANCE_FRESH_MS = 60 * 1000     # 列表里刚读过的余额，紧接着切号时直接复用，不重复请求
BALANCE_WORKERS = 6              # 并发读余额的线程数：几个账号也就一两秒
_tls = threading.local()         # 暂存签到脚本读余额期间打的日志，用来归因失败原因


def fmt_num(value) -> str:
    """积分数字：整数不带小数，其余保留两位（与 accounts.md 一致）"""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "—"
    return f"{v:.0f}" if abs(v - round(v)) < 0.005 else f"{v:.2f}"


def balance_text(bal: dict) -> str:
    """余额文案：剩余 / 总额；一次都没读到过就是 —"""
    left, total = bal.get("left"), bal.get("total")
    if left is None:
        return "—"
    return f"{fmt_num(left)} / {fmt_num(total)}" if total else fmt_num(left)


def pad_display(text: str, width: int) -> str:
    """按终端显示宽度左对齐（中文占两格），账号名前那一列才不会歪

    名字跟 trae/switch_account.py 保持一致；别改回 pad，那份脚本里 pad 是
    Crypto.Util.Padding.pad，撞名就会把加密写坏。"""
    used = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
    return text + " " * max(width - used, 0)


def _quiet_log(msg: str) -> None:
    """顶替签到脚本的 log：不打印也不写 checkin.log，只留下失败原因"""
    bucket = getattr(_tls, "msgs", None)
    if bucket is not None:
        bucket.append(msg)


def fetch_one(rec: dict) -> tuple:
    """读一个账号的余额，返回 (balance 或 None, 失败原因)"""
    if not wb:
        return None, f"签到脚本不可用（{WB_IMPORT_ERROR}）"
    _tls.msgs = []
    try:
        bal = wb.fetch_balance(rec)
    except Exception as exc:
        bal, _tls.msgs = None, [f"{type(exc).__name__}: {exc}"]
    reason = _tls.msgs[-1] if _tls.msgs else ""
    if reason.startswith("["):                 # "[账号 uid] 查询积分余额失败：xxx" → 只留原因
        reason = reason.split("]", 1)[-1].strip()
    return bal, reason


def refresh_balances(accounts: list, live: bool = True) -> dict:
    """给每个账号的 rec 补上最新 balance，返回 {uid: {live, reason}}

    live=False（--no-balance）只读缓存值，不联网。"""
    status = {rec["uid"]: {"live": False, "reason": ""} for rec in accounts}
    if not (live and wb and accounts):
        return status
    saved, wb.log = wb.log, _quiet_log          # 读余额期间别让签到脚本的日志混进输出
    try:
        with ThreadPoolExecutor(max_workers=min(BALANCE_WORKERS, len(accounts))) as pool:
            futures = {pool.submit(fetch_one, rec): rec for rec in accounts}
            for fut in as_completed(futures):
                rec = futures[fut]
                bal, reason = fut.result()
                if bal:
                    rec["balance"] = bal
                    status[rec["uid"]]["live"] = True
                else:
                    status[rec["uid"]]["reason"] = reason
    finally:
        wb.log = saved
    return status


def balance_suffix(bal: dict, live: bool) -> str:
    """余额后面的小尾巴：实时读到的什么都不加，缓存的标出时间"""
    if live:
        return ""
    if bal.get("left") is None:
        return "（读取失败）"
    return f"（缓存 {fmt_ts(bal.get('updatedAt')).split(' ')[-1]}）"


def persist_balances(store: dict, status: dict) -> None:
    """把实时读到的余额落盘（accounts.json + accounts.md），写不动也不影响切号"""
    if not any(s.get("live") for s in status.values()):
        return
    try:
        save_store(store)
        if wb:
            wb.render_accounts_md(store)
    except Exception:
        pass


# ---- 登录态文件 ----

def auth_files() -> list:
    """列出可写的明文登录态文件（加密的桌面端文件直接跳过）"""
    out = []
    if not AUTH_DIR.is_dir():
        return out
    for path in sorted(AUTH_DIR.glob("*.info")):
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        auth = data.get("auth") or {}
        token = auth.get("accessToken")
        if not isinstance(token, str) or not token.strip():
            continue                                       # 新版客户端加密落盘的，写不了
        account = data.get("account") or {}
        out.append({"path": path, "uid": account.get("uid") or "",
                    "nickname": account.get("nickname") or "", "data": data})
    return out


def main_auth_file():
    files = auth_files()
    for item in files:
        if item["path"].name == TARGET_NAME:
            return item
    return files[0] if files else None


def encrypted_auth_files() -> list:
    """加密落盘的登录态（WorkBuddy 桌面端等）：uid 是明文，昵称要解密才能看"""
    out = []
    if not AUTH_DIR.is_dir():
        return out
    for path in sorted(AUTH_DIR.glob("*.info")):
        data = read_json(path)
        if not isinstance(data, dict):
            continue
        token = (data.get("auth") or {}).get("accessToken")
        if isinstance(token, str) and token.strip():
            continue                                      # 明文登录态，归 auth_files 管
        account = data.get("account") or {}
        uid = account.get("uid") or ""
        if not uid:
            continue
        name = account.get("nickname")
        out.append({"path": path, "uid": uid,
                    "nickname": name if isinstance(name, str) else ""})
    return out


# ---- WorkBuddy 桌面端的加密登录态（at-rest）----
#
# 桌面端把 token / 昵称等字段写成 AES-256-GCM 信封：
#   {"$wbEncrypted": 1, "envelope": base64({suite, keyId, nonce, authTag, ciphertext})}
# 字段密钥是客户端构建期常量，让客户端自己的 exe 交出来（不会拉起界面）：
#   WorkBuddy.exe -e "..._linkedBinding('electron_browser_workbuddy_storage').loggerGet()"
#   （带 ELECTRON_RUN_AS_NODE=1，以纯 Node 模式跑）
# key = sha256(atRestSecretKey 这个 base64 串)，keyId = sha256(key) 前 16 位 hex。
# 算法与参考实现：dingminhua/dsh-connect-workbuddy（MIT）src/at-rest.ts

_KEY_FETCH_SCRIPT = ("try{process.stdout.write(process._linkedBinding("
                     "'electron_browser_workbuddy_storage').loggerGet())}"
                     "catch(e){process.exitCode=3;process.stderr.write(String(e&&e.message||e))}")
_atrest_cache = {}                                     # 进程内缓存，避免反复拉起 exe


def desktop_file():
    path = AUTH_DIR / DESKTOP_NAME
    return path if path.is_file() else None


def find_app_executable() -> str:
    """找桌面端可执行文件：环境变量 → 常见安装目录 → 注册表（自定义安装目录）"""
    env = os.environ.get(APP_EXE_ENV, "").strip()
    if env and Path(env).is_file():
        return env
    local = os.environ.get("LOCALAPPDATA", "")
    candidates = []
    if local:
        candidates += [Path(local) / "Programs" / "WorkBuddy", Path(local) / "WorkBuddy"]
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(var, "")
        if root:
            candidates.append(Path(root) / "WorkBuddy")
    for d in candidates:
        for exe in APP_EXE_NAMES:
            if (d / exe).is_file():
                return str(d / exe)
    if os.name != "nt":
        return ""
    import winreg
    hives = [(winreg.HKEY_CURRENT_USER, 0),
             (winreg.HKEY_LOCAL_MACHINE, 0),
             (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)]
    exe_lows = tuple(n.lower() for n in APP_EXE_NAMES)
    for hive, view in hives:
        try:
            root = winreg.OpenKey(hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                                  0, winreg.KEY_READ | view)
        except OSError:
            continue
        with root:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, sub) as item:
                        for value_name in ("DisplayIcon", "InstallLocation"):
                            try:
                                value = winreg.QueryValueEx(item, value_name)[0]
                            except OSError:
                                continue
                            value = value.split(",")[0].strip().strip('"').strip()
                            if not value:
                                continue
                            if value.lower().endswith(exe_lows) and Path(value).is_file():
                                return value
                            if value_name == "InstallLocation":
                                for exe in APP_EXE_NAMES:
                                    if (Path(value) / exe).is_file():
                                        return str(Path(value) / exe)
                except OSError:
                    continue
    return ""


def get_atrest_key() -> tuple:
    """向桌面端要字段密钥，返回 (key, keyId)；拿不到就抛 RuntimeError"""
    if _atrest_cache:
        return _atrest_cache["key"], _atrest_cache["keyId"]
    if AES is None:
        raise RuntimeError("缺少 pycryptodome（pip install pycryptodome）")
    exe = find_app_executable()
    if not exe:
        raise RuntimeError(f"找不到 WorkBuddy 桌面端；装上它，或用环境变量 {APP_EXE_ENV} 指向它的 exe")
    env = dict(os.environ)
    env["ELECTRON_RUN_AS_NODE"] = "1"                   # 纯 Node 模式，不弹界面
    try:
        run = subprocess.run([exe, "-e", _KEY_FETCH_SCRIPT], capture_output=True,
                             timeout=KEY_FETCH_TIMEOUT, env=env,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as exc:
        raise RuntimeError(f"无法从桌面端取密钥：{exc}")
    payload = run.stdout.decode("utf-8", "ignore").strip()
    if not payload:
        raise RuntimeError(f"桌面端没有返回密钥（exit={run.returncode} "
                           f"{run.stderr.decode('utf-8', 'ignore').strip()[:120]}）")
    try:
        secret = json.loads(payload).get("atRestSecretKey")
    except Exception:
        secret = None
    if not isinstance(secret, str) or not secret:
        raise RuntimeError("密钥 payload 里没有 atRestSecretKey")
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    _atrest_cache.update({"key": key, "keyId": hashlib.sha256(key).hexdigest()[:16]})
    return key, _atrest_cache["keyId"]


def _field_aad(key_id: str, suite: int) -> bytes:
    """GCM 附加认证数据：域分隔 + 转录版本 + 格式/方案/套件/密钥号 + field 帧类型"""
    out = b"WB-AAD\x00" + b"\x01"
    for part in (b"WBEV1", b"sym-v1"):
        out += len(part).to_bytes(4, "big") + part
    out += suite.to_bytes(4, "big")
    kb = key_id.encode("ascii")
    out += len(kb).to_bytes(4, "big") + kb
    out += bytes([2, 0, 0])                             # field 帧 + 无 sequence + 无 final
    return out


def open_field(wrapper: dict, key: bytes) -> str:
    """解一个加密字段，返回明文；信封不属于这把钥匙或被改过都会抛异常"""
    env = json.loads(base64.b64decode(wrapper["envelope"]))
    suite, key_id = int(env["suite"]), str(env["keyId"])
    dec = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(env["nonce"]))
    dec.update(_field_aad(key_id, suite))
    return dec.decrypt_and_verify(base64.b64decode(env["ciphertext"]),
                                  base64.b64decode(env["authTag"])).decode("utf-8")


def seal_field(value: str, key: bytes, key_id: str) -> dict:
    """按桌面端自己的格式重新密封一个字段"""
    nonce = os.urandom(12)
    enc = AES.new(key, AES.MODE_GCM, nonce=nonce)
    enc.update(_field_aad(key_id, 1))
    ciphertext, tag = enc.encrypt_and_digest(value.encode("utf-8"))
    envelope = {"suite": 1, "keyId": key_id,
                "nonce": base64.b64encode(nonce).decode(),
                "authTag": base64.b64encode(tag).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode()}
    return {"$wbEncrypted": 1,
            "envelope": base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode()).decode()}


def is_encrypted_field(value) -> bool:
    return (isinstance(value, dict) and set(value) == {"$wbEncrypted", "envelope"}
            and value.get("$wbEncrypted") == 1 and isinstance(value.get("envelope"), str))


def desktop_account(data: dict, key: bytes = None) -> dict:
    """桌面端文件当前登录谁；key 给了就连加密昵称一起解，解不开只给 uid"""
    account = data.get("account") or {}
    info = {"uid": str(account.get("uid") or ""), "nickname": "", "encrypted": False}
    nick = account.get("nickname")
    if isinstance(nick, str):
        info["nickname"] = nick
    elif is_encrypted_field(nick):
        info["encrypted"] = True
        if key is not None:
            try:
                info["nickname"] = open_field(nick, key)
            except Exception:
                pass
    return info


def build_desktop_session(rec: dict, profile: dict, template: dict, key: bytes, key_id: str) -> dict:
    """拼桌面端的登录态：沿用原文件其它字段，换账号并按原格式重新密封加密字段"""
    doc = copy.deepcopy(template or {})
    old_auth = (template or {}).get("auth") or {}
    payload = jwt_payload(rec["token"])
    exp = rec.get("expiresAt") or int(payload.get("exp") or 0) * 1000
    rexp = rec.get("refreshExpiresAt") or exp
    last = rec.get("refreshedAt") or rec.get("updatedAt") or now_ms()

    auth = dict(old_auth)
    auth["accessToken"] = seal_field(rec["token"], key, key_id)
    auth["refreshToken"] = seal_field(rec.get("refreshToken") or "", key, key_id)
    auth["tokenType"] = old_auth.get("tokenType") or "Bearer"
    auth["expiresIn"] = max(1, int((exp - last) / 1000))
    auth["refreshExpiresIn"] = max(1, int((rexp - last) / 1000))
    auth["expiresAt"] = exp
    auth["refreshExpiresAt"] = rexp
    auth["lastRefreshTime"] = last
    auth["domain"] = rec.get("domain") or old_auth.get("domain") or "www.workbuddy.cn"
    auth["sessionState"] = str(payload.get("sid") or payload.get("session_state")
                               or old_auth.get("sessionState") or "")

    # 账号块：身份数据换成目标账号；桌面特有字段保留骨架，微信绑定不能跟人走，清空
    profile = dict(profile)
    profile.update({"uid": rec["uid"], "lastLogin": True})
    if not profile.get("nickname"):
        profile["nickname"] = rec.get("nickname") or payload.get("nickname") or rec["uid"][:8]
    if not profile.get("phoneNumber"):
        username = str(payload.get("preferred_username") or "")
        if username.isdigit() and len(username) == 11:
            profile["phoneNumber"] = f"{username[:3]}****{username[-4:]}"
    if not profile.get("uin") and payload.get("uin"):
        profile["uin"] = str(payload["uin"])

    account = dict((template or {}).get("account") or {})
    account.update(profile)
    for k in ("wechatOpenId", "mpOpenId"):
        if k in account:
            account[k] = ""
    account["nickname"] = seal_field(str(profile.get("nickname") or ""), key, key_id)
    if "phoneNumber" in account:
        account["phoneNumber"] = seal_field(str(profile.get("phoneNumber") or ""), key, key_id)
    if "uin" in account:
        account["uin"] = str(profile.get("uin") or "")

    doc["auth"] = auth
    doc["account"] = account
    doc["accounts"] = [account]
    doc["allAccounts"] = [account]
    return doc


_SNAPSHOT = {}                     # 惰性初始化的系统快照句柄与结构体


def _snapshot_processes() -> dict:
    """{pid: 进程名}：走 CreateToolhelp32Snapshot，一次约 20ms"""
    if not _SNAPSHOT:
        import ctypes
        from ctypes import wintypes

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                        ("szExeFile", wintypes.WCHAR * 260)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
        k32.CloseHandle.argtypes = (wintypes.HANDLE,)
        k32.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
        k32.Process32NextW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
        _SNAPSHOT.update({"ctypes": ctypes, "k32": k32, "entry": PROCESSENTRY32W,
                          "invalid": (1 << (8 * ctypes.sizeof(ctypes.c_void_p))) - 1})

    ctypes, k32 = _SNAPSHOT["ctypes"], _SNAPSHOT["k32"]
    handle = k32.CreateToolhelp32Snapshot(0x00000002, 0)          # TH32CS_SNAPPROCESS
    if not handle or handle == _SNAPSHOT["invalid"]:
        raise OSError("CreateToolhelp32Snapshot 失败")
    entry = _SNAPSHOT["entry"]()
    entry.dwSize = ctypes.sizeof(_SNAPSHOT["entry"])
    table = {}
    try:
        if not k32.Process32FirstW(handle, ctypes.byref(entry)):
            raise OSError("Process32FirstW 失败")
        while True:
            table[int(entry.th32ProcessID)] = entry.szExeFile
            if not k32.Process32NextW(handle, ctypes.byref(entry)):
                break
    finally:
        k32.CloseHandle(handle)
    return table


def _tasklist_processes() -> dict:
    """快照不可用时的退路：解析 tasklist 输出（约 1 秒，只作兜底）"""
    try:
        raw = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True,
                             timeout=15).stdout.decode("mbcs", "ignore")
    except Exception:
        return {}
    table = {}
    for row in csv.reader(io.StringIO(raw)):
        if len(row) < 2:
            continue
        try:
            table[int(row[1])] = row[0].strip()
        except ValueError:
            continue
    return table


def workbuddy_pids() -> dict:
    """运行中的 WorkBuddy 桌面端进程：{进程名: [pid, ...]}

    桌面端是 Electron 应用，同名进程有近十个（主进程 + GPU / 渲染 / 工具子进程），
    只有主进程带窗口。原来每次 tasklist 要 1 秒，轮询「退没退」根本快不起来，
    改用系统快照后约 20ms。"""
    try:
        table = _snapshot_processes()
    except Exception:
        table = _tasklist_processes()
    found = {}
    for pid, name in table.items():
        if name.lower().startswith("workbuddy"):
            found.setdefault(name, []).append(pid)
    return found


def workbuddy_processes() -> list:
    """正在运行的 WorkBuddy 桌面端进程名"""
    return sorted(workbuddy_pids())


def _visible_windows(pids) -> list:
    """这些进程拥有的可见顶层窗口 [(hwnd, pid), ...]

    只有带窗口的进程吃 WM_CLOSE，其它子进程不带窗口，非强制结束对它们必然失败。"""
    if os.name != "nt" or not pids:
        return []
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    targets, out = set(pids), []
    proto = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def collect(hwnd, _lparam):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in targets and user32.IsWindowVisible(hwnd):
            out.append((hwnd, pid.value))
        return True

    try:
        user32.EnumWindows(proto(collect), 0)
    except Exception:
        return []
    return out


def request_close(windows: list) -> int:
    """给这些窗口发 WM_CLOSE（等价于点右上角 X），返回发出去的窗口数"""
    if os.name != "nt" or not windows:
        return 0
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    sent = 0
    for hwnd, _pid in windows:
        if user32.PostMessageW(wintypes.HWND(hwnd), 0x0010, 0, 0):   # WM_CLOSE
            sent += 1
    return sent


def _taskkill(args) -> None:
    try:
        subprocess.run(["taskkill"] + list(args), capture_output=True, timeout=20,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def kill_desktop(found: dict) -> None:
    """强制结束整棵进程树：先 /T 连子进程一起收主进程，再逐个补刀、按名字兜底"""
    pids = [pid for lst in found.values() for pid in lst]
    for pid in [pid for _hwnd, pid in _visible_windows(pids)]:      # 主进程优先
        _taskkill(["/F", "/T", "/PID", str(pid)])
    left = workbuddy_pids()
    for pid in [pid for lst in left.values() for pid in lst]:
        _taskkill(["/F", "/PID", str(pid)])
    for name in (left or found):
        _taskkill(["/F", "/IM", name])


def _env_seconds(name: str, default: float) -> float:
    """从环境变量取秒数（方便外部调度改超时），取不到 / 不合法就用默认值"""
    raw = os.environ.get(name, "").strip()
    if raw:
        try:
            value = float(raw)
            if value >= 0:
                return value
        except ValueError:
            pass
    return default


def wait_desktop_exit(seconds: float) -> bool:
    """等桌面端全部退出；交互终端里显示倒计时，返回是否已退出"""
    deadline = time.time() + max(float(seconds), 0.0)
    printed = False
    try:
        while time.time() < deadline:
            if not workbuddy_processes():
                return True
            if not QUIET:
                left = max(0, math.ceil(deadline - time.time()))
                print(f"\r等待 WorkBuddy 桌面端退出… 剩余 {left}s   ", end="", flush=True)
                printed = True
            time.sleep(0.5)
        return not workbuddy_processes()
    finally:
        if printed:                                # 别把半截进度行留给后面的日志
            print("\r" + " " * 42 + "\r", end="", flush=True)


def _wait_quit(pids: list, seconds: float) -> bool:
    """等它响应对关闭请求：全部退出 True；窗口收进托盘但进程还在 → 提前判定关不掉"""
    deadline = time.time() + max(float(seconds), 0.0)
    hidden_at = None
    while time.time() < deadline:
        if not workbuddy_processes():
            return True
        if not _visible_windows(pids):             # 窗口没了、进程还在 = 收进托盘
            hidden_at = hidden_at or time.time()
            if time.time() - hidden_at > 1.0:
                return False
        else:
            hidden_at = None
        time.sleep(0.3)
    return not workbuddy_processes()


def close_desktop(procs: list = None) -> bool:
    """关掉桌面端：发一次正常关闭请求，不响应（托盘常驻）就直接强杀进程树

    WorkBuddy 桌面端点关闭只是把窗口收进托盘，进程根本不退，「优雅关闭」永远等不到
    结果——原来固定等 20 秒再强杀纯属白等（日志里那 24 秒就是这么耗掉的）。现在：
      · 有主窗口 → 发 WM_CLOSE，并盯着窗口是否消失，1 秒内没退干净立即动手
      · 本来就没窗口（后台驻留）→ 连请求都不发，直接杀
    强杀对切号反而更安全：它来不及把内存里的旧登录态写回磁盘。"""
    procs = procs if procs is not None else workbuddy_processes()
    if not procs:
        return True
    found = workbuddy_pids()
    pids = [pid for lst in found.values() for pid in lst]
    log(f"正在关闭 WorkBuddy 桌面端（{', '.join(procs)}，{len(pids)} 个进程）…")

    windows = _visible_windows(pids)
    if windows:
        request_close(windows)
        log(f"已向 {len(windows)} 个窗口发出关闭请求…")
        if _wait_quit(pids, _env_seconds("SWITCH_CLOSE_POLITE", CLOSE_POLITE_SEC)):
            log("桌面端已正常退出")
            return True
        log("桌面端没有响应关闭请求（托盘常驻），强制结束…")
    else:
        log("桌面端只在后台驻留（没有主窗口），直接强制结束…")

    left = workbuddy_pids()
    if left:
        kill_desktop(left)
    if wait_desktop_exit(_env_seconds("SWITCH_CLOSE_FORCE", CLOSE_FORCE_SEC)):
        log("桌面端已强制结束")
        return True
    log("桌面端进程还在（可能被系统保护），请手动结束后重试")
    return False


def can_prompt() -> bool:
    """交互终端里才允许提问（--quiet / --json 一律不打断调用方）"""
    return bool(sys.stdin and sys.stdin.isatty()) and not QUIET


# ---- 切完自动启动桌面端 ----
#
# 交互式切号的目的通常就是「换完号接着用」，所以切成功后直接把客户端拉起来：
# 刚才是脚本帮你关掉的桌面端，切完自然要还给你。行为开关：
#   · 默认只在交互终端（双击 / 手动跑）里启动；--quiet / --json / 管道调用一律不启动
#   · --launch 强制启动、--no-launch 不启动；环境变量 SWITCH_NO_LAUNCH=1 全局关掉
#   · 桌面端已经在跑、或本次桌面端登录态其实没切成（拿不到密钥 / 写入回滚）时不启动，
#     否则打开的会是旧账号，反而误导
#   · 用 DETACHED_PROCESS 脱离当前控制台：脚本退出后客户端继续活着

def should_launch(opts) -> bool:
    """要不要在切成功后启动客户端"""
    if os.environ.get(NO_LAUNCH_ENV, "").strip() not in ("", "0", "false", "False"):
        return False
    if getattr(opts, "no_launch", False):
        return False
    if getattr(opts, "dry_run", False):
        return False
    if getattr(opts, "launch", False):
        return True
    return can_prompt()


def spawn_detached(exe: str, args=None) -> bool:
    """脱离控制台启动一个 GUI 程序（脚本退出后它继续跑）"""
    flags = (getattr(subprocess, "DETACHED_PROCESS", 0)
             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    try:
        subprocess.Popen([exe] + list(args or []), cwd=str(Path(exe).parent),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True,
                         creationflags=flags)
    except Exception as exc:
        log(f"启动失败：{exe}（{type(exc).__name__}: {exc}）")
        return False
    return True


def launch_desktop(opts, switched: bool) -> str:
    """切成功后把 WorkBuddy 桌面端拉起来，返回启动的 exe（没启动返回空串）"""
    if not should_launch(opts):
        return ""
    if workbuddy_processes():
        log("WorkBuddy 桌面端已在运行，不重复启动")
        return ""
    if desktop_file() is None:
        log("没有桌面端登录态（未安装桌面端），跳过自动启动")
        return ""
    if not switched:
        log("桌面端登录态本次未切换，跳过自动启动（免得打开还是旧账号）")
        return ""
    exe = find_app_executable()
    if not exe:
        log(f"没找到 WorkBuddy 桌面端，跳过自动启动（可用环境变量 {APP_EXE_ENV} 指定 exe）")
        return ""
    if spawn_detached(exe):
        log(f"已启动 WorkBuddy 桌面端（{exe}）")
        LAUNCHED.append(exe)
        return exe
    return ""


def desktop_note(store: dict) -> str:
    """WorkBuddy 桌面端当前登录谁（能要到密钥就连昵称一起解）"""
    items = encrypted_auth_files()
    if not items:
        return ""
    try:
        key, _ = get_atrest_key()
    except Exception:
        key = None
    parts = []
    for it in items:
        if key is not None:
            info = desktop_account(read_json(it["path"]) or {}, key)
            if info["nickname"]:
                parts.append(info["nickname"])
                continue
        rec = store.get("accounts", {}).get(it["uid"])
        name = label(rec) if rec else (it["nickname"] or "")
        parts.append(name or f"未知账号（{it['uid'][:8]}…，昵称加密且桌面端不在本机时解不开）")
    return "、".join(parts)


def snapshot_current_profile() -> dict:
    """把当前登录态里的账号资料记下来（uin / 手机号等 accounts.json 里没有）"""
    current = main_auth_file()
    if not current:
        return {}
    account = (current["data"].get("account") or {})
    uid = account.get("uid")
    if not uid:
        return {}
    profiles = load_profiles()
    if profiles.get(uid) != account:
        profiles[uid] = account
        save_profiles(profiles)
    return account


def jwt_payload(token: str) -> dict:
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))
    except Exception:
        return {}


def default_profile(uid: str, nickname: str) -> dict:
    """照抄真实文件的字段结构，缺的填空值，客户端会自己补全"""
    return {
        "uid": uid,
        "nickname": nickname or uid[:8],
        "uin": "",
        "type": "personal",
        "lastLogin": True,
        "isCreator": False,
        "isAdmin": False,
        "pluginEnabled": True,
        "deployStatus": {"statusCode": 0, "statusMsg": "", "detailMsg": ""},
        "accountType": "",
        "sso": {"domain": "", "domainModifiedTimes": 0},
        "idp": "",
        "areaInfoComplete": False,
        "oneidAccountId": "",
        "isCurrentOneIdEnterprise": False,
        "isCurrentOneIdPersonal": False,
        "isFirstLogin": True,
        "phoneNumber": "",
        "logOutEnable": False,
    }


def build_session(rec: dict, profile: dict, template: dict) -> dict:
    """拼出要写进 .info 的完整结构：沿用模板里的其它字段，只换账号和凭证"""
    data = dict(template or {})
    old_auth = (template or {}).get("auth") or {}
    payload = jwt_payload(rec["token"])
    exp = rec.get("expiresAt") or int(payload.get("exp") or 0) * 1000
    rexp = rec.get("refreshExpiresAt") or exp
    now = now_ms()

    auth = dict(old_auth)
    auth.update({
        "accessToken": rec["token"],
        "refreshToken": rec.get("refreshToken") or old_auth.get("refreshToken") or "",
        "tokenType": old_auth.get("tokenType") or "Bearer",
        "expiresIn": max(0, int((exp - now) / 1000)),
        "refreshExpiresIn": max(0, int((rexp - now) / 1000)),
        "expiresAt": exp,
        "refreshExpiresAt": rexp,
        "lastRefreshTime": rec.get("refreshedAt") or rec.get("updatedAt") or now,
        "domain": rec.get("domain") or old_auth.get("domain") or "www.codebuddy.cn",
    })
    sid = payload.get("sid") or payload.get("session_state") or old_auth.get("sessionState")
    auth["sessionState"] = sid or ""
    auth.setdefault("scope", "openid profile offline_access email")

    profile = dict(profile)
    profile.update({"uid": rec["uid"], "lastLogin": True})
    if not profile.get("nickname"):
        profile["nickname"] = rec.get("nickname") or payload.get("nickname") or rec["uid"][:8]
    # 资料没快照过时，从 token 里能拿到多少补多少（客户端登录后会自己覆盖成完整资料）
    if not profile.get("phoneNumber"):
        username = str(payload.get("preferred_username") or "")
        if username.isdigit() and len(username) == 11:
            profile["phoneNumber"] = f"{username[:3]}****{username[-4:]}"
    if not profile.get("uin") and payload.get("uin"):
        profile["uin"] = str(payload["uin"])

    data["account"] = profile
    data["auth"] = auth
    data["accounts"] = [profile]
    return data


# ---- 切换 ----

def running_apps() -> list:
    """可能持有共享登录态的进程；桌面端单独由 workbuddy_processes 管"""
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True,
                             timeout=10).stdout.decode("mbcs", "ignore").lower()
    except Exception:
        return []
    return ["CodeBuddy"] if "codebuddy" in out else []


def ensure_valid(store: dict, rec: dict, force_refresh: bool, no_refresh: bool) -> tuple:
    """切换前把 token 准备好，返回 (是否可用, 说明)"""
    exp = rec.get("expiresAt") or 0
    need = force_refresh or (exp and exp - now_ms() < REFRESH_AHEAD_MS)
    if no_refresh or not need:
        return (bool(rec.get("token")), None)
    if not rec.get("refreshToken"):
        return (bool(exp and exp > now_ms()), "没有续期凭证，直接用现有 token")
    if not wb:
        return (bool(exp and exp > now_ms()), f"签到脚本不可用，跳过自动续期（{WB_IMPORT_ERROR}）")
    ok, err = wb.refresh_account(rec)
    if ok:
        save_store(store)                       # 服务端会轮换 refreshToken，必须立刻落盘
        log(f"已续期 {label(rec)}，新 token 到期 {fmt_ts(rec.get('expiresAt'))}")
        return (True, None)
    log(f"续期失败：{err}（继续尝试用现有 token 切换）")
    return (bool(exp and exp > now_ms()), err)


def do_switch(selector: str, opts) -> int:
    store = load_store()
    accounts = sorted(store.get("accounts", {}).values(), key=label)
    if not accounts:
        log("accounts.json 里没有账号，先跑一次签到脚本 --list 捕获登录态")
        return 1

    rec = resolve(selector, accounts)
    if not rec:
        log(f"找不到账号：{selector}（用 --list 看可用账号）")
        return 2

    snapshot_current_profile()                  # 先把「当前」账号的资料留档
    current = main_auth_file()
    desk = desktop_file()

    # 桌面端那份能不能切，取决于能不能要到它的字段密钥；要不到就退化为只切共享登录态
    key = key_id = None
    desktop_error = None
    if desk:
        try:
            key, key_id = get_atrest_key()
        except RuntimeError as exc:
            desktop_error = str(exc)
            log(f"注意：{exc}，本次只切共享登录态")

    # 共享文件和桌面端文件都已是目标账号才算「无需切换」
    cur_desktop = desktop_account(read_json(desk) or {}, key) if desk else None
    shared_done = bool(current and current["uid"] == rec["uid"])
    desktop_done = bool(cur_desktop and cur_desktop["uid"] == rec["uid"])
    if not opts.force and shared_done and (desktop_done or desk is None):
        log(f"当前已经是 {label(rec)}，无需切换（--force 可强制重写）")
        launch_desktop(opts, switched=True)          # 号已经对了，也把客户端拉起来
        return 0

    ok, note = ensure_valid(store, rec, opts.refresh, opts.no_refresh)
    if not ok:
        log(f"{label(rec)} 的 token 已过期且无法续期，请在客户端登录一次该账号后再切换")
        return 3

    profiles = load_profiles()
    profile = profiles.get(rec["uid"]) or default_profile(rec["uid"], rec.get("nickname") or "")
    template = (current or {}).get("data") if current else {}
    data = build_session(rec, profile, template)
    target = AUTH_DIR / (current["path"].name if current else TARGET_NAME)

    exp = rec.get("expiresAt") or 0
    expired = bool(exp and exp <= now_ms())
    if expired:
        log(f"注意：{label(rec)} 的 token 到期时间 {fmt_ts(exp)} 已过，切过去可能提示重新登录")

    if opts.dry_run:
        scope = str(target.name)
        if desk and key is not None:
            scope += f" + {DESKTOP_NAME}"
        log(f"[dry-run] 将会把 {scope} 的账号切成 {label(rec)}"
            f"（token 到期 {fmt_ts(exp)}）")
        if opts.json:
            print(json.dumps({"ok": True, "dryRun": True, "uid": rec["uid"],
                              "nickname": label(rec), "target": str(target),
                              "desktopIncluded": bool(desk and key is not None)},
                             ensure_ascii=False))
        return 0

    if not AUTH_DIR.is_dir():
        log(f"登录态目录不存在：{AUTH_DIR}")
        return 1

    # 桌面端在跑就必须先关：它退出/刷新时会把内存里的旧登录态写回去
    procs = workbuddy_processes() if (desk and key is not None) else []
    if procs:
        if opts.wait:
            log(f"WorkBuddy 桌面端正在运行（{', '.join(procs)}），等它退出后再切换…")
            if not wait_desktop_exit(opts.wait):
                log("等待超时，桌面端还在运行；请退出后重试（运行中的客户端会覆盖登录态）")
                return 5
        elif opts.force:
            log(f"桌面端正在运行（{', '.join(procs)}），按 --force 直接写入（可能被覆盖）")
        elif can_prompt():
            print(f"WorkBuddy 桌面端正在运行（{', '.join(procs)}），"
                  f"运行中的客户端会用内存里的登录态覆盖文件。")
            try:
                ans = input("现在关闭桌面端并继续切换？[Y/n] 默认Y").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                ans = "n"                                # Ctrl+C / 输入流断开 = 取消
            if ans in ("n", "no", "否"):                 # 直接回车 = 默认同意（Y）
                log("已取消，没有写入任何文件。退出桌面端后重跑即可")
                return 5
            if not close_desktop(procs):
                log("关不掉桌面端，请手动退出后重试")
                return 5
        else:
            log(f"WorkBuddy 桌面端正在运行（{', '.join(procs)}），现在写会被它覆盖。"
                f"请先退出桌面端，或加 --wait 自动等待、--force 强行写入")
            return 5

    running = running_apps()
    if running:
        log(f"提示：{' / '.join(running)} 正在运行，它退出时可能覆盖共享登录态；"
            f"建议先在应用里退出，或切完重启它")

    # 先把桌面端的登录态拼出来并自校验（密封后要能解回来），失败就不碰桌面端文件
    built_desktop = None
    desk_before = read_json(desk) or {} if desk else {}
    if desk and key is not None:
        try:
            built_desktop = build_desktop_session(rec, profile, desk_before, key, key_id)
            if open_field(built_desktop["auth"]["accessToken"], key) != rec["token"]:
                raise RuntimeError("密封自校验不通过")
        except Exception as exc:
            log(f"桌面端登录态生成失败（{exc}），本次只切共享登录态")
            built_desktop = None
            desktop_error = str(exc)

    target.parent.mkdir(parents=True, exist_ok=True)
    shared_before = read_json(target) if target.exists() else None
    write_json_atomic(target, data, compact=True)

    check = read_json(target) or {}
    got = (check.get("account") or {}).get("uid")
    if got != rec["uid"]:
        if isinstance(shared_before, dict):          # 写坏了就当场还原，不留残局
            write_json_atomic(target, shared_before, compact=True)
            log("写入校验失败，已还原原共享登录态")
        log(f"写入校验失败：文件里的 uid={got}，期望 {rec['uid']}")
        return 4

    if built_desktop is not None:
        write_json_atomic(desk, built_desktop, compact=True)
        check_doc = read_json(desk) or {}
        check_uid = (check_doc.get("account") or {}).get("uid")
        try:
            check_token = open_field((check_doc.get("auth") or {}).get("accessToken"), key)
        except Exception:
            check_token = ""
        if check_uid != rec["uid"] or check_token != rec["token"]:
            log("桌面端写入校验失败，已还原桌面端文件（共享登录态保持已切换）")
            write_json_atomic(desk, desk_before, compact=True)
            built_desktop = None
            desktop_error = "写入校验失败，已还原"
        else:
            log(f"WorkBuddy 桌面端已切换 → {desk.name}")

    profiles[rec["uid"]] = profile              # 新账号资料也存一份，下次切换字段更全
    save_profiles(profiles)

    scope = "WorkBuddy 客户端（共享登录态）"
    if built_desktop is not None:
        scope += " + WorkBuddy 桌面端"
    log(f"已切换到 {label(rec)}（token 到期 {fmt_ts(exp)}"
        + ("，已过期" if expired else "") + f"）")
    log(f"生效范围：{scope}")
    if note:
        log(f"备注：{note}")
    if desktop_error:
        log(f"备注：桌面端未切换（{desktop_error}）")

    launched = launch_desktop(opts, switched=built_desktop is not None)

    # 切完报一下这个账号现在还能用多少积分（列表里刚读过就不重复请求）；
    # 余额只是锦上添花，读挂了也不能让已经切好的号看起来像失败
    try:
        bal = rec.get("balance") or {}
        stale = now_ms() - int(bal.get("updatedAt") or 0) > BALANCE_FRESH_MS
        if stale and not opts.no_balance:
            persist_balances(store, refresh_balances([rec], live=True))
        bal = rec.get("balance") or {}
        if bal.get("left") is not None:
            log(f"{label(rec)} 当前可用积分：{balance_text(bal)}")
    except Exception as exc:
        log(f"备注：余额没读到（{type(exc).__name__}: {exc}）")

    if opts.json:
        print(json.dumps({"ok": True, "uid": rec["uid"], "nickname": label(rec),
                          "expiresAt": exp, "file": str(target),
                          "balance": rec.get("balance"),
                          "desktop": {"switched": built_desktop is not None,
                                      "file": str(desk) if desk else None,
                                      "error": desktop_error,
                                      "launched": launched}},
                         ensure_ascii=False))
    return 0


# ---- 列表 ----

def print_list(as_json: bool) -> int:
    store = load_store()
    accounts = sorted(store.get("accounts", {}).values(), key=label)
    current = main_auth_file()
    current_uid = current["uid"] if current else ""
    status = refresh_balances(accounts, live=not NO_BALANCE)
    persist_balances(store, status)              # 顺手把新余额落盘，accounts.json / .md 保持最新

    rows = []
    for idx, rec in enumerate(accounts, 1):
        exp = rec.get("expiresAt") or 0
        state = "可用" if exp and exp > now_ms() else "已过期"
        bal = rec.get("balance") or {}
        stat = status.get(rec["uid"]) or {}
        rows.append({
            "index": idx,
            "uid": rec["uid"],
            "nickname": label(rec),
            "state": state,
            "expiresAt": exp,
            "active": rec["uid"] == current_uid,
            "balance": {"left": bal.get("left"), "total": bal.get("total"),
                        "used": bal.get("used"), "updatedAt": bal.get("updatedAt"),
                        "live": bool(stat.get("live")),
                        "reason": stat.get("reason") or ""},
        })

    if as_json:
        print(json.dumps({"ok": True, "authFile": str(current["path"]) if current else None,
                          "activeUid": current_uid, "accounts": rows}, ensure_ascii=False))
        return 0

    head = f"客户端 {'WorkBuddy':<10} 当前登录：{current['nickname'] or current_uid[:8]}" if current else ""
    if head:
        print(head)
    desk = desktop_note(store)
    if desk:
        print(f"客户端 {'WorkBuddy 桌面端':<10} 当前登录：{desk}")
    if not current and not desk:
        print("未检测到登录态")
    print()
    print("  " + pad_display("序号", 4) + "  " + pad_display("用户名", 12)
          + "  " + pad_display("余额", 10) + "  " + pad_display("状态", 6))
    for row in rows:
        mark = "← 当前" if row["active"] else ""
        suffix = f"  {mark}" if mark else ""
        print(("  " + pad_display(str(row["index"]), 4) + "  "
               + pad_display(row["nickname"], 12) + "  "
               + pad_display(fmt_num(row["balance"]["left"]), 10) + "  "
               + pad_display(row["state"], 6) + suffix).rstrip())

    failed = [(r["nickname"], r["balance"]["reason"]) for r in rows
              if not r["balance"]["live"] and r["balance"]["reason"]]
    if failed:
        print("余额读取失败：" + "；".join(f"{n}（{why}）" for n, why in failed))
    print("\n切换：switch.bat w <序号|账号名>，或直接运行 switch.bat 交互选择")
    return 0


# ---- 校验 ----

def check_token_valid(token: str, uid: str, domain: str) -> tuple:
    """拿 token 调一次只读的签到接口，验证它现在还能不能用，返回 (是否有效, 说明)"""
    if not wb:
        return (False, f"签到脚本不可用，跳过联网校验（{WB_IMPORT_ERROR}）")
    try:
        data = wb.api("checkin-activity-status",
                      {"token": token, "uid": uid, "domain": domain or "www.codebuddy.cn"})
    except Exception as exc:
        return (False, f"接口调用失败：{exc}")
    valid = data.get("code") == 0
    detail = f"签到接口返回 code={data.get('code')}"
    if data.get("msg"):
        detail += f"（{data['msg']}）"
    return (valid, detail)


def verify(as_json: bool) -> int:
    """证明「客户端实际读到的账号」是谁，并验证 token 还能不能用"""
    current = main_auth_file()
    if not current:
        if as_json:
            print(json.dumps({"ok": False, "error": "no-auth-file"}, ensure_ascii=False))
        else:
            print("没有找到共享登录态文件（先用 WorkBuddy 客户端登录一次）")
        return 1

    auth = current["data"].get("auth") or {}
    uid = current["uid"]
    exp = auth.get("expiresAt") or 0
    token = auth.get("accessToken")
    valid, detail = False, "文件里没有 accessToken"
    if isinstance(token, str) and token:
        valid, detail = check_token_valid(token, uid, auth.get("domain") or "")

    # 桌面端那份：解密看账号，同样调接口验证
    desk = desktop_file()
    desk_info = None
    if desk:
        try:
            dkey, _ = get_atrest_key()
        except Exception as exc:
            desk_info = {"file": str(desk), "error": str(exc)}
        else:
            doc = read_json(desk) or {}
            info = desktop_account(doc, dkey)
            dauth = doc.get("auth") or {}
            dvalid, ddetail = False, "文件里没有 accessToken"
            try:
                dtoken = open_field(dauth["accessToken"], dkey)
            except Exception as exc:
                dtoken, ddetail = "", f"解密失败：{exc}"
            if dtoken:
                dvalid, ddetail = check_token_valid(dtoken, info["uid"], dauth.get("domain") or "")
            desk_info = {"file": str(desk), "uid": info["uid"],
                         "nickname": info["nickname"], "expiresAt": dauth.get("expiresAt") or 0,
                         "tokenValid": dvalid, "detail": ddetail}

    if as_json:
        print(json.dumps({"ok": valid, "uid": uid, "nickname": current["nickname"],
                          "file": str(current["path"]), "expiresAt": exp,
                          "tokenValid": valid, "detail": detail,
                          "desktop": desk_info}, ensure_ascii=False))
        return 0 if valid else 3

    print(f"WorkBuddy 客户端读到的账号：{current['nickname'] or uid}（{uid}）")
    print(f"登录态文件：{current['path']}")
    print(f"token 到期：{fmt_ts(exp)}")
    print(("token 校验：有效" if valid else "token 校验：无效") + f"  {detail}")
    if desk_info:
        if desk_info.get("error"):
            print(f"WorkBuddy 桌面端：读不出来（{desk_info['error']}）")
        else:
            name = desk_info.get("nickname") or desk_info.get("uid") or "未知账号"
            print(f"WorkBuddy 桌面端：{name}（{desk_info.get('uid', '')}）")
            print(f"  token 到期：{fmt_ts(desk_info.get('expiresAt'))}，"
                  f"校验：{'有效' if desk_info.get('tokenValid') else '无效'}"
                  f"  {desk_info.get('detail', '')}")
    return 0 if valid else 3


def ask_account() -> str:
    """不带参数运行时：列账号 + 让用户敲序号/账号名"""
    print_list(as_json=False)
    if not (sys.stdin and sys.stdin.isatty()):
        print("非交互环境，请直接带上账号：switch.bat w <序号|账号名|uid 前缀>")
        return ""
    try:
        sel = input("输入要切换的序号 / 账号名（直接回车返回上一层）：").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    return sel


def hold_window(prompted: bool, code: int) -> None:
    """交互式跑完后别让窗口一闪而过

    switch.bat 走菜单时自己会停（并设 SWITCH_NO_PAUSE），这里只给「直接跑 python」
    兜底；stdin 读不到（管道 / 已关闭）立刻返回，不会挂住调用方。"""
    if not prompted or QUIET or os.environ.get("SWITCH_NO_PAUSE"):
        return
    hint = "按回车键退出..." if code == 0 else f"按回车键退出（退出码 {code}）..."
    try:
        input("\n" + hint)
    except (EOFError, KeyboardInterrupt):
        print()
    except Exception:
        pass


def main() -> int:
    global QUIET, NO_BALANCE

    parser = argparse.ArgumentParser(
        prog="switch.bat w",
        description="切换 WorkBuddy 的当前登录账号",
        add_help=True,
    )
    parser.add_argument("account", nargs="?", help="序号 / 账号名 / uid / uid 前缀（留空则交互选择）")
    parser.add_argument("-l", "--list", action="store_true", help="只列出账号与当前登录，不切换")
    parser.add_argument("--verify", action="store_true",
                        help="校验客户端实际读到的账号 / token 是否有效")
    parser.add_argument("--refresh", action="store_true", help="切换前强制续期 token")
    parser.add_argument("--no-refresh", action="store_true", help="不做任何续期，直接用现有 token")
    parser.add_argument("--dry-run", action="store_true", help="只演练，不写文件")
    parser.add_argument("-f", "--force", action="store_true", help="已经是目标账号也强制重写；桌面端在运行时也直接写入")
    parser.add_argument("--wait", nargs="?", const=120, type=int, metavar="秒",
                        help="WorkBuddy 桌面端在运行时等它退出（默认 120 秒）")
    parser.add_argument("--launch", action="store_true",
                        help="切成功后启动 WorkBuddy 桌面端（交互终端里默认就会启动）")
    parser.add_argument("--no-launch", action="store_true",
                        help="切成功后不启动 WorkBuddy 桌面端")
    parser.add_argument("-q", "--quiet", action="store_true", help="安静模式：只输出错误")
    parser.add_argument("-j", "--json", action="store_true", help="输出 JSON（便于其它程序调用）")
    parser.add_argument("--no-balance", action="store_true",
                        help="不联网刷新积分余额，只显示 accounts.json 里的缓存值")
    opts = parser.parse_args()

    QUIET = opts.quiet or opts.json      # JSON 模式下不让日志混进 stdout
    NO_BALANCE = opts.no_balance

    if opts.verify:
        return verify(opts.json)
    if opts.list:
        return print_list(opts.json)

    if opts.account:
        code = do_switch(opts.account, opts)
        if opts.json and code != 0:
            print(json.dumps({"ok": False, "exitCode": code}, ensure_ascii=False))
        return code

    # 交互模式：反复列账号 + 切换，直接回车才返回上一层（回到产品菜单）
    while True:
        selector = ask_account()
        if not selector:
            print("已返回上一层")
            return 0
        code = do_switch(selector, opts)
        if code == 0 and LAUNCHED:
            # 已经切好并把桌面端开起来了，再列一遍账号没有意义，直接收工
            print("已切号并启动桌面端，本次切换结束")
            return 0


if __name__ == "__main__":
    sys.exit(main())
