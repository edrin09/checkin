# -*- coding: utf-8 -*-
"""切换 Trae 客户端当前登录的账号（直接写客户端登录态，切完重开客户端即生效）

签到脚本只读登录态；这个脚本反过来，把 accounts.json 里某个账号的登录态写回
  %APPDATA%\\<客户端>\\User\\globalStorage\\storage.json
的 `iCubeAuthInfo://icube.cloudide`（和 `iCubeAuthInfo://usertag`），
客户端读的就是这份 state，切完重开客户端即用这个账号。

要点：
- 写入格式与客户端自己落盘的一模一样：新版走明文 JSON，旧版走 tc 加密。
  tc 加密算法（头部 + AES-128-CBC + SHA-512 校验段）在 checkin_trae.py 里已能解密，
  这里按同样结构重新加密，写之前会先自解密校验一遍，保证客户端能读回
- **必须先退出 Trae**：客户端运行时会用内存里的登录态覆盖 storage.json，
  切了也白切；用 --wait 可以让脚本等它退出后再切
- 切成功后自动启动 Trae：交互终端里切完就把它开回来（刚才为写文件退出的是同一个），
  --no-launch 可关掉，环境变量 SWITCH_NO_LAUNCH=1 全局关闭；--quiet / --json 一律不启动
- 只改登录态相关的键，其它窗口 / 主题 / 工作区状态原样保留
- 不落备份、不写日志文件：切换结果只在终端输出；顺带读到的积分余额会写回 accounts.json
- 切号前会实时读一次每个账号的积分余额（只读接口），读不到才退回缓存值并标注时间
- token 过期也能切过去（客户端启动时会用自己的设备证明去续期），但过期太久会要求重新登录

用法（入口统一放在仓库根目录的 switch.bat，w = WorkBuddy，t = Trae）：
  switch.bat t                       # 交互式：列出账号，敲序号切换
  switch.bat                         # 先选产品（WorkBuddy / Trae）再选账号
  switch.bat t --list                # 只看账号（含当前可用积分余额）/ 各客户端当前登录，不切换
  switch.bat t --verify              # 校验每个客户端实际读到的账号 / token 是否有效
  switch.bat t edrin                 # 按账号名切换（也支持 userId / userId 前缀 / 序号）
  switch.bat t 1                     # 按列表序号切换
  switch.bat t edrin --wait          # 等 Trae 退出（最多 120 秒）后自动切
  switch.bat t edrin --no-launch     # 切成功也不启动 Trae
  switch.bat t edrin --only "Trae CN"  # 只切某一个客户端
  switch.bat t edrin --quiet         # 只出错才输出（给其它程序调用）
  switch.bat t edrin --json          # 输出机器可读结果
  switch.bat t edrin --dry-run       # 只演练，不写文件

退出码：0 成功；1 一般错误；2 找不到账号；4 写入校验失败；5 Trae 正在运行
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Cipher import AES
# 名字必须带前缀：本文件另有一个显示用的 pad_display()（原来叫 pad），
# 直接 import pad 会被它的定义覆盖，加密时调到显示函数就崩
from Crypto.Util.Padding import pad as pkcs7_pad

BASE_DIR = Path(__file__).resolve().parent

# 复用签到脚本的客户端探测 / 登录态解析
sys.path.insert(0, str(BASE_DIR))
import checkin_trae as ct

QUIET = False
NO_BALANCE = False          # --no-balance：只看 accounts.json 里的缓存余额，不联网
LAUNCHED = []               # 本次运行实际启动的客户端（交互循环据此收工）

CLIENT_EXE_ENV = "TRAE_APP_EXECUTABLE"    # 手动指定客户端 exe 的环境变量
NO_LAUNCH_ENV = "SWITCH_NO_LAUNCH"        # 设成 1 就彻底关掉「切完自动启动」

USER_TAG_KEY = "iCubeAuthInfo://usertag"     # 登录态之外的账号区域标记（{userId: 'cn'|'row'}）

# 区域 → (storeRegion, userTag)：Trae CN 走 CN/cn，其余走 ROW
REGION_TAGS = {"cn": ("CN", "cn")}
DEFAULT_TAG = ("SG", "row")


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


def iso_ms(ms) -> str:
    """毫秒时间戳 → 客户端那种 '2026-11-07T06:01:29.530Z'"""
    try:
        dt = datetime.fromtimestamp(int(ms) / 1000, timezone.utc)
    except Exception:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(ms) % 1000:03d}Z"


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json_atomic(path: Path, data: dict) -> None:
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def label(rec: dict) -> str:
    return rec.get("username") or rec.get("userId") or "?"


# ---- tc 加密（与客户端 / checkin_trae.decrypt_auth 对称）----

TC_HEADER = bytes([0x74, 0x63, 0x05, 0x10, 0x00, 0x00])   # "tc" + 版本/长度标记
TC_XOR = bytes(a ^ b for a, b in zip(ct.URE, ct.DRE))


def encrypt_auth(obj: dict) -> str:
    """按旧版客户端的 tc 格式加密：头部(6) + 随机密钥(32) + AES-CBC(SHA512(body)+body)"""
    body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    key = os.urandom(32)
    mixed = hashlib.sha512(hashlib.sha512(key).digest() + TC_XOR).digest()
    ct_bytes = AES.new(mixed[:16], AES.MODE_CBC, mixed[16:32]).encrypt(
        pkcs7_pad(hashlib.sha512(body).digest() + body, AES.block_size))
    return base64.b64encode(TC_HEADER + key + ct_bytes).decode("ascii")


def encode_like(sample, obj: dict) -> str:
    """按目标客户端现有的落盘格式写：明文 JSON 客户端继续给明文，tc 加密客户端继续给密文"""
    if isinstance(sample, str) and sample.lstrip().startswith("{"):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return encrypt_auth(obj)


def verify_blob(blob: str, uid: str) -> bool:
    """按客户端的解密逻辑回读一遍，确认写进去的确实能解出目标账号"""
    try:
        return str(ct.parse_auth(blob).get("userId")) == str(uid)
    except Exception:
        return False


# ---- 账号仓库 / 解析 ----

def load_store() -> dict:
    return ct.load_store()


def save_store(store: dict) -> None:
    ct.save_store(store)


def resolve(selector: str, accounts: list):
    sel = (selector or "").strip()
    if not sel:
        return None
    low = sel.casefold()

    for rec in accounts:                                    # 完整 userId
        if str(rec.get("userId") or "").casefold() == low:
            return rec

    if sel.isdigit() and 1 <= int(sel) <= len(accounts):     # 序号
        return accounts[int(sel) - 1]

    if len(sel) >= 4:                                       # userId 前缀
        for rec in accounts:
            if str(rec.get("userId") or "").startswith(sel):
                return rec

    exact = [r for r in accounts if label(r).casefold() == low]
    if len(exact) == 1:
        return exact[0]
    part = [r for r in accounts if low in label(r).casefold()]
    return part[0] if len(part) == 1 else None


# ---- 积分余额 ----
#
# 切号前先看一眼「切过去还能用多少积分」：联网读一次只读接口（和客户端「用量」
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

    别把名字改回 pad：会和 Crypto.Util.Padding.pad 撞名。"""
    used = sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)
    return text + " " * max(width - used, 0)


def _quiet_log(msg: str) -> None:
    """顶替签到脚本的 log：不打印也不写 checkin.log，只留下失败原因"""
    bucket = getattr(_tls, "msgs", None)
    if bucket is not None:
        bucket.append(msg)


def fetch_one(rec: dict) -> tuple:
    """读一个账号的余额，返回 (balance 或 None, 失败原因)"""
    _tls.msgs = []
    try:
        bal = ct.fetch_balance(rec)
    except Exception as exc:
        bal, _tls.msgs = None, [f"{type(exc).__name__}: {exc}"]
    reason = _tls.msgs[-1] if _tls.msgs else ""
    if reason.startswith("["):                 # "[账号 userId] 查询积分余额失败：xxx" → 只留原因
        reason = reason.split("]", 1)[-1].strip()
    return bal, reason


def refresh_balances(accounts: list, live: bool = True) -> dict:
    """给每个账号的 rec 补上最新 balance，返回 {userId: {live, reason}}

    live=False（--no-balance）只读缓存值，不联网。"""
    status = {str(rec["userId"]): {"live": False, "reason": ""} for rec in accounts}
    if not (live and accounts):
        return status
    saved, ct.log = ct.log, _quiet_log          # 读余额期间别让签到脚本的日志混进输出
    try:
        with ThreadPoolExecutor(max_workers=min(BALANCE_WORKERS, len(accounts))) as pool:
            futures = {pool.submit(fetch_one, rec): rec for rec in accounts}
            for fut in as_completed(futures):
                rec = futures[fut]
                bal, reason = fut.result()
                if bal:
                    rec["balance"] = bal
                    status[str(rec["userId"])]["live"] = True
                else:
                    status[str(rec["userId"])]["reason"] = reason
    finally:
        ct.log = saved
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
        ct.render_accounts_md(store)
    except Exception:
        pass


# ---- 客户端探测 ----

def clients() -> list:
    """本机存在登录态文件的客户端 [(名称, storage.json 路径)]"""
    out = []
    for name, path, _app_dir in ct.scan_targets():
        if path.exists() and ct.AUTH_KEY in read_json(path):
            out.append((name, path))
    return out


def current_of(path: Path) -> dict:
    """客户端当前登录的账号（解析失败返回空 dict）"""
    enc = read_json(path).get(ct.AUTH_KEY)
    if not enc:
        return {}
    try:
        auth = ct.parse_auth(enc)
    except Exception:
        return {}
    return {"userId": str(auth.get("userId") or ""),
            "username": (auth.get("account") or {}).get("username") or "",
            "expiresAt": ct.parse_expired_at(auth)}


def trae_processes() -> list:
    """正在运行的 Trae 相关进程名"""
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True,
                             timeout=15).stdout.decode("mbcs", "ignore")
    except Exception:
        return []
    names = set()
    for line in out.splitlines():
        head = line.split(",")[0].strip('"')
        if head.lower().startswith("trae"):
            names.add(head)
    return sorted(names)


# ---- 登录态组装 ----

def build_auth(rec: dict) -> dict:
    """照客户端 convertTokenToUserInfo 的结构组装登录态"""
    uid = str(rec["userId"])
    region = str(rec.get("region") or "cn").lower()
    store_region, user_tag = REGION_TAGS.get(region, DEFAULT_TAG)
    username = rec.get("username") or uid
    now = now_ms()

    return {
        "token": rec["token"],
        "refreshToken": rec.get("refreshToken") or "",
        "expiredAt": iso_ms(rec.get("expiresAt") or 0),
        "refreshExpiredAt": iso_ms(rec.get("refreshExpiresAt") or 0),
        "tokenReleaseAt": iso_ms(now),
        "userId": uid,
        "host": (rec.get("host") or ct.DEFAULT_HOST).rstrip("/"),
        "userRegion": {"region": region.upper(), "_aiRegion": region.upper()},
        "account": {
            "username": username,
            "iss": "",
            "iat": 0,
            "organization": "",
            "work_country": "",
            "email": username if "@" in username else "",
            "avatar_url": "",
            "description": "",
            "scope": "marscode",
            "loginScope": "trae",
            "storeCountryCode": "",
            "storeCountrySrc": "",
            "storeRegion": store_region,
            "userTag": user_tag,
        },
    }


def merged_usertag(path: Path, uid: str, tag: str) -> str:
    """usertag 是 {userId: 'cn'|'row'} 的加密串，保留其它账号的，再写当前账号"""
    old, sample = {}, None
    enc = read_json(path).get(USER_TAG_KEY)
    if enc:
        sample = enc
        try:
            parsed = ct.parse_auth(enc) if isinstance(enc, str) else enc
            if isinstance(parsed, dict):
                old = dict(parsed)
        except Exception:
            pass
    old[str(uid)] = tag
    return encode_like(sample, old)


# ---- 切换 ----

def wait_for_exit(seconds: int) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if not trae_processes():
            return True
        if not QUIET:
            print(f"\r等待 Trae 退出… 剩余 {int(deadline - time.time())}s", end="", flush=True)
        time.sleep(2)
    if not QUIET:
        print()
    return not trae_processes()


def can_prompt() -> bool:
    """交互终端里才允许提问（--quiet / --json 一律不打断调用方）"""
    return bool(sys.stdin and sys.stdin.isatty()) and not QUIET


def confirm_close(procs: list) -> bool:
    """确认关闭客户端：默认值 Y，直接回车即同意，只有明确输入 n 才取消"""
    print(f"Trae 正在运行（{', '.join(procs)}），"
          f"运行中的客户端会用内存里的登录态覆盖文件。")
    try:
        ans = input("现在关闭 Trae 并继续切换？[Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False                                     # Ctrl+C / 输入流断开 = 取消
    return ans not in ("n", "no", "否")


def close_trae(procs: list, grace: int = 20) -> bool:
    """先礼后兵：先发正常关闭请求，超时再强杀"""
    log(f"正在关闭 Trae（{', '.join(procs)}）…")
    for name in procs:
        try:
            subprocess.run(["taskkill", "/IM", name], capture_output=True, timeout=20)
        except Exception:
            pass
    if wait_for_exit(grace):
        return True
    left = trae_processes()
    if left:
        log(f"Trae 没有响应关闭请求（{', '.join(left)}），强制结束…")
        for name in left:
            try:
                subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True, timeout=20)
            except Exception:
                pass
    return wait_for_exit(10)


# ---- 切完自动启动客户端 ----
#
# 切号前脚本要求先退出 Trae（运行中的客户端会用内存里的登录态覆盖文件），
# 所以切成功后当然要把它还给你：交互式切号的目的就是「换完号接着用」。
#   · 默认只在交互终端（双击 / 手动跑）里启动；--quiet / --json / 管道调用一律不启动
#   · --launch 强制启动、--no-launch 不启动；环境变量 SWITCH_NO_LAUNCH=1 全局关掉
#   · 客户端已经在跑（--force 强行写入的情形）就不重复启动
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


def _exe_in_dirs(name: str) -> str:
    """常见安装目录：%LOCALAPPDATA%\\Programs\\<客户端>、%ProgramFiles%\\<客户端> 等"""
    dirs = []
    for var in ("LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(var, "")
        if root:
            dirs += [Path(root) / "Programs" / name, Path(root) / name]
    for d in dirs:
        for exe in (f"{name}.exe", "Trae.exe"):
            if (d / exe).is_file():
                return str(d / exe)
    return ""


def _exe_from_uninstall(name: str) -> str:
    """从注册表卸载项里找（DisplayIcon / InstallLocation）：装到 D 盘这类自定义目录靠它"""
    if os.name != "nt":
        return ""
    import winreg
    key_low = name.casefold()
    exe_low = f"{name}.exe".casefold()
    for hive, view in ((winreg.HKEY_CURRENT_USER, 0),
                       (winreg.HKEY_LOCAL_MACHINE, 0),
                       (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY)):
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
                    item = winreg.OpenKey(root, sub)
                except OSError:
                    continue
                with item:
                    try:
                        display = str(winreg.QueryValueEx(item, "DisplayName")[0]).casefold()
                    except OSError:
                        display = ""
                    if key_low not in display:
                        continue
                    for value_name in ("DisplayIcon", "InstallLocation"):
                        try:
                            value = str(winreg.QueryValueEx(item, value_name)[0])
                        except OSError:
                            continue
                        value = value.split(",")[0].strip().strip('"').strip()
                        if not value:
                            continue
                        path = Path(value)
                        if path.is_file() and path.name.casefold() == exe_low:
                            return str(path)
                        if path.is_dir() and (path / f"{name}.exe").is_file():
                            return str(path / f"{name}.exe")
    return ""


def _exe_from_logs(name: str) -> str:
    """兜底：翻客户端自己的 main.log 里出现的启动路径（注册表也没登记时用）"""
    appdata = os.environ.get("APPDATA", "")
    root = Path(appdata) / name / "logs" if appdata else None
    if root is None or not root.is_dir():
        return ""
    try:
        dirs = sorted((d for d in root.iterdir() if d.is_dir()), reverse=True)[:2]
    except OSError:
        return ""
    want = key_of(name)
    for d in dirs:
        log_file = d / "main.log"
        if not log_file.is_file():
            continue
        try:
            text = log_file.read_text(encoding="utf-8", errors="ignore")[:200000]
        except OSError:
            continue
        for raw in re.findall(r"[A-Za-z]:(?:\\\\|\\|/)[^\"'\r\n]*?\.exe", text):
            candidate = Path(raw.replace("\\\\", "\\"))
            if key_of(candidate.stem) == want and candidate.is_file():
                return str(candidate)
    return ""


def key_of(text: str) -> str:
    """比较用的归一化名字：去空格、转小写（'Trae CN' / 'trae cn' 视为同一个）"""
    return text.casefold().replace(" ", "").replace("-", "")


def find_client_executable(name: str) -> str:
    """找一个客户端的 exe：环境变量 → 常见目录 → 注册表卸载项 → 客户端日志"""
    env = os.environ.get(CLIENT_EXE_ENV, "").strip()
    if env and Path(env).is_file():
        return env
    for probe in (_exe_in_dirs, _exe_from_uninstall, _exe_from_logs):
        try:
            found = probe(name)
        except Exception:
            found = ""
        if found:
            return found
    return ""


def launch_clients(opts, names: list) -> list:
    """切成功后把被切的客户端重新打开，返回 [客户端名]"""
    if not names or not should_launch(opts):
        return []
    if trae_processes():
        log("Trae 已在运行，不重复启动")
        return []
    launched = []
    for name in dict.fromkeys(names):                # 去重且保序
        exe = find_client_executable(name)
        if not exe:
            log(f"没找到 {name} 的可执行文件，跳过自动启动"
                f"（可用环境变量 {CLIENT_EXE_ENV} 指定 exe）")
            continue
        if spawn_detached(exe):
            log(f"已启动 {name}（{exe}）")
            launched.append(name)
    LAUNCHED.extend(launched)
    return launched


def do_switch(selector: str, opts) -> int:
    store = load_store()
    accounts = sorted(store.get("accounts", {}).values(), key=label)
    if not accounts:
        log("accounts.json 里没有账号，先跑一次 trae.bat --login")
        return 1

    rec = resolve(selector, accounts)
    if not rec:
        log(f"找不到账号：{selector}（用 --list 看可用账号）")
        return 2

    targets = clients()
    if not targets:
        log("没找到任何带登录态的 Trae 客户端（先打开客户端登录一次）")
        return 1
    if opts.only:
        key = opts.only.casefold()
        targets = [(n, p) for n, p in targets if key in n.casefold()]
        if not targets:
            log(f"没有匹配的客户端：{opts.only}")
            return 1

    exp = rec.get("expiresAt") or 0
    if opts.dry_run:
        for name, path in targets:
            log(f"[dry-run] {name}：{current_of(path).get('username') or '未登录'}"
                f" → {label(rec)}（token 到期 {fmt_ts(exp)}）")
        if opts.json:
            print(json.dumps({"ok": True, "dryRun": True, "userId": rec["userId"],
                              "username": label(rec), "clients": [n for n, _ in targets]},
                             ensure_ascii=False))
        return 0

    procs = trae_processes()
    if procs:
        if opts.wait:
            log(f"Trae 正在运行（{', '.join(procs)}），等它退出后再切换…")
            if not wait_for_exit(opts.wait):
                log("等待超时，Trae 还在运行；请退出后重试（运行中的客户端会覆盖登录态）")
                return 5
        elif opts.force:
            log(f"Trae 正在运行（{', '.join(procs)}），按 --force 直接写入（可能被覆盖）")
        elif can_prompt():
            if not confirm_close(procs):
                log("已取消，没有写入任何文件。退出 Trae 后重跑即可")
                return 5
            if not close_trae(procs):
                log("关不掉 Trae，请手动退出后重试")
                return 5
        else:
            log(f"Trae 正在运行（{', '.join(procs)}），现在写会被它覆盖。"
                f"请先退出 Trae，或加 --wait 自动等待、--force 强行写入")
            return 5

    auth = build_auth(rec)
    tag = auth["account"]["userTag"]
    for name, path in targets:
        old = current_of(path)
        if old.get("userId") == str(rec["userId"]) and not opts.force:
            log(f"{name} 已经是 {label(rec)}，跳过（--force 可强制重写）")
            continue

        storage = read_json(path)
        blob = encode_like(storage.get(ct.AUTH_KEY), auth)
        if not verify_blob(blob, rec["userId"]):
            log("自校验失败：生成的登录态解不出来，已中止（未写入任何文件）")
            return 4
        usertag = merged_usertag(path, rec["userId"], tag)

        storage[ct.AUTH_KEY] = blob
        storage[USER_TAG_KEY] = usertag
        write_json_atomic(path, storage)

        check = current_of(path)
        if check.get("userId") != str(rec["userId"]):
            log(f"{name} 写入校验失败：现在是 {check.get('userId')}，期望 {rec['userId']}")
            return 4
        log(f"{name}：{old.get('username') or '未登录'} → {label(rec)}"
            f"（token 到期 {fmt_ts(exp)}）")

    log(f"已切换到 {label(rec)}")

    # 切号前刚让用户退出了 Trae，切完顺手把它开回来（--no-launch 可关）
    launched = launch_clients(opts, [n for n, _ in targets])

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
        print(json.dumps({"ok": True, "userId": rec["userId"], "username": label(rec),
                          "expiresAt": exp, "balance": rec.get("balance"),
                          "clients": [n for n, _ in targets],
                          "launched": launched},
                         ensure_ascii=False))
    return 0


# ---- 列表 / 交互式选择 ----

def print_list(as_json: bool) -> int:
    store = load_store()
    accounts = sorted(store.get("accounts", {}).values(), key=label)
    rows, active = [], {}
    for name, path in clients():
        cur = current_of(path)
        active[name] = (cur.get("userId") or "", cur.get("username") or "")

    status = refresh_balances(accounts, live=not NO_BALANCE)
    persist_balances(store, status)              # 顺手把新余额落盘，accounts.json / .md 保持最新

    for idx, rec in enumerate(accounts, 1):
        exp = rec.get("expiresAt") or 0
        bal = rec.get("balance") or {}
        stat = status.get(str(rec["userId"])) or {}
        rows.append({
            "index": idx,
            "userId": str(rec["userId"]),
            "username": label(rec),
            "state": "可用" if exp and exp > now_ms() else "已过期",
            "expiresAt": exp,
            "activeIn": [n for n, (uid, _) in active.items() if uid == str(rec["userId"])],
            "balance": {"left": bal.get("left"), "total": bal.get("total"),
                        "used": bal.get("used"), "updatedAt": bal.get("updatedAt"),
                        "live": bool(stat.get("live")),
                        "reason": stat.get("reason") or ""},
        })

    if as_json:
        print(json.dumps({"ok": True, "accounts": rows,
                          "clients": {n: {"userId": u, "username": s}
                                      for n, (u, s) in active.items()}},
                         ensure_ascii=False))
        return 0

    if active:
        for name, (uid, username) in active.items():
            who = next((r["username"] for r in rows if r["userId"] == uid),
                       username or uid or "未登录")
            print(f"客户端 {name:<10} 当前登录：{who}")
    else:
        print("未检测到带登录态的 Trae 客户端")
    print()
    print("  " + pad_display("序号", 4) + "  " + pad_display("用户名", 12)
          + "  " + pad_display("余额", 10) + "  " + pad_display("状态", 6))
    for row in rows:
        mark = f"← {', '.join(row['activeIn'])}" if row["activeIn"] else ""
        suffix = f"  {mark}" if mark else ""
        print(("  " + pad_display(str(row["index"]), 4) + "  "
               + pad_display(row["username"], 12) + "  "
               + pad_display(fmt_num(row["balance"]["left"]), 10) + "  "
               + pad_display(row["state"], 6) + suffix).rstrip())

    failed = [(r["username"], r["balance"]["reason"]) for r in rows
              if not r["balance"]["live"] and r["balance"]["reason"]]
    if failed:
        print("余额读取失败：" + "；".join(f"{n}（{why}）" for n, why in failed))
    print("\n切换：switch.bat t <序号|账号名>，或直接运行 switch.bat 交互选择")
    if trae_processes():
        print("注意：Trae 正在运行，切换前请先退出（或加 --wait）")
    return 0


# ---- 校验 ----

def verify(as_json: bool) -> int:
    """证明每个客户端实际读到的账号是谁，并验证 token 还能不能用"""
    targets = clients()
    if not targets:
        if as_json:
            print(json.dumps({"ok": False, "error": "no-client"}, ensure_ascii=False))
        else:
            print("没找到带登录态的 Trae 客户端（先打开客户端登录一次）")
        return 1

    rows, all_ok = [], True
    managed = {str(r.get("userId")) for r in load_store().get("accounts", {}).values()}
    for name, path in targets:
        cur = current_of(path)
        auth = {}
        try:
            auth = ct.parse_auth(read_json(path).get(ct.AUTH_KEY))
        except Exception:
            pass
        token = auth.get("token") or ""
        valid = False
        if token:
            valid = bool(ct.get_user_info(token, {}))       # 只读接口
        uid = cur.get("userId") or ""
        if uid in managed:                                  # 只管 accounts.json 里的账号
            all_ok = all_ok and valid
        rows.append({"client": name, "userId": uid,
                     "username": cur.get("username") or "",
                     "expiresAt": cur.get("expiresAt") or 0,
                     "tokenValid": valid, "managed": uid in managed})

    running = trae_processes()
    if as_json:
        print(json.dumps({"ok": all_ok, "clients": rows, "running": running},
                         ensure_ascii=False))
        return 0 if all_ok else 3

    for row in rows:
        who = row["username"] or row["userId"] or "未登录"
        state = "有效" if row["tokenValid"] else "无效"
        extra = "" if row["managed"] else "（账号不在 accounts.json 里，未纳入管理）"
        print(f"客户端 {row['client']:<10} 读到：{who}（{row['userId']}）"
              f"  token {state}，到期 {fmt_ts(row['expiresAt'])}{extra}")
    if running:
        print(f"注意：{', '.join(running)} 正在运行 —— 界面要重启后才会显示新账号，"
              f"现在切换会被它覆盖")
    return 0 if all_ok else 3


def ask_account() -> str:
    """不带参数运行时：列账号 + 让用户敲序号/账号名"""
    print_list(as_json=False)
    if not (sys.stdin and sys.stdin.isatty()):
        print("非交互环境，请直接带上账号：switch.bat t <序号|账号名|userId 前缀>")
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

    parser = argparse.ArgumentParser(prog="switch.bat t",
                                     description="切换 Trae 客户端当前登录的账号")
    parser.add_argument("account", nargs="?",
                        help="序号 / 账号名 / userId / userId 前缀（留空则交互选择）")
    parser.add_argument("-l", "--list", action="store_true", help="只列出账号，不切换")
    parser.add_argument("--verify", action="store_true",
                        help="校验每个客户端实际读到的账号 / token 是否有效")
    parser.add_argument("--only", help="只切某个客户端，例如 \"Trae CN\"")
    parser.add_argument("--wait", nargs="?", const=120, type=int, metavar="秒",
                        help="等 Trae 退出后再切（默认最多 120 秒）")
    parser.add_argument("--launch", action="store_true",
                        help="切成功后启动 Trae（交互终端里默认就会启动）")
    parser.add_argument("--no-launch", action="store_true",
                        help="切成功后不启动 Trae")
    parser.add_argument("--dry-run", action="store_true", help="只演练，不写文件")
    parser.add_argument("-f", "--force", action="store_true",
                        help="Trae 正在运行也强行写入 / 已是目标账号也重写")
    parser.add_argument("-q", "--quiet", action="store_true", help="安静模式：只输出错误")
    parser.add_argument("-j", "--json", action="store_true", help="输出 JSON（便于其它程序调用）")
    parser.add_argument("--no-balance", action="store_true",
                        help="不联网刷新积分余额，只显示 accounts.json 里的缓存值")
    opts = parser.parse_args()

    QUIET = opts.quiet or opts.json
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
            # 已经切好并把客户端开起来了，再列一遍账号没有意义，直接收工
            print("已切号并启动 Trae，本次切换结束")
            return 0


if __name__ == "__main__":
    sys.exit(main())
