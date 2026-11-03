# -*- coding: utf-8 -*-
"""WorkBuddy 每日自动签到（多账号）

通过 HTTP API 调用官方签到接口（读取本地登录态，无需打开客户端）。
- 只读登录态文件，不修改任何文件
- 多账号：登录态会汇总到同目录 accounts.json（按账号 uid 归并），
  之后每天对 accounts.json 里的所有账号依次签到
- 自动吸收明文登录态：auth 目录下任何带明文 accessToken 的 *.info
  （如 CodeBuddy 的 Tencent-Cloud.coding-copilot.info）每次运行都会被读入并保存，
  因此「登录一个新账号」后跑一次脚本（或开着 --watch）就完成该账号的登记
  最省事的方式：终端运行 codebuddy，在对话框输入 /login 切换账号（每次约 1 分钟）
- 新版 WorkBuddy 客户端（5.6.x+）把 accessToken 加密落盘（{$wbEncrypted, envelope}），
  密钥由客户端原生模块提供、不落盘，本脚本无法解密；这类登录态只会被提示，
  需要同一账号在明文产品（如 CodeBuddy CLI/IDE）里登录一次以完成捕获
- 自动续期：accessToken 快到期时（< 2 天），用 refreshToken 调客户端自己的
  /v2/plugin/auth/token/refresh 换新 token 并写回 accounts.json；
  refreshToken 也会随之轮换，正常每天运行即可长期免登录
- 签到按「腾讯账号」计算：同一账号的多个产品登录态只领一次，按 uid 去重
- 随机延时启动：计划任务触发的时刻固定，脚本内部再随机等待一段时间才真正请求，
  使每天的实际请求时刻都不同，避开整点高峰；同时与 Trae 签到任务错开
- 单次运行限时 25 分钟（计划任务里两个产品错开 30 分钟启动）：预算用完就不再开新账号，
  剩下的留给下午的补签任务，保证两边的日志按时间段能分开、不会互相穿插
- 不打印 token；accounts.json 内含 token，已在 .gitignore 中忽略
- 结果写入仓库根目录 checkin.log（与 Trae 共用一份，每行带 [WorkBuddy] 前缀区分）；
  账号状态（签到/连续/累计/余额/合计）写入同目录 accounts.md，每签完一个账号就刷新一次

用法：
  python checkin_workbuddy.py                 # 正常签到（带随机延时）
  python checkin_workbuddy.py --no-delay      # 立即签到（验证/补签）
  python checkin_workbuddy.py --list          # 查看已捕获账号与本机登录过的账号
  python checkin_workbuddy.py --capture       # 只抓取当前明文登录态，不签到
  python checkin_workbuddy.py --refresh       # 只续期所有账号的 token（不签到）
  python checkin_workbuddy.py --watch 30      # 监听 30 分钟，自动捕获期间登录的账号
"""
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# 缺依赖时给出明确指引，而不是直接抛一堆栈
try:
    import requests
except ModuleNotFoundError:
    sys.stderr.write(
        "缺少依赖 requests：当前解释器没有安装。\n"
        f"  当前解释器：{sys.executable}\n"
        "请先安装依赖：pip install requests pycryptodome\n"
        "或直接用同目录的 workbuddy.bat 运行：\n"
        "  .\\workbuddy.bat --watch 15\n"
    )
    raise SystemExit(2)

# ---- 配置 ----
# WorkBuddy 签到 API（Desktop 网关）
API_BASE = "https://copilot.tencent.com/v2/billing/meter"

# 积分余额 API：客户端「账户用量」面板读的同一个接口（注意这个在根路径下，没有 /v2）
BALANCE_URL = "https://copilot.tencent.com/billing/meter/get-user-resource-summary"

# 网关按 UA 识别客户端来源，缺 User-Agent 会直接 403（code 10085 请求不合法）
CLIENT_USER_AGENT = "WorkBuddy/1.0.0"

# 登录态续期 API（客户端自己用的接口，只需 refreshToken，无需 client secret）
REFRESH_URL = "https://copilot.tencent.com/v2/plugin/auth/token/refresh"

# accessToken 剩余有效期低于该值时自动续期（毫秒）
REFRESH_AHEAD_MS = 2 * 24 * 3600 * 1000

# 登录态文件目录：%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth
AUTH_DIR = Path(os.environ.get("LOCALAPPDATA", "")) / "CodeBuddyExtension" / "Data" / "Public" / "auth"

# WorkBuddy 客户端数据目录（用于识别「登录过但没有可用 token」的账号）
WORKBUDDY_HOME = Path(os.environ.get("USERPROFILE", "")) / ".workbuddy"

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR.parent / "checkin.log"   # 日志统一放仓库根目录（与 Trae 共用一份）
LOG_TAG = "WorkBuddy"                        # 每行日志的产品前缀，两个产品共用日志时用来区分
STORE_FILE = BASE_DIR / "accounts.json"   # 多账号登录态仓库（含 token，注意保密）
ACCOUNTS_MD = BASE_DIR / "accounts.md"    # 账号状态文档（每次签到后自动更新）

# 随机延时启动区间（秒）：计划任务触发时间不变，脚本内部随机等待 1~15 分钟后再请求，
# 使每天的实际请求时刻都不同，避开整点高峰的限流，并与 Trae 签到任务错开
STARTUP_DELAY_RANGE = (60, 900)

# 本次运行的时间预算（分钟）：计划任务里 WorkBuddy 和 Trae 错开 30 分钟启动，
# 单个产品必须在半小时内跑完，日志才不会互相穿插（排查时按时间段就能分清）
RUN_BUDGET_MINUTES = 25
RUN_DEADLINE = 0.0       # main() 里初始化；0 表示不限时（--list / --watch 等命令）

# --watch 的轮询间隔（秒）
WATCH_INTERVAL = 5

# 多账号之间的随机间隔（秒）：避免多个账号在同一秒连发请求，看起来更像真人操作
ACCOUNT_GAP_RANGE = (5, 15)


def log(msg: str) -> None:
    # 每一行都带产品标签：账号相关的行就是 "[WorkBuddy] [账号名] ..."，
    # 和 Trae 的日志合在根目录同一个 checkin.log 里也能一眼分清是谁的
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


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def fmt_ts(ms) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "未知"


def short_uid(uid: str) -> str:
    return (uid or "")[:8]


# ---- 登录态读取 ----

def extract_token(session: dict) -> tuple:
    """从登录态中取出可用的 accessToken 明文。

    新版客户端把 auth.accessToken 从明文字符串改成了加密结构 dict
    （{'$wbEncrypted': 1, 'envelope': ...}，密钥由客户端原生模块提供、不落盘），
    脚本内无法解密。
    返回 (token, err)：token 非空表示可用；否则 err 为失败原因。"""
    auth = session.get("auth") or {}
    tok = auth.get("accessToken")
    if isinstance(tok, str) and tok.strip():
        return tok.strip(), None
    if isinstance(tok, dict):
        # 兜底：若加密结构里仍带明文字段则优先使用
        for k in ("token", "accessToken", "plaintext", "value"):
            v = tok.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip(), None
        return None, "accessToken 已被新版客户端加密落盘（脚本无法解密）"
    return None, "登录态中没有 accessToken，请重新登录"


def scan_sessions() -> tuple:
    """扫描 auth 目录下所有 *.info 登录态。

    返回 (usable, unavailable)：
      usable      —— 带明文 token 的账号记录列表
      unavailable —— 读不到明文 token 的登录态（uid 可能为空）
    """
    usable, unavailable = [], []
    if not AUTH_DIR.is_dir():
        return usable, unavailable

    for path in sorted(AUTH_DIR.glob("*.info")):
        name = path.stem
        session = read_json(path)
        if not isinstance(session, dict):
            unavailable.append({"name": name, "uid": "", "nickname": "", "error": "登录态文件无法解析"})
            continue
        account = session.get("account") or {}
        auth = session.get("auth") or {}
        uid = account.get("uid") or ""
        token, err = extract_token(session)

        entry = {
            "name": name,
            "uid": uid,
            "nickname": account.get("nickname") or "",
            "domain": auth.get("domain") or "",
            "token": token,
            "refreshToken": auth.get("refreshToken") if isinstance(auth.get("refreshToken"), str) else "",
            "expiresAt": auth.get("expiresAt") or 0,
            "refreshExpiresAt": auth.get("refreshExpiresAt") or 0,
            "source": str(path),
        }
        if err:
            entry["error"] = err
            unavailable.append(entry)
        else:
            usable.append(entry)
    return usable, unavailable


# ---- 多账号仓库 ----

def load_store() -> dict:
    data = read_json(STORE_FILE) if STORE_FILE.exists() else None
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("accounts"), dict):
        data = {"version": 1, "accounts": {}}
    return data


def save_store(store: dict) -> None:
    store["version"] = 1
    tmp = STORE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, STORE_FILE)


def status_row(rec: dict) -> tuple:
    """返回 (今日是否签到, 连续天数, 累计积分)；只认今天的数据，过期显示为空"""
    st = rec.get("lastStatus") or {}
    if st.get("date") != datetime.now().strftime("%Y-%m-%d"):
        return False, None, None
    return bool(st.get("checked_in")), st.get("streak_days") or 0, st.get("total_credits") or 0


def fmt_credits(value) -> str:
    """积分数字：整数不带小数，其余保留两位（余额是浮点，累计签到是整数）"""
    if value is None:
        return "—"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{v:.0f}" if abs(v - round(v)) < 0.005 else f"{v:.2f}"


def balance_cell(rec: dict) -> str:
    """余额列：剩余 / 总额；这个账号还没读到过余额时显示 —"""
    bal = rec.get("balance") or {}
    left, total = bal.get("left"), bal.get("total")
    if left is None:
        return "—"
    if not total:
        return fmt_credits(left)
    return f"{fmt_credits(left)} / {fmt_credits(total)}"


def fetch_balance(rec: dict):
    """读取账号当前的积分余额（客户端「账户用量」同款接口）。

    返回 {left, total, used, plan, is_paid, updatedAt}；失败返回 None。
    left 就是客户端里显示的「剩余积分」，total 是各积分包额度之和。"""
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {rec['token']}",
        "Content-Type": "application/json",
        "X-User-Id": rec.get("uid", ""),
        "X-Domain": rec.get("domain", ""),
        "User-Agent": CLIENT_USER_AGENT,
    }
    try:
        r = requests.post(BALANCE_URL, headers=headers, json={}, timeout=30)
        payload = r.json()
    except Exception as e:
        log(f"[{account_label(rec)} {short_uid(rec.get('uid', ''))}] 查询积分余额失败：{type(e).__name__}")
        return None

    if payload.get("code") != 0:
        log(f"[{account_label(rec)} {short_uid(rec.get('uid', ''))}] 查询积分余额失败："
            f"{payload.get('msg') or payload.get('error_msg') or '未知错误'}")
        return None

    data = payload.get("data") or {}
    packages = data.get("Packages") or []
    try:
        total = sum(float(p.get("CycleTotalCapacity") or 0) for p in packages)
        used = sum(float(p.get("CycleUsedCapacity") or 0) for p in packages)
    except (TypeError, ValueError):
        total = used = 0.0
    left = data.get("TotalCredits")
    try:
        left = float(left)
    except (TypeError, ValueError):
        left = max(total - used, 0.0)

    return {
        "left": round(left, 2),
        "total": round(total, 2),
        "used": round(used, 2),
        "plan": data.get("SubscriptionPackageName") or "",
        "is_paid": bool(data.get("IsPaidUser")),
        "updatedAt": now_ms(),
    }


def render_accounts_md(store: dict) -> None:
    """生成 accounts.md：账号 / uid / 今日是否签到 / 连续天数 / 签到累计积分 / 剩余积分 + 合计"""
    accounts = sorted(store.get("accounts", {}).values(), key=account_label)
    lines = [
        "# WorkBuddy 账号签到状态",
        "",
        f"最后更新：{datetime.now():%Y-%m-%d %H:%M}",
        "",
        "| 账号 | uid | 今日签到 | 连续签到 | 签到累计积分 | 积分余额（剩余/总额） |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    total, done, left_sum, balance_known = 0, 0, 0.0, 0
    for rec in accounts:
        checked, streak, credits = status_row(rec)
        if checked:
            done += 1
        if credits is not None:
            total += credits
        bal = rec.get("balance") or {}
        if bal.get("left") is not None:
            left_sum += float(bal["left"])
            balance_known += 1
        lines.append(
            "| {name} | `{uid}` | {checked} | {streak} | {credits} | {balance} |".format(
                name=rec.get("nickname") or short_uid(rec.get("uid", "")),
                uid=rec.get("uid", ""),
                checked="✅" if checked else "—",
                streak=f"{streak} 天" if streak else "—",
                credits=credits if credits is not None else "—",
                balance=balance_cell(rec),
            )
        )
    lines += [
        "",
        f"今日已签到 **{done}/{len(accounts)}** 个账号，签到累计 **{total}** 积分。",
        f"账号积分余额合计 **{fmt_credits(left_sum)}**"
        f"（{balance_known}/{len(accounts)} 个账号读取成功）。",
        "",
    ]
    tmp = ACCOUNTS_MD.parent / "accounts.md.tmp"
    tmp.write_text("\n".join(lines), encoding="utf-8")
    os.replace(tmp, ACCOUNTS_MD)


def merge_into_store(store: dict, entries: list) -> list:
    """把扫描到的明文登录态并入仓库，返回实际新增/更新的账号记录列表。

    同一账号只保留「过期时间更晚」的 token；客户端刷新 token 时（明文变化）
    也会跟着更新。"""
    updated, accounts = [], store["accounts"]
    for e in entries:
        uid, token = e.get("uid"), e.get("token")
        if not uid or not token:
            continue
        old = accounts.get(uid) or {}
        new_exp = e.get("expiresAt") or 0
        old_exp = old.get("expiresAt") or 0

        # 以「过期时间更晚」的那份为准；token 和 refreshToken 必须成对使用，
        # 否则可能把自动续期拿到的新凭证覆盖成文件里的旧凭证
        use_new = not old.get("token") or new_exp >= old_exp
        if use_new:
            token_v = token
            rt_v = e.get("refreshToken") or ""
            exp_v = new_exp or old_exp
            rexp_v = e.get("refreshExpiresAt") or 0
            src_v = e.get("source") or old.get("source") or ""
        else:
            token_v = old.get("token")
            rt_v = old.get("refreshToken") or ""
            exp_v = old_exp
            rexp_v = old.get("refreshExpiresAt") or 0
            src_v = old.get("source") or e.get("source") or ""

        record = {
            "uid": uid,
            "nickname": e.get("nickname") or old.get("nickname") or "",
            "token": token_v,
            "refreshToken": rt_v,
            "domain": e.get("domain") or old.get("domain") or "",
            "expiresAt": exp_v,
            "refreshExpiresAt": rexp_v,
            "source": src_v,
            "updatedAt": now_ms(),
        }
        # 文件里没有续期凭证、token 也没变时，保留仓库里已有的凭证
        if not record["refreshToken"] and old.get("token") == record["token"]:
            record["refreshToken"] = old.get("refreshToken") or ""
            record["refreshExpiresAt"] = record["refreshExpiresAt"] or old.get("refreshExpiresAt") or 0
        if old.get("refreshedAt") and old.get("token") == record["token"]:
            record["refreshedAt"] = old["refreshedAt"]
        same = all(old.get(k) == record[k] for k in
                   ("token", "refreshToken", "domain", "expiresAt", "nickname"))
        if same:
            continue
        accounts[uid] = record
        updated.append(record)
    if updated:
        store["updatedAt"] = now_ms()
    return updated


def known_accounts() -> dict:
    """本机「登录过」的账号（uid -> 昵称），用于提示哪些账号还没捕获到 token。

    只看客户端留下的账号痕迹，不含 token：
      local_storage/wb_entry_*.info  客户端账号列表
      connectors/<uid>/              每个账号一份主密钥目录
      storage/user-<uid>-personal/   每个账号的存储目录
      storage/skeleton/account-snapshot.json  当前账号昵称
    """
    known = {}

    for path in (WORKBUDDY_HOME / "local_storage").glob("wb_entry_*.info"):
        data = read_json(path)
        if not isinstance(data, list):
            continue
        for item in data:
            key = item.get("key") if isinstance(item, dict) else None
            if not isinstance(key, str):
                continue
            uid = key.split("|")[0]
            if len(uid) == 36:
                known.setdefault(uid, "")

    for parent, prefix in ((WORKBUDDY_HOME / "connectors", ""),
                           (WORKBUDDY_HOME / "storage", "user-"),
                           (WORKBUDDY_HOME / "security", "")):
        if not parent.is_dir():
            continue
        for p in parent.iterdir():
            if not p.is_dir():
                continue
            uid = p.name[len(prefix):] if prefix and p.name.startswith(prefix) else p.name
            if len(uid) == 36:
                known.setdefault(uid, "")

    snap = read_json(WORKBUDDY_HOME / "storage" / "skeleton" / "account-snapshot.json")
    if isinstance(snap, dict):
        primary = snap.get("primary") or {}
        uid = primary.get("uid") or ""
        if uid:
            known[uid] = primary.get("nickname") or known.get(uid, "")
    return known


def account_label(rec: dict) -> str:
    return rec.get("nickname") or (rec.get("source") and Path(rec["source"]).stem) or short_uid(rec.get("uid", ""))


# ---- 自动续期 ----

def refresh_account(rec: dict) -> tuple:
    """用 refreshToken 换新 token，成功后就地更新 rec（不落盘）。

    返回 (ok, err)。接口是客户端自己用的那个，只需 refreshToken + X-Domain。
    注意：服务端会轮换 refreshToken，成功后必须立即保存。"""
    rt = rec.get("refreshToken") or ""
    if not rt:
        return False, "没有 refreshToken"

    headers = {
        "X-Refresh-Token": rt,
        "X-Auth-Refresh-Source": "plugin",
        "X-Domain": rec.get("domain") or "",
        "Content-Type": "application/json",
    }
    try:
        r = requests.post(REFRESH_URL, headers=headers, json={}, timeout=30)
    except Exception as e:
        return False, f"请求异常 {type(e).__name__}"

    if r.status_code != 200:
        detail = ""
        try:
            body = r.json()
            detail = body.get("error_msg") or body.get("msg") or body.get("error") or ""
        except Exception:
            detail = " ".join((r.text or "").split())[:60]
        return False, f"HTTP {r.status_code}" + (f"：{detail}" if detail else "")

    try:
        payload = r.json()
    except ValueError:
        return False, "返回非 JSON"

    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    if not isinstance(data, dict) or not data.get("accessToken"):
        return False, "返回结构中没有 accessToken"

    now = now_ms()
    expires_at = data.get("expiresAt") or (now + int(data.get("expiresIn") or 0) * 1000)
    if data.get("refreshExpiresAt"):
        refresh_expires_at = data["refreshExpiresAt"]
    elif data.get("refreshExpiresIn"):
        refresh_expires_at = now + int(data["refreshExpiresIn"]) * 1000
    else:
        refresh_expires_at = rec.get("refreshExpiresAt") or 0

    rec["token"] = data["accessToken"]
    if data.get("refreshToken"):
        rec["refreshToken"] = data["refreshToken"]
    rec["expiresAt"] = expires_at
    rec["refreshExpiresAt"] = refresh_expires_at
    rec["refreshedAt"] = now
    rec["updatedAt"] = now
    return True, None


def ensure_fresh(store: dict, rec: dict, force: bool = False) -> bool:
    """token 快过期（或 force）时自动续期，返回是否持有可用 token。"""
    exp = rec.get("expiresAt") or 0
    if not force and exp and exp - now_ms() > REFRESH_AHEAD_MS:
        return True
    if not rec.get("refreshToken"):
        return bool(exp and exp > now_ms())

    name = f"{account_label(rec)} {short_uid(rec.get('uid', ''))}"
    ok, err = refresh_account(rec)
    if ok:
        save_store(store)   # 服务端已轮换 refreshToken，必须立即落盘
        log(f"[{name}] 已自动续期，新 token 到期 {fmt_ts(rec['expiresAt'])}")
        return True
    log(f"[{name}] 自动续期失败：{err}（先用现有 token 尝试签到）")
    return bool(exp and exp > now_ms())


# ---- 签到 ----

def api(path: str, rec: dict) -> dict:
    headers = {
        "Authorization": f"Bearer {rec['token']}",
        "X-User-Id": rec["uid"],
        "X-Domain": rec.get("domain", ""),
        "Content-Type": "application/json",
    }
    r = requests.post(f"{API_BASE}/{path}", headers=headers, json={}, timeout=30)
    try:
        return r.json()
    except ValueError:
        # 未登录/无权限时网关可能直接返回 HTML 或空响应
        snippet = " ".join((r.text or "").split())[:80]
        raise RuntimeError(f"HTTP {r.status_code}"
                           + (f"，返回非 JSON：{snippet}" if snippet else "，返回空响应"))


def status_snapshot(data: dict) -> dict:
    """把接口返回的签到状态整理成要存进 accounts.json / accounts.md 的字段"""
    return {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "checked_in": bool(data.get("today_checked_in")),
        "streak_days": int(data.get("streak_days") or 0),
        "total_credits": int(data.get("total_credits") or 0),
        "today_credit": int(data.get("today_credit") or 0),
        "updatedAt": now_ms(),
    }


def checkin_api(rec: dict) -> tuple:
    """HTTP API 签到，返回 (是否成功, 状态信息)"""
    name = f"{account_label(rec)} {short_uid(rec.get('uid', ''))}"
    expires_at = rec.get("expiresAt") or 0
    if expires_at and expires_at / 1000 < time.time():
        log(f"[{name}] accessToken 已于 {fmt_ts(expires_at)} 过期，"
            f"请在对应客户端/IDE 登录该账号以刷新登录态")
        return False, None

    # 先查签到活动状态：今日已领取就不再发领取请求
    data = {}
    try:
        status = api("checkin-activity-status", rec)
        if status.get("code") == 0:
            data = status.get("data") or {}
    except Exception as e:
        log(f"[{name}] 查询签到状态失败（继续尝试领取）：{e}")

    if data.get("today_checked_in"):
        extra = []
        if data.get("streak_days"):
            extra.append(f"连续 {data['streak_days']} 天")
        if data.get("total_credits"):
            extra.append(f"累计 {data['total_credits']} 积分")
        log(f"[{name}] (API) 今日已签到" + (f"（{'，'.join(extra)}）" if extra else ""))
        return True, status_snapshot(data)

    try:
        claim = api("daily-checkin", rec)
    except Exception as e:
        log(f"[{name}] 领取积分失败：{e}")
        return False, status_snapshot(data) if data else None

    if claim.get("code") == 0:
        credit = (claim.get("data") or {}).get("credit")
        log(f"[{name}] (API) 签到成功，获得积分：{credit if credit is not None else '?'}")
    elif claim.get("code") == 10001:  # 今天已签到，请明天再来
        log(f"[{name}] (API) 今日已签到")
    else:
        log(f"[{name}] (API) 签到失败：{claim.get('msg')}")
        return False, status_snapshot(data) if data else None

    # 领取后重新查一次，拿到最新的连续天数 / 累计积分
    try:
        fresh = api("checkin-activity-status", rec)
        if fresh.get("code") == 0:
            data = fresh.get("data") or data
    except Exception:
        pass

    info = status_snapshot(data)
    if claim.get("code") == 0 and not info["checked_in"]:
        # 查询失败时的兜底：按刚领到的积分推算
        credit = int((claim.get("data") or {}).get("credit") or 0)
        info["checked_in"] = True
        info["today_credit"] = info["today_credit"] or credit
        info["streak_days"] = info["streak_days"] + 1 if info["streak_days"] else 1
        info["total_credits"] += info["today_credit"]
    return True, info


# ---- 命令 ----

def do_capture(reason: str = "") -> tuple:
    """扫描明文登录态并入仓库，返回 (store, 新增/更新列表, 不可用列表)"""
    usable, unavailable = scan_sessions()
    store = load_store()
    updated = merge_into_store(store, usable)
    if updated:
        save_store(store)
        render_accounts_md(store)
        names = "、".join(account_label(r) for r in updated)
        log(f"[WorkBuddy] 已保存 {len(updated)} 个账号的登录态：{names}{reason}")
    elif reason:
        log(f"[WorkBuddy] 登录态无变化{reason}")
    return store, updated, unavailable


def print_overview(store: dict, unavailable: list) -> None:
    """打印仓库 + 本机登录过但无 token 的账号"""
    accounts = store.get("accounts") or {}
    known = known_accounts()

    log(f"[WorkBuddy] 已捕获账号（accounts.json，共 {len(accounts)} 个）：")
    if not accounts:
        log("  （空）")
    for rec in sorted(accounts.values(), key=lambda r: account_label(r)):
        state = "已过期" if (rec.get("expiresAt") or 0) and rec["expiresAt"] / 1000 < time.time() else "可用"
        nick = rec.get("nickname") or "未命名"
        log(f"  - {nick}  uid={short_uid(rec.get('uid'))}…  状态={state}  "
            f"token 到期={fmt_ts(rec.get('expiresAt'))}  "
            f"续期凭证到期={fmt_ts(rec.get('refreshExpiresAt'))}  "
            f"来源={Path(rec.get('source', '')).stem or '—'}")

    missing = [uid for uid in known if uid not in accounts]
    if missing:
        log(f"[WorkBuddy] 本机登录过但还没有可用 token 的账号（{len(missing)} 个）：")
        for uid in missing:
            nick = known.get(uid) or "未命名"
            log(f"  - {nick}  uid={short_uid(uid)}…")
        log("[WorkBuddy] 这些账号的登录态被新版客户端加密了，脚本无法解密。"
            "请用 CodeBuddy 命令行登录这些账号一次（终端运行 codebuddy，输入 /login 切换账号），"
            "然后运行 --capture（或提前开着 --watch），即可登记进 accounts.json。")

    for entry in unavailable:
        if entry.get("uid") and entry["uid"] in accounts:
            continue  # 同账号已有可用 token，无需提示
        name = entry.get("name") or "?"
        log(f"[WorkBuddy] 提示：[{name}] {entry.get('error')}"
            + (f"（uid={short_uid(entry['uid'])}…）" if entry.get("uid") else ""))


def watch(minutes: float) -> int:
    """监听登录态目录，自动捕获期间新登录的账号（明文登录态才会被捕获）"""
    log("=" * 50)
    log(f"[WorkBuddy] 监听登录态目录 {minutes:g} 分钟（每 {WATCH_INTERVAL}s 检查一次，Ctrl+C 结束）")
    log("=" * 50)

    store, _, _ = do_capture()
    seen = set(store["accounts"])
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        time.sleep(WATCH_INTERVAL)
        store, updated, _ = do_capture()
        for rec in updated:
            if rec["uid"] not in seen:
                seen.add(rec["uid"])
                log(f"[WorkBuddy] 捕获到新账号：{account_label(rec)}（已捕获 {len(store['accounts'])} 个）")
    log(f"[WorkBuddy] 监听结束，当前已捕获 {len(store['accounts'])} 个账号")
    return 0


def startup_delay() -> None:
    """随机延时启动：等随机一段时间后再请求，避开整点高峰（命令行加 --no-delay 可跳过）"""
    if "--no-delay" in sys.argv:
        log("[WorkBuddy] 检测到 --no-delay，跳过随机延时启动")
        return
    delay = random.uniform(*STARTUP_DELAY_RANGE)
    # 别把预算全花在等待上，否则签到本身没时间跑
    if RUN_DEADLINE:
        delay = min(delay, max(time_left() * 0.5, 60))
    eta = datetime.now() + timedelta(seconds=delay)
    log(f"[WorkBuddy] 随机延时启动 {int(delay) // 60} 分 {int(delay) % 60:02d} 秒"
        f"（{delay:.0f}s），预计 {eta:%H:%M:%S} 开始领取")
    time.sleep(delay)


def main() -> int:
    global RUN_DEADLINE
    argv = sys.argv[1:]
    # 计划任务给每个产品留的是 30 分钟槽位，这里按 25 分钟收口：
    # 超时就不再开新账号，宁可留给下午的补签任务，也别把日志和 Trae 的混在一起
    RUN_DEADLINE = time.time() + RUN_BUDGET_MINUTES * 60

    if "--list" in argv:
        store, _, unavailable = do_capture()
        print_overview(store, unavailable)
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

    capture_only = "--capture" in argv
    if not capture_only and "--refresh" not in argv:
        startup_delay()

    log("=" * 50)
    log("[WorkBuddy] 开始每日积分领取")
    log("=" * 50)

    store, _, unavailable = do_capture()
    if capture_only:
        log(f"[WorkBuddy] --capture 完成，当前已捕获 {len(store['accounts'])} 个账号")
        print_overview(store, unavailable)
        return 0

    accounts = sorted(store["accounts"].values(), key=lambda r: account_label(r))
    if not accounts:
        log("ERROR: 没有可用登录态，请先登录 WorkBuddy / CodeBuddy 后重试")
        print_overview(store, unavailable)
        return 1

    if "--refresh" in argv:
        ok = 0
        for rec in accounts:
            if ensure_fresh(store, rec, force=True):
                ok += 1
        log(f"[WorkBuddy] 续期完成：成功 {ok} / {len(accounts)} 个账号")
        return 0 if ok == len(accounts) else 1

    results = []
    for idx, rec in enumerate(accounts):
        if time_left() <= 0:
            log(f"[WorkBuddy] 已用满 {RUN_BUDGET_MINUTES} 分钟预算，"
                f"剩下 {len(accounts) - idx} 个账号留给下午的补签任务")
            break
        if idx and "--no-delay" not in argv and time_left() > 60:
            gap = random.uniform(*ACCOUNT_GAP_RANGE)
            log(f"[WorkBuddy] {gap:.1f}s 后处理下一个账号")
            time.sleep(gap)
        ensure_fresh(store, rec)
        ok, info = checkin_api(rec)
        # 签到失败时再强制续期一次（token 可能被服务端提前失效），续期成功则重试签到
        if not ok and rec.get("refreshToken"):
            log(f"[{account_label(rec)} {short_uid(rec.get('uid', ''))}] 签到失败，尝试续期登录态后重试")
            if ensure_fresh(store, rec, force=True):
                ok, info = checkin_api(rec)
        # 签到后刷新该账号的积分余额（和客户端「账户用量」读的是同一个接口）
        bal = fetch_balance(rec)
        if bal:
            rec["balance"] = bal
            log(f"[{account_label(rec)} {short_uid(rec.get('uid', ''))}] 当前积分余额 "
                f"{fmt_credits(bal['left'])} / {fmt_credits(bal['total'])}")
        # 每签完一个账号就更新 accounts.md
        if info:
            rec["lastStatus"] = info
        save_store(store)
        render_accounts_md(store)
        results.append(ok)
    log(f"[WorkBuddy] 完成：成功 {sum(results)} / {len(accounts)} 个账号"
        + ("" if len(results) == len(accounts) else "（预算用完，提前收尾）"))

    missing = [uid for uid in known_accounts() if uid not in store["accounts"]]
    if missing:
        log(f"[WorkBuddy] 另有 {len(missing)} 个本机登录过的账号没有可用 token，"
            f"运行 --list 查看详情（终端运行 codebuddy → /login 登录一次后用 --capture 登记）")
    return 0 if all(results) else 1


if __name__ == "__main__":
    code = main()
    try:
        if sys.stdin and sys.stdin.isatty() and "--watch" not in sys.argv:
            input("\n按回车键退出...")
    except Exception:
        pass
    sys.exit(code)
