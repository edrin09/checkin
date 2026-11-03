# -*- coding: utf-8 -*-
"""签到汇总邮件

默认先跑 WorkBuddy、再跑 Trae 的每日积分领取（直接调用两个子脚本，签到逻辑与计划任务完全一致），
全部跑完后再把两个产品的账号状态合并成一张表，用 SMTP 发一封汇总邮件；
--mail-only 时只发信（计划任务的第二个动作就是这么用的）。

表格列：类型 | 账号 | 签到 | 余额（只显示剩余积分）

用法：
  python send_mail.py               # 签到（各自带随机延时）→ 发汇总邮件
  python send_mail.py --no-delay    # 跳过随机延时，立即签到 → 发邮件
  python send_mail.py --mail-only   # 不签到，只按 accounts.json 现状发一封汇总
  python send_mail.py --no-mail     # 只签到，不发邮件
  python send_mail.py --dry-run     # 不发邮件，渲染到 mail_preview.html 预览
  python send_mail.py --only wb     # 只跑 WorkBuddy（Trae 用 --only trae）

邮件配置读同目录 .env（同名的系统环境变量优先），字段见 .env：
  MAIL_HOST / MAIL_PORT / MAIL_SECURE / MAIL_USER / MAIL_PASS / MAIL_TO（多个收件人用逗号分隔）
"""
import html
import json
import os
import smtplib
import ssl
import subprocess
import sys
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "checkin.log"          # 与两个签到脚本共用一份日志
LOG_TAG = "Mail"                             # 本脚本的日志前缀

ENV_FILE = BASE_DIR / ".env"
PREVIEW_FILE = BASE_DIR / "mail_preview.html"

TODAY = datetime.now().strftime("%Y-%m-%d")

# 子脚本要用的解释器：与计划任务一致（自带 requests / pycryptodome）
SCHEDULED_PYTHON = r"C:\uv\py3.14.8\Scripts\python.exe"
PYTHON = SCHEDULED_PYTHON if Path(SCHEDULED_PYTHON).exists() else sys.executable

# 单个产品的执行上限（分钟）：子脚本自带 25 分钟预算，这里只兜底防止卡死
RUN_TIMEOUT_MINUTES = 40

PRODUCTS = [
    {
        "key": "wb",
        "name": "WorkBuddy",
        "script": BASE_DIR / "workbuddy" / "checkin_workbuddy.py",
        "store": BASE_DIR / "workbuddy" / "accounts.json",
    },
    {
        "key": "trae",
        "name": "Trae",
        "script": BASE_DIR / "trae" / "checkin_trae.py",
        "store": BASE_DIR / "trae" / "accounts.json",
    },
]

# 表格里产品标签的配色（邮件客户端只认行内样式）
TYPE_STYLE = {
    "WorkBuddy": ("#1d4ed8", "#dbeafe"),
    "Trae": ("#6d28d9", "#ede9fe"),
}


# ---- 基础 ----

def log(msg: str) -> None:
    """写一行日志：终端 + 根目录 checkin.log（带 [Mail] 前缀）"""
    tag = f"[{LOG_TAG}]"
    if msg.startswith(tag):
        msg = msg[len(tag):].lstrip()
    if msg and not msg.startswith("="):
        msg = f"{tag} {msg}"
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def fmt_num(value) -> str:
    """积分数字：整数不带小数，其余保留两位"""
    if value is None:
        return "—"
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{v:.0f}" if abs(v - round(v)) < 0.005 else f"{v:.2f}"


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} 秒"
    return f"{seconds // 60} 分 {seconds % 60:02d} 秒"


# ---- 邮件配置 ----

def load_env() -> None:
    """把 .env 里的键值补进环境变量（已存在的系统环境变量优先，方便临时覆盖）"""
    if not ENV_FILE.exists():
        return
    try:
        text = ENV_FILE.read_text(encoding="utf-8")
    except Exception as e:
        log(f"读取 .env 失败：{e}")
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def cfg(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


# ---- 执行签到 ----

def run_product(product: dict, extra_args: list) -> dict:
    """跑一个产品的签到脚本，返回 {code, seconds}"""
    script = product["script"]
    if not script.exists():
        log(f"[{product['name']}] 找不到脚本：{script}")
        return {"code": "missing", "seconds": 0.0}

    cmd = [PYTHON, str(script)] + extra_args
    log(f"[{product['name']}] 开始执行（{' '.join(extra_args) or '默认参数'}）")
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(script.parent), stdin=subprocess.DEVNULL,
                              timeout=RUN_TIMEOUT_MINUTES * 60)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        code = "timeout"
        log(f"[{product['name']}] 超过 {RUN_TIMEOUT_MINUTES} 分钟仍未结束，已中断")
    except Exception as e:
        code = f"error:{type(e).__name__}"
        log(f"[{product['name']}] 启动失败：{e}")
    seconds = time.time() - started
    log(f"[{product['name']}] 执行结束：退出码 {code}，用时 {fmt_duration(seconds)}")
    return {"code": code, "seconds": seconds}


# ---- 汇总数据 ----

def collect_rows(product: dict) -> list:
    """从 accounts.json 读出该产品的账号状态，整理成统一的行"""
    store = read_json(product["store"])
    rows = []
    for rec in (store.get("accounts") or {}).values():
        st = rec.get("lastStatus") or {}
        same_day = st.get("date") == TODAY
        if product["key"] == "wb":
            name = (rec.get("nickname") or Path(rec.get("source") or "").stem
                    or (rec.get("uid") or "")[:8])
            credit = st.get("today_credit") if same_day else None
        else:
            name = rec.get("username") or rec.get("userId") or "?"
            credit = st.get("credit") if same_day else None
        rows.append({
            "type": product["name"],
            "name": name,
            "today": same_day,
            "checked": bool(st.get("checked_in")) if same_day else False,
            "credit": credit,
            "balance": rec.get("balance") or {},
        })
    rows.sort(key=lambda r: str(r["name"]).casefold())
    return rows


def summarize(rows: list) -> dict:
    total = len(rows)
    done = sum(1 for r in rows if r["checked"])
    credit_sum = sum(float(r["credit"]) for r in rows if r["credit"] is not None)
    left_sum = sum(float(r["balance"]["left"]) for r in rows
                   if r["balance"].get("left") is not None)
    balance_known = sum(1 for r in rows if r["balance"].get("left") is not None)
    return {
        "total": total, "done": done,
        "credit": credit_sum,
        "left": left_sum, "balance_known": balance_known,
    }


def balance_text(balance: dict) -> str:
    left = balance.get("left")
    return fmt_num(left) if left is not None else "—"


def check_mark(row: dict) -> str:
    if row["checked"]:
        return "✅"
    return "❌" if row["today"] else "—"


def build_subject(groups: list) -> str:
    all_rows = [r for _, rows in groups for r in rows]
    s = summarize(all_rows)
    return f"[签到汇总] {TODAY} · {s['done']}/{s['total']} 已领取"


def balance_html(balance: dict) -> str:
    """余额单元格：只显示剩余积分；还没读到过余额时显示 —（调用处 nowrap）"""
    left = balance.get("left")
    return fmt_num(left) if left is not None else "—"


def render_text(groups: list, runs: dict) -> str:
    """纯文本版（不支持 HTML 的客户端看这个）"""
    all_rows = [r for _, rows in groups for r in rows]
    lines = [
        f"每日积分领取汇总 · {TODAY}",
        "=" * 46,
        "类型 | 账号 | 签到 | 余额",
        "-" * 46,
    ]
    for row in all_rows:
        lines.append(f"{row['type']} | {row['name']} | {check_mark(row)} | "
                     f"{balance_text(row['balance'])}")
    lines.append("-" * 46)
    missing = [f"{r['type']} {r['name']}" for r in all_rows if not r["checked"]]
    if missing:
        lines += ["", f"未完成领取：{'、'.join(missing)}（登录失效或本轮没跑到，原因见 checkin.log）"]
    if runs:
        lines += ["", "本轮执行："]
        for name, info in runs.items():
            bad = str(info["code"]) != "0"
            lines.append(f"  {name} 退出码 {info['code']}，用时 {fmt_duration(info['seconds'])}"
                         + ("  ← 异常，详见 checkin.log" if bad else ""))
    return "\n".join(lines) + "\n"


# 窄屏（手机）断点：只覆盖内边距和字号，表格结构不变。
# 单列成常量是因为里面有 CSS 的 { }，塞进 f-string 会炸。
MOBILE_STYLE = """<style type="text/css">
@media only screen and (max-width: 480px) {
  table.mail-table th, table.mail-table td { padding: 3px 3px !important; }
  table.mail-table th { font-size: 11px !important; }
  table.mail-table .c-name { font-size: 12px !important; }
  table.mail-table .badge { font-size: 9px !important; padding: 0 4px !important; line-height: 13px !important; }
  table.mail-table .c-bal, table.mail-table .c-mark { font-size: 12px !important; }
}
</style>"""


def render_html(groups: list, runs: dict) -> str:
    """HTML 版邮件：手机 / 电脑都能看。

    手机端的坑与对策：
      · 表格加 36 位 uid 会把每列挤到几像素宽，数字被拆行——uid 列直接删掉
      · 表头四列：类型 / 账号 / 签到 / 余额，每行单行显示，整体更紧凑
      · 数字列一律 nowrap，宁可整列变宽也不在数字中间换行
      · 正文不放「今日已领取 x/y」这句汇总，领取情况直接看表格的签到列
    """
    all_rows = [r for _, rows in groups for r in rows]
    esc = html.escape

    cell = "padding:3px 6px;border-bottom:1px solid #eef2f7;line-height:17px"
    rows_html = []
    for idx, row in enumerate(all_rows):
        fg, bg = TYPE_STYLE.get(row["type"], ("#374151", "#f3f4f6"))
        zebra = "#ffffff" if idx % 2 == 0 else "#f8fafc"
        mark = check_mark(row)
        mark_color = "#16a34a" if row["checked"] else ("#dc2626" if row["today"] else "#9ca3af")
        rows_html.append(
            f'<tr style="background:{zebra}">'
            f'<td class="c-type" style="padding:3px 6px;border-bottom:1px solid #eef2f7;line-height:17px;white-space:nowrap">'
            f'<span class="badge" style="display:inline-block;padding:0 5px;border-radius:8px;'
            f'font-size:10px;line-height:15px;color:{fg};background:{bg}">{esc(row["type"])}</span></td>'
            f'<td class="c-name" style="{cell};font-size:13px;font-weight:600;color:#111827">{esc(str(row["name"]))}</td>'
            f'<td class="c-mark" style="{cell};text-align:center;color:{mark_color};font-size:13px">{mark}</td>'
            f'<td class="c-bal" style="{cell};text-align:right;font-size:13px;color:#111827;white-space:nowrap">'
            f'{balance_html(row["balance"])}</td>'
            f'</tr>'
        )

    note = ""
    missing = [f'{r["type"]} {r["name"]}' for r in all_rows if not r["checked"]]
    if missing:
        note += (f'<p style="margin:12px 0 0;padding:9px 11px;background:#fef2f2;'
                 f'border-left:3px solid #dc2626;color:#991b1b;font-size:12px;line-height:19px">'
                 f'未完成领取：{esc("、".join(missing))}（登录失效或本轮没跑到，原因见 checkin.log）</p>')
    if runs:
        items = ""
        for name, info in runs.items():
            bad = str(info["code"]) != "0"
            color = "#dc2626" if bad else "#8b95a5"
            items += (f'<span style="display:inline-block;margin-right:12px;color:{color}">'
                      f'{esc(name)} 退出码 <b>{esc(str(info["code"]))}</b>'
                      f'，用时 {fmt_duration(info["seconds"])}'
                      + ("　← 异常，详见 checkin.log" if bad else "")
                      + "</span>")
        bad_any = any(str(i["code"]) != "0" for i in runs.values())
        note += (f'<p style="margin:10px 0 0;font-size:12px;line-height:19px;'
                 f'color:{"#b91c1c" if bad_any else "#8b95a5"}">本轮执行：{items}</p>')

    return f"""<div style="max-width:560px;margin:0 auto;padding:2px;font-family:-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;color:#1f2937">
{MOBILE_STYLE}
<h2 style="margin:0 0 3px;font-size:18px;line-height:26px;color:#111827">每日积分领取汇总</h2>
<p style="margin:0 0 8px;font-size:12px;color:#9ca3af">{TODAY}</p>
<table class="mail-table" cellpadding="0" cellspacing="0" width="100%" style="width:100%;max-width:560px;table-layout:fixed;border-collapse:collapse;border:1px solid #e5e7eb;font-size:13px">
  <colgroup>
    <col style="width:22%" />
    <col style="width:44%" />
    <col style="width:14%" />
    <col style="width:20%" />
  </colgroup>
  <thead>
    <tr style="background:#f1f5f9">
      <th style="padding:6px 6px;text-align:left;font-size:12px;font-weight:600;color:#475569;border-bottom:1px solid #e5e7eb;white-space:nowrap">类型</th>
      <th style="padding:6px 6px;text-align:left;font-size:12px;font-weight:600;color:#475569;border-bottom:1px solid #e5e7eb">账号</th>
      <th style="padding:6px 6px;text-align:center;font-size:12px;font-weight:600;color:#475569;border-bottom:1px solid #e5e7eb;white-space:nowrap">签到</th>
      <th style="padding:6px 6px;text-align:right;font-size:12px;font-weight:600;color:#475569;border-bottom:1px solid #e5e7eb;white-space:nowrap">余额</th>
    </tr>
  </thead>
  <tbody>
{''.join(rows_html)}
  </tbody>
</table>
{note}
</div>"""


# ---- 发信 ----

def send_mail(subject: str, text: str, html_body: str) -> bool:
    host, port = cfg("MAIL_HOST"), int(cfg("MAIL_PORT", "465") or 465)
    user, password = cfg("MAIL_USER"), cfg("MAIL_PASS")
    to_list = [x.strip() for x in cfg("MAIL_TO").replace(";", ",").split(",") if x.strip()]
    secure = cfg("MAIL_SECURE", "true").lower() in ("1", "true", "yes", "on")

    if not (host and user and password and to_list):
        log("邮件配置不完整：请在 .env 里填 MAIL_HOST / MAIL_USER / MAIL_PASS / MAIL_TO")
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg("MAIL_FROM") or user
    msg["To"] = ", ".join(to_list)
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")

    try:
        if secure:
            with smtplib.SMTP_SSL(host, port, timeout=30,
                                  context=ssl.create_default_context()) as smtp:
                smtp.login(user, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(user, password)
                smtp.send_message(msg)
    except Exception as e:
        log(f"发送失败：{type(e).__name__}：{e}")
        return False
    log(f"邮件已发送 → {'、'.join(to_list)}：{subject}")
    return True


# ---- 主流程 ----

def main() -> int:
    argv = sys.argv[1:]
    dry_run = "--dry-run" in argv
    mail_only = "--mail-only" in argv
    no_mail = "--no-mail" in argv
    only = ""
    if "--only" in argv:
        i = argv.index("--only")
        if i + 1 < len(argv):
            only = argv[i + 1].strip().lower()

    load_env()
    log("=" * 50)
    log(f"开始：{'只发汇总' if mail_only else '领取积分 → 发汇总'}"
        f"（{'预览模式，不发信' if dry_run else '正常发信'}）")
    log("=" * 50)

    targets = [p for p in PRODUCTS if not only or p["key"] == only]
    if not targets:
        log(f"--only 参数无效：{only}（可选 wb / trae）")
        return 1

    runs = {}
    if not mail_only:
        # 两个产品串行跑：日志按时间段就能分清是哪个产品的（与现有计划任务的节奏一致）
        child_args = ["--no-delay"] if "--no-delay" in argv else []
        for product in targets:
            runs[product["name"]] = run_product(product, child_args)

    groups = [(p["name"], collect_rows(p)) for p in targets]
    groups = [(name, rows) for name, rows in groups if rows]
    if not groups:
        log("没有读到任何账号数据：先确认 accounts.json 里有账号（workbuddy/trae 各跑一次 --list）")
        return 1

    subject = build_subject(groups)
    text = render_text(groups, runs)
    html_body = render_html(groups, runs)

    if dry_run:
        PREVIEW_FILE.write_text(html_body, encoding="utf-8")
        log(f"预览已写入 {PREVIEW_FILE}（未发信）")
        print("\n" + text)
        return 0

    if no_mail:
        log("--no-mail：跳过发信")
        print("\n" + text)
        return 0

    ok = send_mail(subject, text, html_body)
    if not ok:
        return 1

    all_rows = [r for _, rows in groups for r in rows]
    s = summarize(all_rows)
    log(f"汇总：{s['done']}/{len(all_rows)} 个账号已领取，"
        f"今日积分 {fmt_num(s['credit'])}，余额合计 {fmt_num(s['left'])}")
    # 邮件发出去就算完成；有账号没领到用非 0 退出码提醒（计划任务里能看出来）
    return 0 if s["done"] == len(all_rows) else 1


if __name__ == "__main__":
    try:
        code = main()
    except KeyboardInterrupt:
        code = 130
    sys.exit(code)
