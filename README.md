<div align="center">

# WorkBuddy & Trae 自动签到

每天自动领取积分、同步余额、发送汇总邮件，还能一键切换本机客户端账号。

**Windows · Python 3.9+ · 纯本地运行 · 账号数据不上传**

![Platform](https://img.shields.io/badge/platform-Windows-0078D4?logo=windows&logoColor=white)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

只做两件事：把每天重复的签到点掉，把多账号的登录态管好。脚本直接调用官方 Web 接口，
不模拟点击、不需要一直开着客户端；账号、token、日志全部留在本机。

## 功能

| 能力 | 说明 |
| --- | --- |
| 多账号签到 | WorkBuddy / Trae CN 的所有账号依次领取，单次运行即可补签 |
| 自动续期 | WorkBuddy token 到期前自动刷新，长期免登录 |
| 幂等执行 | 已签到的账号只查状态、刷新余额，不会重复领取 |
| 余额同步 | 实时读取官方只读接口，写入 `accounts.json` / `accounts.md` |
| 邮件日报 | HTML + 纯文本两版，汇总签到结果、今日积分、余额 |
| 一键切号 | 把指定账号的登录态写回客户端，切完自动启动对应客户端 |
| 无人值守 | Windows 计划任务每天两次，随机延时 + 运行预算，避免整点限流 |
| 可集成 | 切号支持 `--quiet` / `--json` / `--dry-run` 和明确的退出码 |

## 支持的产品

| 产品 | 签到 | 切号 | 添加账号 |
| --- | --- | --- | --- |
| WorkBuddy | ✅ | ✅ | 客户端登录后自动捕获 |
| Trae CN | ✅ | ✅ | 浏览器登录 / 客户端登录态 |

## 快速开始

### 1. 安装

需要 Windows 10/11、Python 3.9+，以及已安装并登录过的 WorkBuddy / Trae CN 客户端。

```powershell
pip install requests pycryptodome
git clone <仓库地址> checkin
cd checkin
```

### 2. 添加账号

**WorkBuddy**：先开启监听，再登录客户端。

```powershell
.\workbuddy\workbuddy.bat --watch 30
```

另开一个终端执行 `codebuddy`（或打开 WorkBuddy 桌面端）登录新账号；
登录后等 3 秒再切下一个，登录态会自动写入 `workbuddy\accounts.json`。

**Trae**：命令行登录，不需要打开客户端。

```powershell
.\trae\trae.bat --login
```

浏览器登录完成后自动写入 `trae\accounts.json`。登录态约 14 天有效，过期重跑一次即可。

### 3. 先手动跑一次

```powershell
.\workbuddy\workbuddy.bat --no-delay
.\trae\trae.bat --no-delay
```

### 4. 配置汇总邮件（可选）

```powershell
Copy-Item .env.example .env
notepad .env
python send_mail.py --dry-run   # 渲染到 mail_preview.html 预览
python send_mail.py --mail-only # 按当前数据发一封
```

### 5. 交给计划任务

```powershell
$root = "D:\path\to\checkin"
$pyw  = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $pyw) { $pyw = (Get-Command python.exe).Source }

function New-CheckinTask($name, $time, $script) {
    $action   = New-ScheduledTaskAction -Execute $pyw -Argument "`"$root\$script`""
    $trigger  = New-ScheduledTaskTrigger -Daily -At $time
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Force
}

New-CheckinTask 'WorkBuddy每日签到' '10:00' 'workbuddy\checkin_workbuddy.py'
New-CheckinTask 'TraeCN每日签到'    '10:30' 'trae\checkin_trae.py'
New-CheckinTask 'WorkBuddy每日补签' '15:00' 'workbuddy\checkin_workbuddy.py'
New-CheckinTask 'TraeCN每日补签'    '15:30' 'trae\checkin_trae.py'
```

两个产品错开 30 分钟，日志按时间段就能分清来源。想每天自动收邮件，
在 Trae 任务里追加第二个动作：`pythonw.exe send_mail.py --mail-only`。

## 常用命令

| 场景 | 命令 |
| --- | --- |
| WorkBuddy 签到 | `.\workbuddy\workbuddy.bat` |
| WorkBuddy 立即签到 | `.\workbuddy\workbuddy.bat --no-delay` |
| WorkBuddy 续期 token | `.\workbuddy\workbuddy.bat --refresh` |
| Trae 签到 | `.\trae\trae.bat` |
| Trae 只查状态 | `.\trae\trae.bat --status-only` |
| Trae 删除账号 | `.\trae\trae.bat --forget <账号名>` |
| 签到 + 发邮件 | `python send_mail.py` |
| 只发邮件 | `python send_mail.py --mail-only` |
| 切号菜单 | `.\main.bat` |
| 查看账号与余额 | `.\main.bat w --list` / `.\main.bat t --list` |
| 校验切号结果 | `.\main.bat w --verify` / `.\main.bat t --verify` |
| 直接切某个账号 | `.\main.bat w <账号名>` / `.\main.bat t <账号名>` |

## 切换账号

`main.bat` 是统一入口：不带参数进入中文菜单，带参数直接执行。

```powershell
.\main.bat            # 先选 WorkBuddy / Trae，再选账号
.\main.bat w --list   # 只看 WorkBuddy 账号和余额
.\main.bat t edrin    # 按账号名切换 Trae
.\main.bat w --verify # 检查客户端实际读到的账号和 token 是否有效
```

- 切换前会检查客户端是否在运行；需要时提示关闭，`--wait` 等待退出，`--force` 强行写入。
- 切成功后自动启动刚才切换的客户端；加 `--no-launch` 可只切不启动。
- 支持 `--quiet`（只报错）、`--json`（机器可读）、`--dry-run`（只演练）。
- 退出码：`0` 成功、`1` 一般错误、`2` 找不到账号、`3` token 失效、`4` 写入校验失败、`5` 客户端正在运行。

## 配置

复制 `.env.example` 为 `.env`，按需填写：

| 变量 | 说明 |
| --- | --- |
| `MAIL_HOST` | SMTP 服务器，例如 `smtp.126.com` |
| `MAIL_PORT` | 端口，SSL 通常为 `465` |
| `MAIL_SECURE` | 是否使用 SSL，`true` / `false` |
| `MAIL_USER` | 发件邮箱 |
| `MAIL_PASS` | 邮箱客户端授权码（不是登录密码） |
| `MAIL_TO` | 收件人，多个用英文逗号分隔 |

同名的系统环境变量优先于 `.env`，方便临时换收件人。

## 目录结构

```
checkin/
├─ main.bat              # 切号入口
├─ switch.py             # 产品选择菜单
├─ send_mail.py          # 签到 + 邮件汇总
├─ workbuddy/            # WorkBuddy 签到、切号、账号数据
├─ trae/                 # Trae 签到、切号、账号数据
├─ .env.example          # 邮件配置模板
└─ checkin.log           # 运行日志（自动生成）
```

`accounts.json`（token）、`profiles.json`、`accounts.md`、`.env`、`checkin.log`
都是本机生成或保存凭据的文件，已加入 `.gitignore`，不会被提交。

## 工作原理

- 从本机客户端读取登录态，直接请求签到 / 余额接口；不修改客户端安装文件。
- WorkBuddy 在 token 剩余不足 2 天时自动续期；Trae 由客户端续期或重新 `--login`。
- 启动后随机等待 1~15 分钟，账号之间间隔 5~15 秒，单次运行有 25 分钟预算。
- 补签与正常签到共用同一套逻辑，已领取的账号不会重复领取。
- 余额来自只读接口，读取失败时保留上次缓存值，并在日志/表尾注明。

## 常见问题

**日志里没有当天的记录？**
计划任务没触发。检查 `Get-ScheduledTaskInfo` 的 `LastRunTime`，以及电脑当时是否开机、是否登录。

**Trae 报 9074？**
触发限流。脚本会自动换设备号重试，仍失败就等下午补签。

**余额显示旧值？**
该账号 token 可能失效，重新登录添加账号即可。表尾会显示读取成功数量。

**支持 macOS / Linux 吗？**
目前只支持 Windows：登录态路径、计划任务和切号都依赖 Windows 客户端。

**接口变了怎么办？**
这类工具依赖客户端接口，产品更新后可能需要跟着调整。欢迎提 Issue 或 PR。

## 免责声明

本项目仅供个人学习与效率实践。请遵守 WorkBuddy / Trae 的服务条款，
不要用于账号买卖、商业代签或大规模滥用；使用风险由使用者自行承担。

## License

[MIT](LICENSE)
