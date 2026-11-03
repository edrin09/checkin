# -*- coding: utf-8 -*-
"""switch.bat 双击（无参数）时的中文产品菜单入口。

switch.bat 本体必须保持纯 ASCII（cmd 在 chcp 65001 下会按字节偏移重读 .bat，
非 ASCII 字符会导致后续命令错乱），所以产品菜单和中文提示都放在这里。

流程：显示产品菜单 → 选 WorkBuddy / Trae → 转交对应 switch_account.py 的
交互循环（内部反复「列账号 + 切号」，直接回车返回）→ 回到本菜单。
切号成功且自动启动了客户端时，那个循环会直接收工（再列账号没有意义），
所以正常情况下是「选产品 → 选账号 → 客户端开起来 → 回到本菜单」。
退出：在产品菜单直接回车即可。
"""
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent


def main() -> int:
    while True:
        print()
        print("  1) WorkBuddy")
        print("  2) Trae")
        print()
        try:
            sel = input("请选择产品 [1/2，回车退出]：").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not sel:
            return 0
        if sel in ("1", "w", "wb", "workbuddy", "codebuddy"):
            script = BASE / "workbuddy" / "switch_account.py"
        elif sel in ("2", "t", "trae"):
            script = BASE / "trae" / "switch_account.py"
        else:
            print(f'无效选择 "{sel}"：请输入 1（WorkBuddy）或 2（Trae）')
            continue
        # 转交对应脚本的交互循环（无账号参数 → 内部循环，回车返回上一层）
        subprocess.run([sys.executable, str(script)])
        # 返回后回到产品菜单，可继续切换


if __name__ == "__main__":
    sys.exit(main())
