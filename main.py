"""
Class Widgets 2 - UIAccess 提权插件

为 Class Widgets 2 提升 UIAccess 令牌，使窗口可以置顶到全屏 UWP 应用
和系统界面（如任务管理器）上方。

原理:
  通过获取同一 Session 下 winlogon.exe 的 System 令牌来设置当前进程的
  TokenUIAccess 属性。如果当前进程尚未获得 UIAccess，插件会使用具有
  UIAccess 的令牌重新启动 Class Widgets 2。

注意事项:
  - 必须以管理员身份运行 Class Widgets 2 才能正常使用本插件
  - 本插件仅在 Windows 平台上有效
  - 提权操作可能触发安全软件拦截，建议添加白名单

参考:
  - https://github.com/HelloWRC/GrantUiAccess
  - https://github.com/killtimer0/uiaccess
"""

import sys
from loguru import logger

from ClassWidgets.SDK import CW2Plugin, PluginAPI


class Plugin(CW2Plugin):
    """UIAccess 提权插件"""

    def on_load(self):
        super().on_load()

        if sys.platform != "win32":
            logger.warning("[UIAccess] 本插件仅支持 Windows 平台，跳过")
            return

        from uiaccess import is_admin, has_uiaccess, prepare_for_uiaccess, request_admin_elevation

        # 检查管理员权限，如果不是管理员则请求 UAC 提权重启
        if not is_admin():
            logger.warning("[UIAccess] 当前未以管理员权限运行，尝试请求 UAC 提权...")
            if not request_admin_elevation():
                # 用户拒绝了 UAC 或提权失败
                logger.error("[UIAccess] UAC 提权请求失败，用户可能拒绝了提权")
            return

        # 检查是否已有 UIAccess
        if has_uiaccess():
            logger.info("[UIAccess] 当前进程已具有 UIAccess 权限 ✓")
            return

        # 尝试获取 UIAccess（这会重启进程）
        logger.info("[UIAccess] 尝试获取 UIAccess 权限...")
        err = prepare_for_uiaccess()

        # 如果执行到这里说明重启失败了（成功的话进程已经退出）
        if err != 0:
            logger.error(f"[UIAccess] 提权失败，Win32 错误码: {err} (0x{err:08X})")

    def on_unload(self):
        logger.info("[UIAccess] 插件已卸载")
