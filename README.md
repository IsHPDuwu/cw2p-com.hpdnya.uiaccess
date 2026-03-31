# UIAccess 提权插件

为 Class Widgets 2 提升 UIAccess 令牌，使窗口可以置顶到全屏 UWP 应用和系统界面上方。

## 功能

- 自动为 Class Widgets 2 获取 UIAccess 权限
- 获取权限后窗口可以置顶到任务管理器等系统界面上方
- 支持置顶到全屏 UWP 应用上方

## 原理

Windows 8 开始引入了窗口段（Band）机制，普通窗口的段为 `ZBID_DESKTOP`，无论如何 `SetWindowPos(HWND_TOPMOST)` 都无法超过更高层段的窗口（如任务管理器的 `ZBID_SYSTEM_TOOLS`）。

具有 `UIAccess` 权限的进程可以将窗口设置到 `ZBID_UIACCESS` 段，从而置顶到几乎所有系统窗口之上。

本插件通过以下步骤获取 UIAccess：

1. 检测当前进程是否已具有 UIAccess 权限
2. 若没有，从同一 Session 的 `winlogon.exe` 获取具有 `SeTcbPrivilege` 的令牌
3. 模拟该令牌，复制自身令牌并设置 `TokenUIAccess = TRUE`
4. 使用新令牌通过 `CreateProcessAsUser` 重新启动 Class Widgets 2
5. 旧进程退出，新进程继续运行并具有 UIAccess 权限

## 使用方法

1. 安装并启用本插件
2. 以管理员身份运行 Class Widgets 2（右键 → 以管理员身份运行，或在属性中设置兼容性）
3. 启动后插件会自动提升 UIAccess 权限

> ⚠️ **注意事项：**
>
> - **必须以管理员身份运行**，否则无法获取 UIAccess
> - 提权操作可能触发安全软件拦截，建议将 Class Widgets 2 工作目录添加到安全软件白名单
> - 如果设置了开机自启，每次启动系统时可能会显示 UAC 弹窗

## 致谢

提权方法参考：
- [GrantUiAccess](https://github.com/HelloWRC/GrantUiAccess) by HelloWRC
- [uiaccess](https://github.com/killtimer0/uiaccess) by killtimer0
- 提权核心方法由 Doubx690i (Dubi906w/kriastans) 提供

## 许可证

本插件基于 MIT 许可。
