"""
UIAccess 提权核心模块

通过获取 winlogon.exe 的 System 令牌来为当前进程设置 UIAccess 权限。
原理参考: https://github.com/killtimer0/uiaccess
         https://github.com/HelloWRC/GrantUiAccess

流程:
1. 检测当前进程是否已具有 UIAccess
2. 如果没有, 从同一 Session 的 winlogon.exe 获取具有 SeTcbPrivilege 的令牌
3. 模拟该令牌, 复制自身令牌并设置 TokenUIAccess = True
4. 用新令牌 CreateProcessAsUser 重新启动自身, 旧进程退出

前提条件: 进程必须以管理员(elevated)权限运行。
"""

import ctypes
import ctypes.wintypes as wintypes
import os
import sys
from loguru import logger

# ──────────────── Windows 常量 ────────────────
ERROR_SUCCESS = 0
ERROR_NOT_FOUND = 0x00000490

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_DUPLICATE = 0x0002
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_IMPERSONATE = 0x0004

PRIVILEGE_SET_ALL_NECESSARY = 1
SE_TCB_NAME = "SeTcbPrivilege"

# Token information classes
TokenSessionId = 12
TokenUIAccess = 26

# Security enums
SecurityImpersonation = 2
SecurityAnonymous = 0
TokenImpersonation = 2
TokenPrimary = 1

# Snapshot
TH32CS_SNAPPROCESS = 0x00000002

# Startup info flags
STARTF_USESHOWWINDOW = 0x00000001

# ──────────────── 结构体定义 ────────────────
class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]

class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Control", wintypes.DWORD),
        ("Privilege", LUID_AND_ATTRIBUTES * 1),
    ]

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


# ──────────────── API 绑定 ────────────────
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Process / Snapshot
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
CreateToolhelp32Snapshot.restype = wintypes.HANDLE

Process32FirstW = kernel32.Process32FirstW
Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32FirstW.restype = wintypes.BOOL

Process32NextW = kernel32.Process32NextW
Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
Process32NextW.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetCurrentProcess = kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = wintypes.HANDLE

GetLastError = kernel32.GetLastError
GetLastError.restype = wintypes.DWORD

# Token
OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
OpenProcessToken.restype = wintypes.BOOL

GetTokenInformation = advapi32.GetTokenInformation
GetTokenInformation.argtypes = [
    wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
]
GetTokenInformation.restype = wintypes.BOOL

SetTokenInformation = advapi32.SetTokenInformation
SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
SetTokenInformation.restype = wintypes.BOOL

DuplicateTokenEx = advapi32.DuplicateTokenEx
DuplicateTokenEx.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)
]
DuplicateTokenEx.restype = wintypes.BOOL

LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
LookupPrivilegeValueW.restype = wintypes.BOOL

PrivilegeCheck = advapi32.PrivilegeCheck
PrivilegeCheck.argtypes = [wintypes.HANDLE, ctypes.POINTER(PRIVILEGE_SET), ctypes.POINTER(wintypes.BOOL)]
PrivilegeCheck.restype = wintypes.BOOL

SetThreadToken = advapi32.SetThreadToken
SetThreadToken.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.HANDLE]
SetThreadToken.restype = wintypes.BOOL

RevertToSelf = advapi32.RevertToSelf
RevertToSelf.argtypes = []
RevertToSelf.restype = wintypes.BOOL

# CreateProcessAsUser
CreateProcessAsUserW = advapi32.CreateProcessAsUserW
CreateProcessAsUserW.argtypes = [
    wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR,
    ctypes.POINTER(SECURITY_ATTRIBUTES), ctypes.POINTER(SECURITY_ATTRIBUTES),
    wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)
]
CreateProcessAsUserW.restype = wintypes.BOOL

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


# ──────────────── 核心实现 ────────────────

def _check_uiaccess() -> tuple[bool, int]:
    """
    检查当前进程是否已具有 UIAccess。

    :return: (success, uiaccess_flag)  success=False 表示查询失败
    """
    hToken = wintypes.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(hToken)):
        return False, 0

    try:
        ui_access = wintypes.DWORD(0)
        ret_len = wintypes.DWORD(0)
        if not GetTokenInformation(
            hToken, TokenUIAccess,
            ctypes.byref(ui_access), ctypes.sizeof(ui_access),
            ctypes.byref(ret_len)
        ):
            return False, 0
        return True, ui_access.value
    finally:
        CloseHandle(hToken)


def _duplicate_winlogon_token(session_id: int, desired_access: int = TOKEN_IMPERSONATE) -> tuple[int, wintypes.HANDLE]:
    """
    从同一 Session 下的 winlogon.exe 复制一个具有 SeTcbPrivilege 的令牌。

    :param session_id: 目标 Session ID
    :param desired_access: 复制令牌的期望访问权限
    :return: (error_code, hToken)
    """
    ps = PRIVILEGE_SET()
    ps.PrivilegeCount = 1
    ps.Control = PRIVILEGE_SET_ALL_NECESSARY

    if not LookupPrivilegeValueW(None, SE_TCB_NAME, ctypes.byref(ps.Privilege[0].Luid)):
        return ctypes.windll.kernel32.GetLastError(), wintypes.HANDLE()

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hSnapshot == INVALID_HANDLE_VALUE:
        return ctypes.windll.kernel32.GetLastError(), wintypes.HANDLE()

    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        found = False
        result_token = wintypes.HANDLE()
        err = ERROR_NOT_FOUND

        has_entry = Process32FirstW(hSnapshot, ctypes.byref(pe))
        while has_entry:
            if pe.szExeFile.lower() == "winlogon.exe":
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pe.th32ProcessID)
                if hProcess:
                    try:
                        hToken = wintypes.HANDLE()
                        if OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, ctypes.byref(hToken)):
                            try:
                                fTcb = wintypes.BOOL()
                                if PrivilegeCheck(hToken, ctypes.byref(ps), ctypes.byref(fTcb)) and fTcb.value:
                                    sid = wintypes.DWORD()
                                    ret_len = wintypes.DWORD()
                                    if (GetTokenInformation(hToken, TokenSessionId, ctypes.byref(sid),
                                                            ctypes.sizeof(sid), ctypes.byref(ret_len))
                                            and sid.value == session_id):
                                        found = True
                                        dup_token = wintypes.HANDLE()
                                        if DuplicateTokenEx(hToken, desired_access,
                                                            None, SecurityImpersonation,
                                                            TokenImpersonation, ctypes.byref(dup_token)):
                                            err = ERROR_SUCCESS
                                            result_token = dup_token
                                        else:
                                            err = GetLastError()
                            finally:
                                CloseHandle(hToken)
                    finally:
                        CloseHandle(hProcess)

                if found:
                    break

            has_entry = Process32NextW(hSnapshot, ctypes.byref(pe))

        return err, result_token
    finally:
        CloseHandle(hSnapshot)


def _create_uiaccess_token() -> tuple[int, wintypes.HANDLE]:
    """
    基于当前进程令牌创建一个具有 UIAccess 的主令牌。

    步骤:
    1. 获取当前进程的 SessionId
    2. 从 winlogon.exe 复制一个模拟令牌（具有 SeTcbPrivilege）
    3. 模拟该令牌后, 复制自身令牌为主令牌
    4. 对新令牌设置 TokenUIAccess = TRUE
    """
    hTokenSelf = wintypes.HANDLE()
    if not OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, ctypes.byref(hTokenSelf)):
        return GetLastError(), wintypes.HANDLE()

    try:
        # 获取 SessionId
        session_id = wintypes.DWORD()
        ret_len = wintypes.DWORD()
        if not GetTokenInformation(hTokenSelf, TokenSessionId, ctypes.byref(session_id),
                                   ctypes.sizeof(session_id), ctypes.byref(ret_len)):
            return GetLastError(), wintypes.HANDLE()

        # 从 winlogon 获取系统令牌（仅需模拟权限）
        err, hTokenSystem = _duplicate_winlogon_token(session_id.value, TOKEN_IMPERSONATE)
        if err != ERROR_SUCCESS:
            return err, wintypes.HANDLE()

        try:
            # 模拟系统令牌
            if not SetThreadToken(None, hTokenSystem):
                return GetLastError(), wintypes.HANDLE()

            try:
                # 复制自身令牌为主令牌
                desired_access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT
                hNewToken = wintypes.HANDLE()
                if not DuplicateTokenEx(hTokenSelf, desired_access, None,
                                        SecurityAnonymous, TokenPrimary, ctypes.byref(hNewToken)):
                    return GetLastError(), wintypes.HANDLE()

                # 设置 UIAccess
                ui_access = wintypes.BOOL(True)
                if not SetTokenInformation(hNewToken, TokenUIAccess,
                                           ctypes.byref(ui_access), ctypes.sizeof(ui_access)):
                    err = GetLastError()
                    CloseHandle(hNewToken)
                    return err, wintypes.HANDLE()

                return ERROR_SUCCESS, hNewToken

            finally:
                RevertToSelf()
        finally:
            CloseHandle(hTokenSystem)
    finally:
        CloseHandle(hTokenSelf)


def _build_command_line() -> str:
    """
    构建重启的命令行参数。
    与 central.py 中 restart() 使用 os.execl(sys.executable, sys.executable, *sys.argv) 类似,
    但这里需要拼成字符串给 CreateProcessAsUserW 使用。
    """
    parts = [sys.executable] + sys.argv
    # 对含空格的参数加引号
    quoted = []
    for p in parts:
        if ' ' in p or '\t' in p:
            quoted.append(f'"{p}"')
        else:
            quoted.append(p)
    return ' '.join(quoted)


def prepare_for_uiaccess() -> int:
    """
    主入口: 为当前进程准备 UIAccess。

    - 如果已有 UIAccess → 返回 ERROR_SUCCESS (0)
    - 如果没有 → 创建 UIAccess 令牌, 用它重启进程, 旧进程 ExitProcess
    - 失败 → 返回 Win32 错误码

    :return: Win32 error code (0 = success)
    """
    ok, ui_access = _check_uiaccess()
    if ok and ui_access:
        logger.info("[UIAccess] 当前进程已具有 UIAccess 权限")
        return ERROR_SUCCESS

    logger.info("[UIAccess] 当前进程不具有 UIAccess, 尝试获取...")

    err, hToken = _create_uiaccess_token()
    if err != ERROR_SUCCESS:
        logger.error(f"[UIAccess] 创建 UIAccess 令牌失败, 错误码: {err} (0x{err:08X})")
        return err

    # 用新令牌重启进程
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()

    cmd_line = _build_command_line()
    logger.info(f"[UIAccess] 使用 UIAccess 令牌重启: {cmd_line}")

    # CreateProcessAsUserW 需要可写的命令行缓冲区
    cmd_buf = ctypes.create_unicode_buffer(cmd_line)

    if CreateProcessAsUserW(
        hToken, None, cmd_buf,
        None, None, False, 0, None, None,
        ctypes.byref(si), ctypes.byref(pi)
    ):
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        CloseHandle(hToken)
        logger.info("[UIAccess] 新进程已启动, 旧进程即将退出")
        os._exit(0)  # 立即退出旧进程
    else:
        err = GetLastError()
        logger.error(f"[UIAccess] CreateProcessAsUser 失败, 错误码: {err} (0x{err:08X})")
        CloseHandle(hToken)
        return err


def has_uiaccess() -> bool:
    """检查当前进程是否具有 UIAccess 权限"""
    ok, flag = _check_uiaccess()
    return ok and bool(flag)


def is_admin() -> bool:
    """检查当前进程是否以管理员权限运行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def request_admin_elevation() -> bool:
    """
    通过 UAC 请求管理员权限并重启当前进程。

    使用 ShellExecuteW 的 "runas" 动词触发 UAC 提示。
    若用户同意，新的管理员进程将启动，当前进程退出。

    :return: 始终返回 False（成功时进程已退出，不会到 return）
    """
    import subprocess
    params = subprocess.list2cmdline(sys.argv)
    logger.info(f"[UIAccess] 请求管理员权限重启: {sys.executable} {params}")

    ret = ctypes.windll.shell32.ShellExecuteW(
        None,            # hwnd
        "runas",         # lpOperation - 触发 UAC
        sys.executable,  # lpFile
        params,          # lpParameters
        None,            # lpDirectory
        1                # nShowCmd = SW_SHOWNORMAL
    )
    # ShellExecuteW 返回值 > 32 表示成功
    if ret > 32:
        logger.info("[UIAccess] 管理员进程已启动，当前进程即将退出")
        os._exit(0)
    else:
        logger.error(f"[UIAccess] ShellExecuteW 失败，返回值: {ret}")
        return False
