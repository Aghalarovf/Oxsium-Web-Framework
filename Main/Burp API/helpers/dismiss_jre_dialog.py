import ctypes
import logging
import os
import threading
import time
from ctypes import wintypes

logger = logging.getLogger("oxsium.burp_api")

_IS_WINDOWS = os.name == "nt"

DIALOG_TITLE_PREFIX = "burp suite"
JAVA_IMAGES = ("java.exe", "javaw.exe")
MAX_DIALOG_WIDTH = 1200
MAX_DIALOG_HEIGHT = 600

_OK_BUTTON_OFFSETS = ((56, 25), (30, 25), (80, 25), (56, 18), (56, 32))

_SW_SHOW = 5
_SW_RESTORE = 9
_SWP_NOSIZE = 0x0001
_SWP_NOMOVE = 0x0002
_SWP_SHOWWINDOW = 0x0040
_HWND_TOPMOST = -1
_HWND_NOTOPMOST = -2
_VK_RETURN = 0x0D
_VK_MENU = 0x12
_KEYEVENTF_KEYUP = 0x0002
_MOUSEEVENTF_LEFTDOWN = 0x0002
_MOUSEEVENTF_LEFTUP = 0x0004
_WM_CLOSE = 0x0010
_WM_KEYDOWN = 0x0100
_WM_KEYUP = 0x0101
_WM_MOUSEMOVE = 0x0200
_WM_LBUTTONDOWN = 0x0201
_WM_LBUTTONUP = 0x0202
_MK_LBUTTON = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_DWMWA_EXTENDED_FRAME_BOUNDS = 9
_DPI_AWARENESS_PER_MONITOR_V2 = -4

_user32 = None
_kernel32 = None
_dwmapi = None
_WNDENUMPROC = None

if _IS_WINDOWS:
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    try:
        _dwmapi = ctypes.WinDLL("dwmapi")
    except OSError:
        _dwmapi = None

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    _user32.EnumWindows.argtypes = [_WNDENUMPROC, wintypes.LPARAM]
    _user32.IsWindow.argtypes = [wintypes.HWND]
    _user32.IsWindowVisible.argtypes = [wintypes.HWND]
    _user32.IsIconic.argtypes = [wintypes.HWND]
    _user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.BringWindowToTop.argtypes = [wintypes.HWND]
    _user32.SetFocus.argtypes = [wintypes.HWND]
    _user32.SetWindowPos.argtypes = [
        wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, wintypes.UINT,
    ]
    _user32.GetForegroundWindow.restype = wintypes.HWND
    _user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
    _user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    _user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _user32.ScreenToClient.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
    _user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
    _user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]

    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.GetCurrentThreadId.restype = wintypes.DWORD

    if _dwmapi is not None:
        _dwmapi.DwmGetWindowAttribute.argtypes = [
            wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ]


def _set_thread_dpi_awareness():
    try:
        _user32.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        _user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(_DPI_AWARENESS_PER_MONITOR_V2))
    except (AttributeError, OSError):
        pass


def _window_text(hwnd, getter):
    buf = ctypes.create_unicode_buffer(512)
    getter(hwnd, buf, 512)
    return buf.value


def _image_name(pid, cache):
    if pid in cache:
        return cache[pid]
    name = ""
    handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if _kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                name = os.path.basename(buf.value).lower()
        finally:
            _kernel32.CloseHandle(handle)
    cache[pid] = name
    return name


def _is_burp_process(pid, root_pid, cache):
    if pid == root_pid:
        return True
    return _image_name(pid, cache) in JAVA_IMAGES


def _window_size(hwnd):
    rect = wintypes.RECT()
    if not _user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return 0, 0
    return rect.right - rect.left, rect.bottom - rect.top


def _list_windows(root_pid, cache):
    windows = []

    def callback(hwnd, _lparam):
        try:
            if not hwnd or not _user32.IsWindowVisible(hwnd):
                return True
            owner_pid = wintypes.DWORD(0)
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
            if not _is_burp_process(owner_pid.value, root_pid, cache):
                return True
            width, height = _window_size(hwnd)
            windows.append({
                "hwnd": hwnd,
                "pid": owner_pid.value,
                "cls": _window_text(hwnd, _user32.GetClassNameW),
                "title": _window_text(hwnd, _user32.GetWindowTextW),
                "width": width,
                "height": height,
            })
        except Exception:
            logger.exception("Failed to inspect a window while looking for the Burp JRE dialog")
        return True

    _user32.EnumWindows(_WNDENUMPROC(callback), 0)
    return windows


def _is_jre_dialog(window):
    if not window["title"].strip().lower().startswith(DIALOG_TITLE_PREFIX):
        return False
    if "dialog" not in window["cls"].lower():
        return False
    if window["width"] <= 0 or window["height"] <= 0:
        return False
    return window["width"] <= MAX_DIALOG_WIDTH and window["height"] <= MAX_DIALOG_HEIGHT


def _find_dialog(windows):
    for window in windows:
        if _is_jre_dialog(window):
            return window
    return None


def _is_gone(hwnd):
    return not _user32.IsWindow(hwnd) or not _user32.IsWindowVisible(hwnd)


def _wait_gone(hwnd, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if _is_gone(hwnd):
            return True
        time.sleep(0.1)
    return _is_gone(hwnd)


def _scale(hwnd):
    try:
        dpi = _user32.GetDpiForWindow(hwnd)
    except (AttributeError, OSError):
        dpi = 96
    return (dpi or 96) / 96.0


def _visible_frame(hwnd):
    rect = wintypes.RECT()
    if _dwmapi is not None:
        try:
            result = _dwmapi.DwmGetWindowAttribute(
                hwnd, _DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(rect), ctypes.sizeof(rect)
            )
            if result == 0 and rect.right > rect.left and rect.bottom > rect.top:
                return rect
        except OSError:
            pass
    if _user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return rect
    return None


def _ok_button_points(hwnd):
    frame = _visible_frame(hwnd)
    if frame is None:
        return []
    scale = _scale(hwnd)
    return [
        (frame.right - int(dx * scale), frame.bottom - int(dy * scale))
        for dx, dy in _OK_BUTTON_OFFSETS
    ]


def _post_click(hwnd, screen_x, screen_y):
    point = wintypes.POINT(screen_x, screen_y)
    if not _user32.ScreenToClient(hwnd, ctypes.byref(point)):
        return
    lparam = ((point.y & 0xFFFF) << 16) | (point.x & 0xFFFF)
    _user32.PostMessageW(hwnd, _WM_MOUSEMOVE, 0, lparam)
    _user32.PostMessageW(hwnd, _WM_LBUTTONDOWN, _MK_LBUTTON, lparam)
    time.sleep(0.08)
    _user32.PostMessageW(hwnd, _WM_LBUTTONUP, 0, lparam)


def _post_enter(hwnd):
    _user32.PostMessageW(hwnd, _WM_KEYDOWN, _VK_RETURN, 0x001C0001)
    time.sleep(0.05)
    _user32.PostMessageW(hwnd, _WM_KEYUP, _VK_RETURN, 0xC01C0001)


def _force_foreground(hwnd):
    foreground = _user32.GetForegroundWindow()
    this_thread = _kernel32.GetCurrentThreadId()
    foreground_thread = _user32.GetWindowThreadProcessId(foreground, None) if foreground else 0
    target_thread = _user32.GetWindowThreadProcessId(hwnd, None)

    attached = []
    for thread_id in (foreground_thread, target_thread):
        if thread_id and thread_id != this_thread and thread_id not in attached:
            if _user32.AttachThreadInput(this_thread, thread_id, True):
                attached.append(thread_id)
    try:
        _user32.ShowWindow(hwnd, _SW_RESTORE if _user32.IsIconic(hwnd) else _SW_SHOW)
        _user32.keybd_event(_VK_MENU, 0, 0, 0)
        _user32.keybd_event(_VK_MENU, 0, _KEYEVENTF_KEYUP, 0)
        flags = _SWP_NOMOVE | _SWP_NOSIZE | _SWP_SHOWWINDOW
        _user32.SetWindowPos(hwnd, _HWND_TOPMOST, 0, 0, 0, 0, flags)
        _user32.SetWindowPos(hwnd, _HWND_NOTOPMOST, 0, 0, 0, 0, flags)
        _user32.BringWindowToTop(hwnd)
        _user32.SetForegroundWindow(hwnd)
        _user32.SetFocus(hwnd)
    finally:
        for thread_id in attached:
            _user32.AttachThreadInput(this_thread, thread_id, False)
    time.sleep(0.25)
    return _user32.GetForegroundWindow() == hwnd


def _press_enter():
    _user32.keybd_event(_VK_RETURN, 0, 0, 0)
    time.sleep(0.05)
    _user32.keybd_event(_VK_RETURN, 0, _KEYEVENTF_KEYUP, 0)


def _real_click(screen_x, screen_y):
    previous = wintypes.POINT()
    has_previous = bool(_user32.GetCursorPos(ctypes.byref(previous)))
    _user32.SetCursorPos(screen_x, screen_y)
    time.sleep(0.05)
    _user32.mouse_event(_MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.05)
    _user32.mouse_event(_MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
    time.sleep(0.05)
    if has_previous:
        _user32.SetCursorPos(previous.x, previous.y)


def _step_post_click(hwnd):
    points = _ok_button_points(hwnd)
    if points:
        _post_click(hwnd, *points[0])


def _step_post_enter(hwnd):
    _post_enter(hwnd)


def _step_post_click_all(hwnd):
    for point in _ok_button_points(hwnd)[1:]:
        if _is_gone(hwnd):
            return
        _post_click(hwnd, *point)
        time.sleep(0.15)


def _step_real_enter(hwnd):
    if _force_foreground(hwnd):
        _press_enter()


def _step_real_click(hwnd):
    points = _ok_button_points(hwnd)
    if points and _force_foreground(hwnd):
        _real_click(*points[0])


def _step_real_click_all(hwnd):
    points = _ok_button_points(hwnd)
    if not points or not _force_foreground(hwnd):
        return
    for point in points[1:]:
        if _is_gone(hwnd):
            return
        _real_click(*point)
        time.sleep(0.15)


_STEPS = (
    _step_post_click,
    _step_post_enter,
    _step_real_enter,
    _step_real_click,
    _step_post_click_all,
    _step_real_click_all,
)


def _dismiss(hwnd, deadline):
    cycle = 0
    while time.monotonic() < deadline:
        for step in _STEPS:
            if _is_gone(hwnd):
                return True
            try:
                step(hwnd)
            except Exception:
                logger.exception("Dialog dismiss step %s failed", step.__name__)
            if _wait_gone(hwnd, 0.7):
                return True
        cycle += 1
        if cycle >= 2:
            _user32.PostMessageW(hwnd, _WM_CLOSE, 0, 0)
            if _wait_gone(hwnd, 1.0):
                return True
    return _is_gone(hwnd)


def _describe(windows):
    return [
        {"pid": w["pid"], "class": w["cls"], "title": w["title"], "size": f"{w['width']}x{w['height']}"}
        for w in windows
    ]


def _watch(proc, timeout):
    try:
        _set_thread_dpi_awareness()
        cache = {}
        started = time.monotonic()
        deadline = started + timeout
        diagnosed = False
        while time.monotonic() < deadline and proc.poll() is None:
            windows = _list_windows(proc.pid, cache)
            dialog = _find_dialog(windows)
            if dialog:
                logger.info(
                    "Burp JRE warning dialog detected (pid=%s, class=%s, title=%s)",
                    dialog["pid"], dialog["cls"], dialog["title"],
                )
                if _dismiss(dialog["hwnd"], deadline):
                    logger.info("Burp JRE warning dialog dismissed automatically (pid=%s)", proc.pid)
                else:
                    logger.warning(
                        "Failed to dismiss Burp JRE warning dialog (pid=%s). Windows: %s",
                        proc.pid, _describe(_list_windows(proc.pid, cache)),
                    )
                return
            if not diagnosed and time.monotonic() - started >= 25:
                diagnosed = True
                logger.info(
                    "Burp JRE dialog watcher has not seen a dialog yet. Visible Java windows: %s",
                    _describe(windows),
                )
            time.sleep(0.2)
        logger.info("Burp JRE dialog watcher finished without handling a dialog (pid=%s)", proc.pid)
    except Exception:
        logger.exception("Burp JRE dialog watcher crashed")


def start_auto_dismiss(proc, timeout=120):
    if not _IS_WINDOWS or proc is None:
        return None
    thread = threading.Thread(
        target=_watch,
        args=(proc, timeout),
        name="burp-jre-dialog-dismisser",
        daemon=True,
    )
    thread.start()
    return thread