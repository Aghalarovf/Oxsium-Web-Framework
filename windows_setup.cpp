/*
 * windows_setup.cpp — Oxsium Web  ·  Bootstrap Installer  (Windows)
 *
 * Compile (MinGW / MSYS2):
 *   g++ -std=c++17 -static -static-libgcc -static-libstdc++ windows_setup.cpp -o setup.exe
 *
 * What it does:
 *   1. Detects / prompts for Python 3
 *   2. Creates virtual environment  →  <project_root>\oxsium-web\
 *   3. Installs packages from       →  Main\Configurations\requirements.txt
 *   4. Writes start.py              →  <project_root>\start.py
 */

#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fs = std::filesystem;

/* ══════════════════════════════════════════════════════════════════════════
   ANSI color helpers
   ══════════════════════════════════════════════════════════════════════════ */
namespace ansi {

static bool enabled = false;

static void init() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    if (GetConsoleMode(h, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        enabled = SetConsoleMode(h, mode);
    }
}

static inline std::string c(const char* code) {
    return enabled ? std::string("\033[") + code + "m" : "";
}

static std::string RST()      { return c("0");    }
static std::string BOLD()     { return c("1");    }
static std::string DIM()      { return c("2");    }
static std::string RED()      { return c("31");   }
static std::string YELLOW()   { return c("33");   }
static std::string CYAN()     { return c("36");   }
static std::string WHITE()    { return c("97");   }
static std::string OK_TAG()   { return c("1;32"); }
static std::string ERR_TAG()  { return c("1;31"); }
static std::string WARN_TAG() { return c("1;33"); }
static std::string INFO_TAG() { return c("1;36"); }
static std::string HDR()      { return c("1;34"); }
static std::string PATH_CLR() { return c("33");   }

} // namespace ansi

/* ── print helpers ────────────────────────────────────────────────────── */

static void ok(const std::string& msg) {
    std::cout << "  " << ansi::OK_TAG()   << "[ OK ]" << ansi::RST() << "  " << msg << "\n";
}
static void err(const std::string& msg) {
    std::cout << "  " << ansi::ERR_TAG()  << "[FAIL]" << ansi::RST() << "  "
              << ansi::RED() << msg << ansi::RST() << "\n";
}
static void warn(const std::string& msg) {
    std::cout << "  " << ansi::WARN_TAG() << "[WARN]" << ansi::RST() << "  "
              << ansi::YELLOW() << msg << ansi::RST() << "\n";
}
static void info(const std::string& msg) {
    std::cout << "  " << ansi::INFO_TAG() << "[INFO]" << ansi::RST() << "  " << msg << "\n";
}
static void bullet(const std::string& msg) {
    std::cout << "         " << ansi::DIM() << ">>" << ansi::RST() << "  " << msg << "\n";
}

static void step_header(int n, const std::string& title) {
    std::cout << "\n"
              << ansi::HDR()
              << "  +-- Step " << n << " ------------------------------------------+\n"
              << "  |  " << ansi::WHITE() << title << ansi::HDR() << "\n"
              << "  +--------------------------------------------------+"
              << ansi::RST() << "\n\n";
}

static void print_banner() {
    std::cout
        << "\n"
        << ansi::HDR()
        << "  +==================================================+\n"
        << "  |      " << ansi::WHITE() << "Oxsium Web  -  Setup Installer (Windows)"
        << ansi::HDR()  << "     |\n"
        << "  +==================================================+"
        << ansi::RST()  << "\n\n";
}

static void print_success(const fs::path& root) {
    std::cout
        << "\n"
        << ansi::OK_TAG()
        << "  +==================================================+\n"
        << "  |       " << ansi::WHITE() << "Installation completed successfully! "
        << ansi::OK_TAG() << "       |\n"
        << "  +==================================================+"
        << ansi::RST() << "\n\n";

    std::cout << ansi::BOLD() << "  Quick-start:" << ansi::RST() << "\n\n";
    std::cout << "    " << ansi::CYAN() << "python start.py"
              << ansi::RST() << ansi::DIM() << "   =>  launch Oxsium Service Manager\n"
              << ansi::RST();
    std::cout << "\n"
              << ansi::DIM() << "  Virtual env : "
              << ansi::PATH_CLR() << (root / "oxsium-web").string()
              << ansi::RST() << "\n\n";
}

/* ══════════════════════════════════════════════════════════════════════════
   Core helpers
   ══════════════════════════════════════════════════════════════════════════ */

static std::string quote(const fs::path& p) { return '"' + p.string() + '"'; }

static int run(const std::string& cmd) {
    return std::system(cmd.c_str());
}

static bool command_ok(const std::string& cmd) {
    return run(cmd + " >nul 2>&1") == 0;
}

/* ── run_direct ───────────────────────────────────────────────────────────
   Launches exe with args directly via CreateProcess — no cmd.exe in between.
   This avoids "filename/directory/volume label syntax is incorrect" errors
   when python.exe lives in a path with spaces (e.g. C:\Program Files\...).
   ──────────────────────────────────────────────────────────────────────── */
static int run_direct(const fs::path& exe, const std::string& args) {
    std::string cmdline = '"' + exe.string() + '"';
    if (!args.empty()) { cmdline += ' '; cmdline += args; }

    STARTUPINFOW        si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    std::wstring wcmd(cmdline.begin(), cmdline.end());

    BOOL launched = CreateProcessW(
        exe.wstring().c_str(),
        wcmd.data(),
        nullptr, nullptr,
        FALSE, 0,
        nullptr, nullptr,
        &si, &pi
    );

    if (!launched) return -1;

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
}

/* ── project root ─────────────────────────────────────────────────────── */

static fs::path locate_root(const fs::path& start) {
    fs::path cur = start;
    while (!cur.empty()) {
        if (fs::exists(cur / "Main" / "Configurations" / "requirements.txt"))
            return cur;
        fs::path parent = cur.parent_path();
        if (parent == cur) break;
        cur = parent;
    }
    return start;
}

/* ── Python detection ─────────────────────────────────────────────────── */

static bool python_exists()      { return command_ok("python --version"); }
static bool py_launcher_exists() { return command_ok("py -3 --version");  }

static fs::path scan_dir(const char* root_dir) {
    if (!root_dir) return {};
    fs::path base(root_dir);
    if (!fs::exists(base)) return {};
    for (const auto& e : fs::directory_iterator(base)) {
        if (!e.is_directory()) continue;
        fs::path direct = e.path() / "python.exe";
        if (fs::exists(direct)) return direct;
        if (e.path().filename().string().find("Python") != std::string::npos)
            for (const auto& sub : fs::recursive_directory_iterator(e.path()))
                if (sub.is_regular_file() && sub.path().filename() == "python.exe")
                    return sub.path();
    }
    return {};
}

static fs::path find_python_exe() {
    // 1. LOCALAPPDATA\Programs\Python
    if (const char* loc = std::getenv("LOCALAPPDATA")) {
        fs::path base = fs::path(loc) / "Programs" / "Python";
        if (fs::exists(base))
            for (const auto& e : fs::directory_iterator(base)) {
                fs::path c = e.path() / "python.exe";
                if (fs::exists(c)) return c;
            }
    }
    // 2. Program Files
    fs::path found = scan_dir(std::getenv("ProgramFiles"));
    if (!found.empty()) return found;
    found = scan_dir(std::getenv("ProgramFiles(x86)"));
    if (!found.empty()) return found;
    // 3. PATH fallback
    if (python_exists())      return fs::path("python");
    if (py_launcher_exists()) return fs::path("py -3");
    return {};
}

static bool ensure_python() {
    if (python_exists() || py_launcher_exists()) {
        ok("Python detected on this system.");
        return true;
    }

    warn("Python was not found on this system.");
    std::cout << "\n  " << ansi::BOLD()
              << "Please install Python 3 from https://www.python.org/downloads/\n"
              << ansi::RST();
    bullet("Make sure to check  " + ansi::CYAN() + "Add Python to PATH" + ansi::RST()
           + "  during installation.");
    bullet("Then close this window and re-run setup.exe.");
    std::cout << "\n";
    return false;
}

/* ── Virtual environment ──────────────────────────────────────────────── */

static fs::path venv_python(const fs::path& root) {
    return root / "oxsium-web" / "Scripts" / "python.exe";
}

static void diagnose_venv_failure(const fs::path& interp_path,
                                  const fs::path& venv_dir,
                                  int             exit_code)
{
    std::cout << "\n"
              << ansi::ERR_TAG()
              << "  +-- Diagnostic Report ---------------------------------------+"
              << ansi::RST() << "\n\n";

    // Interpreter reachable?
    bool interp_ok = (interp_path == fs::path("python") || interp_path == fs::path("py -3"))
                     ? command_ok(interp_path.string() + " --version")
                     : fs::exists(interp_path);

    if (!interp_ok)
        err("Interpreter not found: " + interp_path.string());
    else
        ok("Interpreter reachable: " + interp_path.string());

    // Path safety (Windows-specific)
    {
        const std::string p = venv_dir.string();
        bool trailing_bs    = (!p.empty() && p.back() == '\\');
        bool bad_chars      = (p.find('(') != std::string::npos ||
                               p.find(')') != std::string::npos ||
                               p.find('!') != std::string::npos ||
                               p.find('^') != std::string::npos ||
                               p.find('&') != std::string::npos ||
                               p.find('%') != std::string::npos);
        bool embedded_quote = (p.find('"') != std::string::npos);

        if (trailing_bs || bad_chars || embedded_quote) {
            err("Destination path contains characters that break cmd.exe quoting.");
            if (trailing_bs)    bullet("Trailing backslash before closing quote.");
            if (bad_chars)      bullet("Shell-special character ( ) ! ^ & % in path.");
            if (embedded_quote) bullet("Embedded double-quote in path name.");
            bullet("Move the project to a path without these characters.");
        } else {
            ok("Destination path looks safe.");
        }
        if (p.find(' ') != std::string::npos)
            warn("Path contains spaces — this can cause issues with some tools.");
    }

    // Broken leftover venv
    if (fs::exists(venv_dir) && !fs::exists(venv_dir / "pyvenv.cfg")) {
        warn("Directory exists but has no pyvenv.cfg — leftover from failed attempt.");
        bullet("Delete and re-run:  " + ansi::CYAN() +
               "rmdir /s /q \"" + venv_dir.string() + "\"" + ansi::RST());
    }

    // Disk space
    {
        ULARGE_INTEGER free_bytes{};
        std::wstring wpath(venv_dir.wstring());
        if (GetDiskFreeSpaceExW(wpath.c_str(), &free_bytes, nullptr, nullptr)) {
            const unsigned long long free_mb = free_bytes.QuadPart / (1024ULL * 1024ULL);
            if (free_mb < 150ULL)
                err("Low disk space: " + std::to_string(free_mb) + " MB free (need ≥150 MB).");
            else
                ok("Disk space OK: " + std::to_string(free_mb) + " MB free.");
        }
    }

    // ensurepip
    {
        std::string chk = (interp_path == fs::path("python") || interp_path == fs::path("py -3"))
                          ? interp_path.string()
                          : quote(interp_path);
        if (!command_ok(chk + " -c \"import ensurepip\"")) {
            err("The ensurepip module is missing.");
            bullet("Install the full Python 3 from https://www.python.org/downloads/");
        } else {
            ok("ensurepip module: present.");
        }
    }

    // Exit code hints
    warn("venv exit code: " + std::to_string(exit_code) + ".");
    if (exit_code == 1)
        bullet("General Python error — see traceback above.");
    else if (exit_code == 2)
        bullet("Bad command-line arguments.");
    else if (exit_code == 0xC0000135 || exit_code == -1073741515)
        bullet("DLL not found — Python install may be incomplete or corrupted.");
    else if (exit_code == 0xC0000005 || exit_code == -1073741819)
        bullet("Access violation — possible antivirus interference.");
    else
        bullet("Run manually to see full error: " + ansi::CYAN() +
               quote(interp_path) + " -m venv " + quote(venv_dir) + ansi::RST());

    std::cout << "\n"
              << ansi::ERR_TAG()
              << "  +------------------------------------------------------------+"
              << ansi::RST() << "\n\n";
}

static bool create_virtual_environment(const fs::path& root) {
    if (fs::exists(venv_python(root))) {
        ok("Virtual environment 'oxsium-web' already exists.");
        bullet(ansi::PATH_CLR() + (root / "oxsium-web").string() + ansi::RST());
        return true;
    }

    fs::path interp_path = find_python_exe();
    std::string interp;

    if (!interp_path.empty()
        && interp_path != fs::path("python")
        && interp_path != fs::path("py -3")) {
        interp = quote(interp_path);        // full path
    } else if (!interp_path.empty()) {
        interp = interp_path.string();      // "python" or "py -3"
    } else if (py_launcher_exists()) {
        interp = "py -3";
        interp_path = fs::path("py -3");
    } else if (python_exists()) {
        interp = "python";
        interp_path = fs::path("python");
    } else {
        err("No Python interpreter found — cannot create virtual environment.");
        return false;
    }

    const fs::path venv_dir = root / "oxsium-web";
    info("Creating virtual environment " + ansi::CYAN() + "oxsium-web" + ansi::RST() + " ...");

    int rc;
    if (interp_path != fs::path("python") && interp_path != fs::path("py -3")) {
        // Use CreateProcess to avoid cmd.exe quoting issues with paths containing spaces
        bullet(ansi::DIM() + interp_path.string() + " -m venv " + venv_dir.string() + ansi::RST());
        rc = run_direct(interp_path, "-m venv \"" + venv_dir.string() + "\"");
    } else {
        const std::string cmd = interp + " -m venv \"" + venv_dir.string() + "\"";
        bullet(ansi::DIM() + cmd + ansi::RST());
        rc = run(cmd);
    }

    if (rc != 0) {
        err("Failed to create virtual environment.");
        diagnose_venv_failure(interp_path, venv_dir, rc);
        return false;
    }

    ok("Virtual environment 'oxsium-web' created.");
    bullet(ansi::PATH_CLR() + venv_dir.string() + ansi::RST());
    return true;
}

/* ── pip / requirements ───────────────────────────────────────────────── */

static bool install_requirements(const fs::path& root) {
    fs::path req = root / "Main" / "Configurations" / "requirements.txt";
    if (!fs::exists(req)) {
        err("requirements.txt not found: " + req.string());
        return false;
    }

    fs::path interp_path = venv_python(root);
    if (!fs::exists(interp_path)) {
        interp_path = find_python_exe();
        if (interp_path.empty()) {
            err("No usable Python interpreter found for pip.");
            return false;
        }
    }

    auto pip_run = [&](const std::string& args) -> int {
        return run_direct(interp_path, args);
    };

    info("Upgrading pip, setuptools and wheel ...");
    std::cout << "\n";
    if (pip_run("-m pip install --upgrade pip setuptools wheel") != 0) {
        std::cout << "\n";
        err("Failed to upgrade pip.");
        return false;
    }

    std::cout << "\n";
    info("Installing packages from requirements.txt ...");
    bullet(ansi::PATH_CLR() + req.string() + ansi::RST());
    std::cout << "\n";

    if (pip_run("-m pip install -r \"" + req.string() + "\"") != 0) {
        std::cout << "\n";
        err("Failed to install requirements.");
        return false;
    }

    std::cout << "\n";
    ok("All packages installed successfully.");
    return true;
}

/* ── start.py writer ──────────────────────────────────────────────────── */

static bool write_file(const fs::path& path, const std::string& content) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f << content;
    return static_cast<bool>(f);
}

// Embedded start.py template — used as fallback if start.py is not found
// alongside the installer. Venv name is oxsium-web.
static std::string start_py_content() {
    return R"===("""
start.py  —  Oxsium Service Manager
"""
from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore    import Qt, QTimer, pyqtSignal
from PyQt6.QtGui     import QColor, QPainter, QLinearGradient
from PyQt6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QMainWindow,
    QSplitter, QStackedWidget, QVBoxLayout, QWidget, QFrame,
)

PANEL_DIR = Path(__file__).resolve().parent / "Control-Panel"
if str(PANEL_DIR) not in sys.path:
    sys.path.insert(0, str(PANEL_DIR))

from config         import C, DEFAULT_PORTS, FILES, QSS, SERVICE_DEFS, SIDEBAR_ENTRIES
from env_utils      import build_env
from service_runner import ServiceRunner
from web_controller import WebController
from primitives     import Btn, Field, Log, StatusLight, hline, make_chip, make_label, make_badge
from sidebar        import Sidebar


# ══════════════════════════════════════════════════════════════════════════════
# GradientHeader — top title bar (with gold gradient line)
# ══════════════════════════════════════════════════════════════════════════════
class GradientHeader(QWidget):
    def __init__(self, ctrl, parent=None):
        super().__init__(parent)
        self._ctrl = ctrl
        self.setFixedHeight(58)

        hl = QHBoxLayout(self)
        hl.setContentsMargins(20, 0, 20, 0)
        hl.setSpacing(12)

        self._light = StatusLight(10)
        hl.addWidget(self._light)

        # Service name
        name = QLabel(ctrl.name)
        name.setStyleSheet(f"""
            color: {C.T0};
            font-size: 15px;
            font-weight: 700;
            letter-spacing: 0.5px;
        """)
        hl.addWidget(name)

        # Tag chip
        tag = make_chip(ctrl.tag, ctrl.tag_col)
        hl.addWidget(tag)

        # Hint
        hint = QLabel(ctrl.hint)
        hint.setStyleSheet(f"color: {C.T2}; font-size: 10px; letter-spacing: 0.3px;")
        hl.addWidget(hint)

        hl.addStretch()

        # Status badge (right side)
        self._status_lbl = QLabel("OFFLINE")
        self._status_lbl.setStyleSheet(f"""
            color: {C.T3};
            font-size: 9px;
            font-weight: 800;
            letter-spacing: 1.5px;
        """)
        hl.addWidget(self._status_lbl)

    def paintEvent(self, e):
        super().paintEvent(e)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # background
        p.fillRect(self.rect(), QColor(C.SURF1))

        # bottom gold line — gradient
        g = QLinearGradient(0, self.height() - 1, self.width(), self.height() - 1)
        g.setColorAt(0.0, QColor(C.G_DIM))
        g.setColorAt(0.3, QColor(C.G2))
        g.setColorAt(0.7, QColor(C.G3))
        g.setColorAt(1.0, QColor(C.G_DIM))
        p.fillRect(0, self.height() - 1, self.width(), 1, g)

    def set_status(self, s: int) -> None:
        labels = {0: ("OFFLINE", C.T3), 1: ("ONLINE", C.GREEN),
                  2: ("ERROR",   C.RED), 3: ("STARTING", C.AMBER)}
        txt, col = labels.get(s, ("OFFLINE", C.T3))
        self._status_lbl.setText(txt)
        self._status_lbl.setStyleSheet(f"""
            color: {col};
            font-size: 9px;
            font-weight: 800;
            letter-spacing: 1.5px;
        """)
        self._light.setState(s)


# ══════════════════════════════════════════════════════════════════════════════
# ControlBar — host/port + buttons
# ══════════════════════════════════════════════════════════════════════════════
class ControlBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(52)
        self.setStyleSheet(f"background: {C.SURF0};")

        hl = QHBoxLayout(self)
        hl.setContentsMargins(20, 0, 20, 0)
        hl.setSpacing(10)

        # Host
        host_lbl = QLabel("HOST")
        host_lbl.setStyleSheet(f"""
            color: {C.T2}; font-size: 9px;
            font-weight: 700; letter-spacing: 1px;
        """)
        self.host = Field("127.0.0.1", w=120)

        # Port
        port_lbl = QLabel("PORT")
        port_lbl.setStyleSheet(f"""
            color: {C.T2}; font-size: 9px;
            font-weight: 700; letter-spacing: 1px;
        """)
        self.port_field = Field("", w=80)

        hl.addWidget(host_lbl)
        hl.addWidget(self.host)
        hl.addSpacing(8)
        hl.addWidget(port_lbl)
        hl.addWidget(self.port_field)
        hl.addSpacing(16)

        self.btn_start = Btn("▶  START", "gold2",  h=30)
        self.btn_stop  = Btn("■  STOP",  "danger", h=30)
        hl.addWidget(self.btn_start)
        hl.addWidget(self.btn_stop)
        hl.addStretch()

        # File path
        self.path_lbl = QLabel("")
        self.path_lbl.setStyleSheet(f"""
            color: {C.TPATH}; font-size: 9px;
            font-family: 'Cascadia Code','Consolas',monospace;
        """)
        hl.addWidget(self.path_lbl)

    def paintEvent(self, e):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(C.SURF0))
        p.fillRect(0, self.height() - 1, self.width(), 1, QColor(C.BDR0))


# ══════════════════════════════════════════════════════════════════════════════
# ServiceController
# ══════════════════════════════════════════════════════════════════════════════
class ServiceController:
    def __init__(self, key, name, hint, fpath: Path, port_def, tag, tag_col):
        self.key = key; self.name = name; self.hint = hint
        self.fpath = fpath; self.port_def = port_def
        self.tag = tag; self.tag_col = tag_col
        self._runner: ServiceRunner | None = None
        self._up = False
        self.on_state = None; self.on_log = None

    @property
    def running(self): return self._up

    def start(self, host, port, glog):
        if self._up: return
        if not self.fpath.exists():
            self._e_log("✗", f"File not found: {self.fpath}", C.RED)
            glog.err(f"[{self.key.upper()}] File not found.")
            self._e_state(2); return

        from config import PYTHON
        env = build_env({"PORT": str(port), "HOST": host})
        self._runner = ServiceRunner(
            [str(PYTHON), str(self.fpath), "--host", host, "--port", str(port)],
            self.fpath.parent, env)
        self._runner.started.connect(self._on_started)
        self._runner.failed.connect(self._on_failed)
        self._runner.log_line.connect(self._on_line)
        self._runner.finished_clean.connect(self._on_finished)
        self._e_state(3); self._runner.start()

    def stop(self, glog):
        if self._runner: self._runner.stop(); self._runner = None
        self._up = False; self._e_state(0)
        self._e_log("▲", "Stopped.", C.AMBER)
        glog.warn(f"[{self.key.upper()}] Stopped.")

    def kill_nowait(self):
        if self._runner: self._runner.stop(); self._runner = None
        self._up = False

    def _on_started(self, pid):
        self._up = True; self._e_state(1)
        self._e_log("✓", f"Started  ·  PID {pid}  ·  :{self.port_def}", C.GREEN)
    def _on_failed(self, msg):
        self._up = False; self._e_state(2)
        self._e_log("✗", f"Error: {msg}", C.RED)
    def _on_line(self, line): self._e_log("·", line, C.TCO)
    def _on_finished(self):
        self._up = False; self._e_state(0)
        self._e_log("▲", "Process exited.", C.AMBER)
    def _e_state(self, s):
        if self.on_state: self.on_state(s)
    def _e_log(self, icon, msg, col):
        if self.on_log: self.on_log(icon, msg, col)


# ══════════════════════════════════════════════════════════════════════════════
# ServicePanel
# ══════════════════════════════════════════════════════════════════════════════
class ServicePanel(QWidget):
    request_start = pyqtSignal(str, int)
    request_stop  = pyqtSignal()

    def __init__(self, ctrl, parent=None):
        super().__init__(parent)
        self._ctrl = ctrl
        self._build()
        self._apply_stopped()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        self._hdr = GradientHeader(self._ctrl)
        root.addWidget(self._hdr)

        self._cbar = ControlBar()
        self._cbar.port_field.setText(str(self._ctrl.port_def))
        self._cbar.path_lbl.setText(str(self._ctrl.fpath))
        self._cbar.path_lbl.setToolTip(str(self._ctrl.fpath))
        self._cbar.btn_start.clicked.connect(self._on_start)
        self._cbar.btn_stop.clicked.connect(self.request_stop)
        root.addWidget(self._cbar)
        root.addWidget(hline(C.BDR0))

        self._log = Log()
        root.addWidget(self._log, stretch=1)

    def _apply_stopped(self):
        self._cbar.btn_start.setEnabled(True)
        self._cbar.btn_stop.setEnabled(False)
    def _apply_running(self):
        self._cbar.btn_start.setEnabled(False)
        self._cbar.btn_stop.setEnabled(True)
    def _apply_pending(self):
        self._cbar.btn_start.setEnabled(False)
        self._cbar.btn_stop.setEnabled(False)
    def _apply_error(self):
        self._cbar.btn_start.setEnabled(True)
        self._cbar.btn_stop.setEnabled(False)

    def apply_state(self, s):
        {0: self._apply_stopped, 1: self._apply_running,
         2: self._apply_error,   3: self._apply_pending}.get(s, self._apply_stopped)()
        self._hdr.set_status(s)

    def append_log(self, icon, msg, col):
        self._log._append(icon, msg, col)

    def _on_start(self):
        try: port = int(self._cbar.port_field.text())
        except ValueError: self._log.err("Invalid port!"); return
        self.request_start.emit(self._cbar.host.text().strip(), port)


# ══════════════════════════════════════════════════════════════════════════════
# WebPanel
# ══════════════════════════════════════════════════════════════════════════════
class WebPanel(QWidget):
    request_start = pyqtSignal(str, int)
    request_stop  = pyqtSignal()

    def __init__(self, ctrl: WebController, parent=None):
        super().__init__(parent)
        self._ctrl = ctrl
        self._build()
        self._apply_stopped()

    def _build(self):
        root = QVBoxLayout(self); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        self._hdr = GradientHeader(self._ctrl)
        root.addWidget(self._hdr)

        # Control bar (simplified for web)
        cbar = QWidget(); cbar.setFixedHeight(52)
        cbar.setStyleSheet(f"background: {C.SURF0};")
        cl = QHBoxLayout(cbar); cl.setContentsMargins(20,0,20,0); cl.setSpacing(10)

        port_lbl = QLabel("PORT")
        port_lbl.setStyleSheet(f"color:{C.T2};font-size:9px;font-weight:700;letter-spacing:1px;")
        self._port = Field(str(self._ctrl.port_def), w=80)

        self._btn_start = Btn("▶  START",   "gold2",  h=30)
        self._btn_stop  = Btn("■  STOP",    "danger", h=30)
        self._btn_open  = Btn("↗  BROWSER", "ghost",  h=30)

        self._btn_start.clicked.connect(self._on_start)
        self._btn_stop.clicked.connect(self.request_stop)
        self._btn_open.clicked.connect(self._ctrl.open_file)

        cl.addWidget(port_lbl); cl.addWidget(self._port)
        cl.addSpacing(16)
        cl.addWidget(self._btn_start); cl.addWidget(self._btn_stop)
        cl.addWidget(self._btn_open); cl.addStretch()

        path_lbl = QLabel(str(self._ctrl.fpath))
        path_lbl.setStyleSheet(f"color:{C.TPATH};font-size:9px;font-family:'Cascadia Code','Consolas',monospace;")
        path_lbl.setToolTip(str(self._ctrl.fpath))
        cl.addWidget(path_lbl)

        root.addWidget(cbar)
        root.addWidget(hline(C.BDR0))

        self._log = Log()
        root.addWidget(self._log, stretch=1)

    def _apply_stopped(self):
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._btn_open.setEnabled(False)
    def _apply_running(self):
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._btn_open.setEnabled(True)
    def _apply_error(self):
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._btn_open.setEnabled(False)

    def apply_state(self, s):
        {0: self._apply_stopped, 1: self._apply_running,
         2: self._apply_error}.get(s, self._apply_stopped)()
        self._hdr.set_status(s)

    def append_log(self, icon, msg, col): self._log._append(icon, msg, col)

    def _on_start(self):
        try: port = int(self._port.text())
        except ValueError: self._log.err("Invalid port!"); return
        self.request_start.emit("127.0.0.1", port)


# ══════════════════════════════════════════════════════════════════════════════
# ServiceManager
# ══════════════════════════════════════════════════════════════════════════════
class ServiceManager:
    def __init__(self, glog):
        self._glog = glog
        self.controllers = []; self.panels = []

    def register_service(self, ctrl, panel):
        ctrl.on_state = panel.apply_state; ctrl.on_log = panel.append_log
        panel.request_start.connect(lambda h, p, c=ctrl: c.start(h, p, self._glog))
        panel.request_stop.connect(lambda c=ctrl: c.stop(self._glog))
        self.controllers.append(ctrl); self.panels.append(panel)

    def register_web(self, ctrl, panel):
        ctrl.on_state = panel.apply_state; ctrl.on_log = panel.append_log
        panel.request_start.connect(lambda h, p, c=ctrl: c.start(h, p, self._glog))
        panel.request_stop.connect(lambda c=ctrl: c.stop(self._glog))
        self.controllers.append(ctrl); self.panels.append(panel)

    def start_all(self):
        for c, panel in zip(self.controllers, self.panels):
            if c.running: continue
            if isinstance(panel, ServicePanel):
                try: port = int(panel._cbar.port_field.text())
                except: port = c.port_def
                c.start(panel._cbar.host.text().strip(), port, self._glog)
            elif isinstance(panel, WebPanel):
                try: port = int(panel._port.text())
                except: port = c.port_def
                c.start("127.0.0.1", port, self._glog)

    def stop_all(self):
        for c in self.controllers:
            if c.running: c.stop(self._glog)

    def kill_all_nowait(self):
        for c in self.controllers: c.kill_nowait()


# ══════════════════════════════════════════════════════════════════════════════
# GlobalLogBar — bottom log panel header
# ══════════════════════════════════════════════════════════════════════════════
class GlobalLogBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(28)
        hl = QHBoxLayout(self)
        hl.setContentsMargins(18, 0, 18, 0)

        lbl = QLabel("GLOBAL LOG")
        lbl.setStyleSheet(f"""
            color: {C.T2}; font-size: 9px;
            font-weight: 700; letter-spacing: 1.8px;
        """)
        hl.addWidget(lbl)
        hl.addStretch()

        dot = QLabel("●")
        dot.setStyleSheet(f"color: {C.G2}; font-size: 8px;")
        hl.addWidget(dot)

    def paintEvent(self, e):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(C.SURF1))
        p.fillRect(0, 0, self.width(), 1, QColor(C.BDR1))


# ══════════════════════════════════════════════════════════════════════════════
# MainWindow
# ══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Oxsium  ·  Service Manager")
        self.resize(1120, 700)
        self.setMinimumSize(860, 520)

        central = QWidget()
        self.setCentralWidget(central)
        ml = QHBoxLayout(central)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(0)

        # Sidebar
        self._sidebar = Sidebar(SIDEBAR_ENTRIES)
        ml.addWidget(self._sidebar)

        # Right side
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(3)

        self._stack = QStackedWidget()
        splitter.addWidget(self._stack)

        # Global log section
        glog_wrap = QWidget()
        gv = QVBoxLayout(glog_wrap)
        gv.setContentsMargins(0, 0, 0, 0)
        gv.setSpacing(0)

        self._glog = Log()
        gv.addWidget(GlobalLogBar())
        gv.addWidget(self._glog)
        splitter.addWidget(glog_wrap)
        splitter.setSizes([490, 180])

        rl.addWidget(splitter, stretch=1)
        ml.addWidget(right, stretch=1)

        # Build controllers and panels
        self._mgr = ServiceManager(self._glog)

        for key, name, hint, fk, pk, tag, tag_col in SERVICE_DEFS:
            ctrl  = ServiceController(key, name, hint, FILES[fk],
                                      DEFAULT_PORTS[pk], tag, tag_col)
            panel = ServicePanel(ctrl)
            self._mgr.register_service(ctrl, panel)
            self._stack.addWidget(panel)

        web_ctrl  = WebController(DEFAULT_PORTS["http"])
        web_panel = WebPanel(web_ctrl)
        self._mgr.register_web(web_ctrl, web_panel)
        self._stack.addWidget(web_panel)

        # Sidebar connections
        self._sidebar.service_selected.connect(self._stack.setCurrentIndex)
        self._sidebar.btn_start_all.clicked.connect(self._mgr.start_all)
        self._sidebar.btn_stop_all.clicked.connect(self._mgr.stop_all)

        # Sidebar LED — bind to panel state
        for i, panel in enumerate(self._mgr.panels):
            def make_apply(orig, idx):
                def apply(s):
                    orig(s)
                    self._sidebar.light(idx).setState(s)
                return apply
            panel.apply_state = make_apply(panel.apply_state, i)

        self._glog.sys("Oxsium Service Manager started.")

    def closeEvent(self, e):
        self._mgr.kill_all_nowait(); e.accept()


# ══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    app.setApplicationName("Oxsium Service Manager")
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
)===";
}

static bool create_start_py(const fs::path& root) {
    fs::path dest = root / "start.py";

    // Try to copy start.py that sits next to this exe
    fs::path src = fs::current_path() / "start.py";
    if (fs::exists(src) && src != dest) {
        std::ifstream in(src, std::ios::binary);
        if (in) {
            std::string content((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
            if (write_file(dest, content)) {
                ok("start.py copied from: " + src.string());
                bullet(ansi::PATH_CLR() + dest.string() + ansi::RST());
                return true;
            }
        }
    }

    // Embedded fallback
    if (!write_file(dest, start_py_content())) {
        err("Failed to write start.py.");
        return false;
    }
    ok("start.py created.");
    bullet(ansi::PATH_CLR() + dest.string() + ansi::RST());
    return true;
}

/* ══════════════════════════════════════════════════════════════════════════
   main
   ══════════════════════════════════════════════════════════════════════════ */

int main() {
    ansi::init();
    print_banner();

    const fs::path exe_dir = fs::current_path();
    const fs::path root    = locate_root(exe_dir);

    std::cout << ansi::DIM() << "  Project root : "
              << ansi::PATH_CLR() << root.string() << ansi::RST() << "\n";
    std::cout << ansi::DIM() << "  Venv target  : "
              << ansi::PATH_CLR() << (root / "oxsium-web").string() << ansi::RST() << "\n";
    std::cout << ansi::DIM() << "  Requirements : "
              << ansi::PATH_CLR()
              << (root / "Main" / "Configurations" / "requirements.txt").string()
              << ansi::RST() << "\n";

    step_header(1, "Python Runtime Check");
    if (!ensure_python()) return 1;

    step_header(2, "Virtual Environment  (oxsium-web)");
    if (!create_virtual_environment(root)) {
        err("Could not create virtual environment. Aborting.");
        return 1;
    }

    step_header(3, "Installing Dependencies");
    if (!install_requirements(root)) {
        err("Could not install required packages. Aborting.");
        return 1;
    }

    step_header(4, "Generating start.py");
    if (!create_start_py(root)) {
        err("Could not write start.py. Aborting.");
        return 1;
    }

    print_success(root);
    return 0;
}