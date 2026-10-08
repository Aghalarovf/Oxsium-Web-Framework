# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import fnmatch
import threading
from collections import deque
from datetime import datetime

from burp import IBurpExtender, ITab, IHttpListener

from javax.swing import (JPanel, JLabel, JTextField, JButton, JCheckBox,
                         JTable, JScrollPane, JSpinner, SpinnerNumberModel,
                         BorderFactory, Box, BoxLayout, JFileChooser, SwingUtilities,
                         JRadioButton, ButtonGroup, JOptionPane)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import (Dimension, Font, Color, FlowLayout, RenderingHints,
                      GridBagLayout, GridBagConstraints, Insets, BorderLayout,
                      GradientPaint, Graphics2D, BasicStroke, AlphaComposite)
from java.awt.geom import RoundRectangle2D
from java.io import File
from java.lang import System


def _ts():
    return datetime.utcnow().strftime("%H:%M:%S")

def _log_info(msg):
    sys.stdout.write("[{}] {}\n".format(_ts(), msg))

def _log_error(msg):
    sys.stderr.write("[{}] ERROR: {}\n".format(_ts(), msg))


# ---------------------------------------------------------------------------
# Project folder discovery  (Windows + Linux + macOS)
#   ...\Oxsium-Web-Framework\Main\Scan-Results\
# ---------------------------------------------------------------------------
_PROJECT_DIR   = "Oxsium-Web-Framework"
_PROJECT_SUB   = ("Main", "Scan-Results")
_PROJECT_FILE  = "burp_traffic.json"

# Directories that never contain the project and are expensive/noisy to walk.
_SKIP_DIRS = set([
    "proc", "sys", "dev", "run", "snap", "boot", "lost+found",
    "lib", "lib32", "lib64", "bin", "sbin",
    "windows", "$recycle.bin", "system volume information",
    "program files", "program files (x86)", "programdata", "appdata",
    "node_modules", "site-packages", "__pycache__",
])


def _project_search_roots():
    """Ordered, de-duplicated list of (root, max_depth). Likely places first."""
    roots = []
    seen = set()

    def add(path, depth):
        if not path:
            return
        path = str(path)
        key = os.path.normcase(os.path.abspath(path))
        if key in seen or not os.path.isdir(path):
            return
        seen.add(key)
        roots.append((path, depth))

    home = str(System.getProperty("user.home") or "")
    try:
        add(os.getcwd(), 5)
    except Exception:
        pass
    add(home, 6)
    for sub in ("Desktop", "Documents", "Downloads", "Tools", "tools", "opt"):
        add(os.path.join(home, sub), 6)
    for p in ("/opt", "/srv", "/mnt", "/media", "/home", "/root", "/usr/local", "/var/www"):
        add(p, 6)
    # Every filesystem root: "/" on Linux/macOS, "C:\\", "D:\\" ... on Windows
    for r in File.listRoots():
        add(str(r.getAbsolutePath()), 6)
    return roots


def _bfs_find_dir(root, name_lower, max_depth, deadline):
    """Breadth-first search for a directory called name_lower (case-insensitive).
    Yields matching absolute paths; stops at the deadline."""
    queue = deque([(root, 0)])
    while queue:
        if time.time() > deadline:
            return
        cur, depth = queue.popleft()
        try:
            names = os.listdir(cur)
        except Exception:
            continue
        subdirs = []
        for n in names:
            low = n.lower()
            full = os.path.join(cur, n)
            try:
                if not os.path.isdir(full):
                    continue
            except Exception:
                continue
            if low == name_lower:
                yield full
                continue
            if depth < max_depth and low not in _SKIP_DIRS and not n.startswith("."):
                try:
                    if os.path.islink(full):
                        continue
                except Exception:
                    continue
                subdirs.append(full)
        for d in subdirs:
            queue.append((d, depth + 1))


def find_scan_results_dir(time_budget=60):
    """Locate <...>/Oxsium-Web-Framework/Main/Scan-Results anywhere on this machine.

    Returns the Scan-Results directory (created if only the framework folder
    exists), or None when Oxsium-Web-Framework cannot be found.
    """
    deadline  = time.time() + time_budget
    fallback  = None
    target    = _PROJECT_DIR.lower()
    for root, depth in _project_search_roots():
        for fw in _bfs_find_dir(root, target, depth, deadline):
            results = os.path.join(fw, *_PROJECT_SUB)
            if os.path.isdir(results):
                return results
            if fallback is None:
                fallback = results
        if time.time() > deadline:
            break
    if fallback:
        try:
            os.makedirs(fallback)
        except Exception:
            if not os.path.isdir(fallback):
                return None
        return fallback
    return None


class JsonExporter(object):
    """Writes HTTP entries either as JSON Lines (.jsonl) or pretty JSON array (.json).

    JSONL mode: one compact JSON object per line, appended in real-time.
    JSON mode:  a valid JSON array; the file is rewritten on every append so it
                stays parseable at any point during a capture session.

    Non-ASCII characters are escaped (\\uXXXX) to stay safe with Jython's
    str/unicode handling; all output is valid JSON.
    """

    FORMAT_JSONL = "jsonl"
    FORMAT_JSON  = "json"

    def __init__(self, output_path, fmt=FORMAT_JSONL):
        self.output_path = output_path
        self.fmt         = fmt          # "jsonl" or "json"
        self.target      = ""
        self._lock       = threading.Lock()
        self._entries    = []           # kept in memory for JSON array rewrites
        self._truncate()

    def set_target(self, target):
        with self._lock:
            if not self.target:
                self.target = target

    def append(self, entry):
        with self._lock:
            self._entries.append(entry)
            if self.fmt == self.FORMAT_JSONL:
                line = json.dumps(entry, ensure_ascii=True, separators=(",", ":"))
                f = open(self.output_path, "a")
                try:
                    f.write(line + "\n")
                finally:
                    f.close()
            else:
                # Rewrite the whole file as a pretty-printed JSON array
                content = json.dumps(self._entries, ensure_ascii=True, indent=2)
                f = open(self.output_path, "w")
                try:
                    f.write(content + "\n")
                finally:
                    f.close()

    def clear(self):
        with self._lock:
            self.target   = ""
            self._entries = []
            self._truncate()

    def _truncate(self):
        f = open(self.output_path, "w")
        try:
            if self.fmt == self.FORMAT_JSON:
                f.write("[]\n")
        finally:
            f.close()


class Engine(object):
    def __init__(self, exporter, domain=None, methods=None,
                 status_filter=None, body_preview=2000, on_entry=None):
        self._exporter      = exporter
        self._methods       = [m.upper() for m in methods] if methods else None
        self._status_filter = status_filter
        self._body_preview  = body_preview
        self._on_entry      = on_entry
        self._pending       = {}
        self._lock          = threading.Lock()
        self._counter       = 0

        # Build a normalised glob pattern for URL matching.
        # Supports * (any chars) and ? (single char) against the full URL.
        # If the user types no wildcards, wrap with * so it acts as substring.
        if domain:
            pat = domain.strip().lower()
            if "*" not in pat and "?" not in pat:
                pat = "*" + pat + "*"
            self._url_pattern = pat
        else:
            self._url_pattern = None

    def _allow_host(self, host, url=None):
        if not self._url_pattern:
            return True
        target = (url if url else host).lower()
        return fnmatch.fnmatch(target, self._url_pattern)

    def _allow_method(self, method):
        if not self._methods:
            return True
        return method.upper() in self._methods

    def _allow_status(self, code):
        if not self._status_filter:
            return True
        code = int(code)
        for f in self._status_filter:
            if f == "1xx" and 100 <= code < 200: return True
            if f == "2xx" and 200 <= code < 300: return True
            if f == "3xx" and 300 <= code < 400: return True
            if f == "4xx" and 400 <= code < 500: return True
            if f == "5xx" and 500 <= code < 600: return True
        return False

    def on_request(self, req_id, method, url, headers, body,
                   http_version, host, protocol):
        if not self._allow_host(host, url):    return
        if not self._allow_method(method): return

        self._exporter.set_target("{}://{}".format(protocol, host))
        with self._lock:
            self._counter += 1
            entry = {
                "id": self._counter,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "http_version": http_version,
                "is_sse": "text/event-stream" in headers.get("accept", ""),
                "request": {"method": method, "url": url,
                            "headers": headers, "body": body},
                "response": None,
                "elapsed_seconds": None
            }
            self._pending[req_id] = {"entry": entry, "start": time.time()}

    def on_response(self, req_id, status_code, headers, body_preview, content_type):
        with self._lock:
            pending = self._pending.pop(req_id, None)
        if pending is None:
            return
        if not self._allow_status(status_code):
            return

        entry   = pending["entry"]
        elapsed = round(time.time() - pending["start"], 3)
        entry["is_sse"]          = "text/event-stream" in content_type
        entry["elapsed_seconds"] = elapsed
        entry["response"] = {
            "status_code": status_code,
            "headers":     headers,
            "body_preview": body_preview[:self._body_preview] if body_preview else ""
        }
        self._exporter.append(entry)
        if self._on_entry:
            self._on_entry(entry)

    def on_complete(self, method, url, headers, body, http_version, host, protocol,
                    status_code, resp_headers, body_preview, content_type):
        if not self._allow_host(host, url):     return
        if not self._allow_method(method):      return
        if not self._allow_status(status_code): return

        self._exporter.set_target("{}://{}".format(protocol, host))
        with self._lock:
            self._counter += 1
            entry_id = self._counter

        entry = {
            "id": entry_id,
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "http_version": http_version,
            "is_sse": "text/event-stream" in content_type,
            "request": {"method": method, "url": url,
                        "headers": headers, "body": body},
            "response": {
                "status_code": status_code,
                "headers": resp_headers,
                "body_preview": body_preview[:self._body_preview] if body_preview else ""
            },
            "elapsed_seconds": None
        }
        self._exporter.append(entry)
        if self._on_entry:
            self._on_entry(entry)

    def reset(self):
        with self._lock:
            self._pending = {}
            self._counter = 0


def _parse_headers(header_list):
    result = {}
    for i in range(1, len(header_list)):
        raw = str(header_list[i])
        if ": " in raw:
            k, v = raw.split(": ", 1)
            result[k.lower()] = v
    return result

def _http_version(first_line):
    if "HTTP/2"   in first_line: return "HTTP/2"
    if "HTTP/1.0" in first_line: return "HTTP/1.0"
    return "HTTP/1.1"


class BurpHttpListener(IHttpListener):
    def __init__(self, helpers, engine):
        self._helpers  = helpers
        self._engine   = engine
        self._lock     = threading.Lock()
        self._counter  = 0

    def processHttpMessage(self, tool_flag, is_request, message_info):
        # Only handle the response phase: message_info then holds both the
        # request and the response, so no setComment()/getComment() correlation
        # is needed. This works for Crawl/Scanner traffic too.
        if is_request:
            return
        try:
            raw_resp = message_info.getResponse()
            if not raw_resp:
                return

            service  = message_info.getHttpService()
            host     = str(service.getHost())
            protocol = str(service.getProtocol())

            raw      = message_info.getRequest()
            analyzed = self._helpers.analyzeRequest(message_info)
            hlist    = analyzed.getHeaders()
            method   = str(analyzed.getMethod())
            url      = str(analyzed.getUrl())
            version  = _http_version(str(hlist[0]) if hlist else "")
            headers  = _parse_headers(hlist)
            body_b   = raw[analyzed.getBodyOffset():]
            body     = self._helpers.bytesToString(body_b) if body_b else None

            analyzed_r   = self._helpers.analyzeResponse(raw_resp)
            resp_headers = _parse_headers(analyzed_r.getHeaders())
            rbody_b      = raw_resp[analyzed_r.getBodyOffset():]
            rbody        = self._helpers.bytesToString(rbody_b) if rbody_b else ""

            self._engine.on_complete(
                method=method, url=url, headers=headers, body=body,
                http_version=version, host=host, protocol=protocol,
                status_code=analyzed_r.getStatusCode(),
                resp_headers=resp_headers, body_preview=rbody,
                content_type=resp_headers.get("content-type", "")
            )
        except Exception as e:
            _log_error("processHttpMessage: " + str(e))


class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


class StatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        self.setHorizontalAlignment(JLabel.CENTER)
        if not isSelected:
            try:
                code = int(str(value))
                if 100 <= code < 200:
                    self.setForeground(Color(0x8E44AD))
                elif 200 <= code < 300:
                    self.setForeground(Color(0x27AE60))
                elif 300 <= code < 400:
                    self.setForeground(Color(0x2980B9))
                elif 400 <= code < 500:
                    self.setForeground(Color(0xE67E22))
                elif 500 <= code < 600:
                    self.setForeground(Color(0xC0392B))
                else:
                    self.setForeground(Color(0x7F8C8D))
            except:
                self.setForeground(Color(0x7F8C8D))
        return c


class MethodCellRenderer(DefaultTableCellRenderer):
    METHOD_COLORS = {
        "GET":     Color(0x27AE60),
        "POST":    Color(0x2980B9),
        "PUT":     Color(0xF39C12),
        "PATCH":   Color(0x8E44AD),
        "DELETE":  Color(0xC0392B),
        "OPTIONS": Color(0x7F8C8D),
        "HEAD":    Color(0x16A085),
    }

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        self.setHorizontalAlignment(JLabel.CENTER)
        self.setFont(Font("SansSerif", Font.BOLD, 11))
        if not isSelected:
            color = self.METHOD_COLORS.get(str(value), Color(0x7F8C8D))
            self.setForeground(color)
        return c


class AlternatingRowRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        if not isSelected:
            if row % 2 == 0:
                c.setBackground(Color(0xFFFFFF))
            else:
                c.setBackground(Color(0xF8F9FA))
            c.setForeground(Color(0x2C3E50))
        return c


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._listener  = None
        self._engine    = None
        self._exporter  = None
        self._running   = False

        callbacks.setExtensionName("Burp Exporter")
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Burp Exporter loaded.")

    def getTabCaption(self):  return "Burp Exporter"
    def getUiComponent(self): return self._root

    def _lbl(self, text, bold=False, size=12, color=None):
        l = JLabel(text)
        l.setFont(Font("SansSerif", Font.BOLD if bold else Font.PLAIN, size))
        if color:
            l.setForeground(color)
        return l

    def _field(self, text, cols):
        f = JTextField(text, cols)
        f.setFont(Font("SansSerif", Font.PLAIN, 12))
        f.setBackground(Color(0xF8F9FA))
        f.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(0xDEE2E6), 1),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ))
        f.setCaretColor(Color(0x495057))
        f.setForeground(Color(0x212529))
        return f

    def _btn(self, text, bg=None, fg=Color.WHITE):
        b = JButton(text)
        b.setFont(Font("SansSerif", Font.BOLD, 12))
        b.setFocusPainted(False)
        if bg:
            b.setBackground(bg)
            b.setForeground(fg)
            b.setOpaque(True)
            b.setBorderPainted(False)
        else:
            b.setBackground(Color(0xF8F9FA))
            b.setForeground(Color(0x495057))
            b.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color(0xDEE2E6), 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)
            ))
        return b

    def _section_label(self, text):
        l = JLabel(text.upper())
        l.setFont(Font("SansSerif", Font.BOLD, 10))
        l.setForeground(Color(0x6C757D))
        return l

    def _build_ui(self):
        C_BG        = Color(0xF0F2F5)
        C_PANEL     = Color(0xFFFFFF)
        C_DARK      = Color(0x1A1D23)
        C_ACCENT    = Color(0xFF6633)
        C_ACCENT2   = Color(0xFF8C55)
        self._C_GREEN  = Color(0x28A745)
        self._C_RED    = Color(0xDC3545)
        self._C_ORANGE = Color(0xFD7E14)

        self._root = JPanel(BorderLayout())
        self._root.setBackground(C_BG)

        header = JPanel(BorderLayout())
        header.setBackground(C_DARK)
        header.setPreferredSize(Dimension(0, 52))

        left_header = JPanel(FlowLayout(FlowLayout.LEFT, 20, 0))
        left_header.setBackground(C_DARK)
        left_header.setBorder(BorderFactory.createEmptyBorder(12, 16, 0, 0))

        icon_lbl = JLabel(">>>")
        icon_lbl.setFont(Font("SansSerif", Font.BOLD, 18))
        icon_lbl.setForeground(C_ACCENT)
        left_header.add(icon_lbl)

        title_panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        title_panel.setBackground(C_DARK)
        title_lbl = JLabel("Burp Exporter")
        title_lbl.setFont(Font("SansSerif", Font.BOLD, 15))
        title_lbl.setForeground(Color.WHITE)
        sep_lbl = JLabel("/")
        sep_lbl.setFont(Font("SansSerif", Font.PLAIN, 15))
        sep_lbl.setForeground(Color(0x495057))
        sub_lbl = JLabel("Real-time HTTP Traffic Exporter")
        sub_lbl.setFont(Font("SansSerif", Font.PLAIN, 12))
        sub_lbl.setForeground(Color(0x6C757D))
        title_panel.add(title_lbl)
        title_panel.add(sep_lbl)
        title_panel.add(sub_lbl)
        left_header.add(title_panel)

        header.add(left_header, BorderLayout.WEST)
        self._root.add(header, BorderLayout.NORTH)

        centre = JPanel(BorderLayout(0, 12))
        centre.setBackground(C_BG)
        centre.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16))
        centre.add(self._build_config(C_PANEL, C_BG, C_ACCENT), BorderLayout.NORTH)
        centre.add(self._build_table(C_DARK, C_BG), BorderLayout.CENTER)
        self._root.add(centre, BorderLayout.CENTER)

        bar = JPanel(FlowLayout(FlowLayout.LEFT, 16, 0))
        bar.setBackground(Color(0xFFFFFF))
        bar.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, Color(0xDEE2E6)),
            BorderFactory.createEmptyBorder(8, 16, 8, 16)
        ))
        self._status_dot  = JLabel("*")
        self._status_dot.setFont(Font("SansSerif", Font.BOLD, 14))
        self._status_dot.setForeground(self._C_RED)
        self._status_text = JLabel("Stopped")
        self._status_text.setFont(Font("SansSerif", Font.BOLD, 12))
        self._status_text.setForeground(Color(0x495057))
        sep = JLabel("|")
        sep.setForeground(Color(0xDEE2E6))
        sep.setFont(Font("SansSerif", Font.PLAIN, 16))
        self._counter_lbl = JLabel("0 requests captured")
        self._counter_lbl.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._counter_lbl.setForeground(Color(0x6C757D))
        self._target_lbl = JLabel("")
        self._target_lbl.setFont(Font("SansSerif", Font.PLAIN, 11))
        self._target_lbl.setForeground(Color(0xADB5BD))
        bar.add(self._status_dot)
        bar.add(self._status_text)
        bar.add(sep)
        bar.add(self._counter_lbl)
        bar.add(sep)
        bar.add(self._target_lbl)
        self._root.add(bar, BorderLayout.SOUTH)

    def _card(self, C_PANEL, title=None):
        wrapper = JPanel(BorderLayout(0, 8))
        wrapper.setBackground(Color(0xF0F2F5))
        if title:
            wrapper.add(self._section_label(title), BorderLayout.NORTH)
        p = JPanel(GridBagLayout())
        p.setBackground(C_PANEL)
        p.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(0xDEE2E6), 1),
            BorderFactory.createEmptyBorder(14, 16, 14, 16)
        ))
        wrapper.add(p, BorderLayout.CENTER)
        return wrapper, p

    def _build_config(self, C_PANEL, C_BG, C_ACCENT):
        wrapper = JPanel(GridBagLayout())
        wrapper.setBackground(C_BG)
        oc = GridBagConstraints()
        oc.fill    = GridBagConstraints.BOTH
        oc.weighty = 1.0
        oc.insets  = Insets(0, 0, 0, 10)

        c1w, c1 = self._card(C_PANEL, "Target")
        g   = GridBagConstraints()
        g.anchor = GridBagConstraints.WEST
        g.insets = Insets(5, 0, 5, 10)

        g.gridx, g.gridy = 0, 0
        c1.add(self._lbl("Domain Regex", bold=True, size=11, color=Color(0x495057)), g)
        self._domain_field = self._field("", 22)
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1.0
        c1.add(self._domain_field, g)
        g.fill = GridBagConstraints.NONE; g.weightx = 0; g.gridx = 2
        hint = self._lbl("e.g. *flare.*  or  *.example.com*", size=11, color=Color(0xADB5BD))
        c1.add(hint, g)

        g.gridx, g.gridy = 0, 1; g.fill = GridBagConstraints.NONE
        c1.add(self._lbl("Output File", bold=True, size=11, color=Color(0x495057)), g)
        self._output_field = self._field("burp_traffic.json", 22)
        g.gridx = 1; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1.0
        c1.add(self._output_field, g)
        g.fill = GridBagConstraints.NONE; g.weightx = 0; g.gridx = 2
        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        btn_row.setBackground(C_PANEL)
        bb = self._btn("Browse")
        bb.addActionListener(lambda e: self._browse())
        self._project_btn = self._btn("Project", Color(0x8E44AD))
        self._project_btn.setToolTipText(
            "Find Oxsium-Web-Framework/Main/Scan-Results on this machine "
            "and save burp_traffic.json there")
        self._project_btn.addActionListener(lambda e: self._project())
        btn_row.add(bb)
        btn_row.add(self._project_btn)
        c1.add(btn_row, g)

        # --- Output Format row (JSON / JSONL radio buttons) ---
        g.gridx, g.gridy = 0, 2; g.fill = GridBagConstraints.NONE
        c1.add(self._lbl("Output Format", bold=True, size=11, color=Color(0x495057)), g)

        fmt_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        fmt_row.setBackground(C_PANEL)

        self._fmt_jsonl = JRadioButton("JSONL  (one line per request)")
        self._fmt_json  = JRadioButton("JSON  (pretty array)")
        for rb in (self._fmt_jsonl, self._fmt_json):
            rb.setFont(Font("SansSerif", Font.PLAIN, 12))
            rb.setBackground(C_PANEL)
            rb.setForeground(Color(0x212529))
            rb.setFocusPainted(False)

        self._fmt_json.setSelected(True)    # default: JSON
        self._fmt_jsonl.setForeground(Color(0x27AE60))
        self._fmt_json.setForeground(Color(0x2980B9))

        fmt_group = ButtonGroup()
        fmt_group.add(self._fmt_jsonl)
        fmt_group.add(self._fmt_json)

        # Update file extension when format changes
        def _on_fmt_change(e):
            txt = self._output_field.getText().strip()
            if self._fmt_jsonl.isSelected():
                if txt.endswith(".json") and not txt.endswith(".jsonl"):
                    self._output_field.setText(txt[:-5] + ".jsonl")
            else:
                if txt.endswith(".jsonl"):
                    self._output_field.setText(txt[:-6] + ".json")
                elif txt.endswith(".json"):
                    pass
                else:
                    self._output_field.setText(txt)
        self._fmt_jsonl.addActionListener(_on_fmt_change)
        self._fmt_json.addActionListener(_on_fmt_change)

        fmt_row.add(self._fmt_jsonl)
        fmt_row.add(self._fmt_json)

        g.gridx = 1; g.gridwidth = 2; g.fill = GridBagConstraints.HORIZONTAL
        c1.add(fmt_row, g)
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE

        oc.gridx = 0; oc.weightx = 0.42
        wrapper.add(c1w, oc)

        c2w, c2 = self._card(C_PANEL, "Filters")
        g2  = GridBagConstraints()
        g2.anchor = GridBagConstraints.WEST
        g2.insets = Insets(5, 0, 5, 10)

        g2.gridx, g2.gridy = 0, 0
        c2.add(self._lbl("Methods", bold=True, size=11, color=Color(0x495057)), g2)
        mrow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        mrow.setBackground(C_PANEL)
        self._method_checks = {}
        METHOD_COLORS = {
            "GET": Color(0x27AE60), "POST": Color(0x2980B9),
            "PUT": Color(0xF39C12), "PATCH": Color(0x8E44AD),
            "DELETE": Color(0xC0392B), "OPTIONS": Color(0x7F8C8D),
            "HEAD": Color(0x16A085)
        }
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
            cb = JCheckBox(m)
            cb.setSelected(True)
            cb.setFont(Font("SansSerif", Font.BOLD, 11))
            cb.setForeground(METHOD_COLORS.get(m, Color(0x495057)))
            cb.setBackground(C_PANEL)
            self._method_checks[m] = cb
            mrow.add(cb)
        g2.gridx = 1; g2.gridwidth = 3
        c2.add(mrow, g2)

        g2.gridx, g2.gridy = 0, 1; g2.gridwidth = 1
        c2.add(self._lbl("Status", bold=True, size=11, color=Color(0x495057)), g2)
        srow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        srow.setBackground(C_PANEL)
        self._status_checks = {}
        STATUS_COLORS = {
            "1xx": Color(0x8E44AD), "2xx": Color(0x27AE60), "3xx": Color(0x2980B9),
            "4xx": Color(0xE67E22), "5xx": Color(0xC0392B)
        }
        for s in ["1xx", "2xx", "3xx", "4xx", "5xx"]:
            cb = JCheckBox(s)
            cb.setSelected(True)
            cb.setFont(Font("SansSerif", Font.BOLD, 11))
            cb.setForeground(STATUS_COLORS.get(s, Color(0x495057)))
            cb.setBackground(C_PANEL)
            self._status_checks[s] = cb
            srow.add(cb)
        g2.gridx = 1; g2.gridwidth = 3
        c2.add(srow, g2)

        g2.gridx, g2.gridy = 0, 2; g2.gridwidth = 1
        c2.add(self._lbl("Body Preview", bold=True, size=11, color=Color(0x495057)), g2)
        self._body_spinner = JSpinner(SpinnerNumberModel(1000000, 100, 10000000, 10000))
        self._body_spinner.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._body_spinner.setPreferredSize(Dimension(110, 28))
        g2.gridx = 1
        c2.add(self._body_spinner, g2)
        g2.gridx = 2
        c2.add(self._lbl("chars", size=11, color=Color(0xADB5BD)), g2)

        oc.gridx = 1; oc.weightx = 0.45
        wrapper.add(c2w, oc)

        c3w, c3 = self._card(C_PANEL, "Actions")
        c3.setLayout(BoxLayout(c3, BoxLayout.Y_AXIS))
        SZ = Dimension(120, 32)

        self._start_btn = self._btn("  Start", self._C_GREEN)
        self._start_btn.setMaximumSize(SZ)
        self._start_btn.setPreferredSize(SZ)
        self._start_btn.addActionListener(lambda e: self._start())

        self._stop_btn = self._btn("  Stop", self._C_RED)
        self._stop_btn.setMaximumSize(SZ)
        self._stop_btn.setPreferredSize(SZ)
        self._stop_btn.setEnabled(False)
        self._stop_btn.addActionListener(lambda e: self._stop())

        self._clear_btn = self._btn("  Clear", Color(0x6C757D))
        self._clear_btn.setMaximumSize(SZ)
        self._clear_btn.setPreferredSize(SZ)
        self._clear_btn.addActionListener(lambda e: self._clear())

        c3.add(self._start_btn)
        c3.add(Box.createRigidArea(Dimension(0, 6)))
        c3.add(self._stop_btn)
        c3.add(Box.createRigidArea(Dimension(0, 6)))
        c3.add(self._clear_btn)

        oc.gridx = 2; oc.weightx = 0.13
        oc.fill = GridBagConstraints.NONE
        oc.anchor = GridBagConstraints.NORTHWEST
        wrapper.add(c3w, oc)

        return wrapper

    def _build_table(self, C_DARK, C_BG):
        cols = ["#", "Timestamp", "Method", "URL", "Status", "Elapsed (s)"]
        self._table_model = ReadOnlyTableModel(cols, 0)

        self._table = JTable(self._table_model)
        self._table.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._table.setRowHeight(26)
        self._table.setGridColor(Color(0xF1F3F5))
        self._table.setShowGrid(True)
        self._table.setIntercellSpacing(Dimension(0, 1))
        self._table.setSelectionBackground(Color(0xCFE2FF))
        self._table.setSelectionForeground(Color(0x084298))

        hdr = self._table.getTableHeader()
        hdr.setFont(Font("SansSerif", Font.BOLD, 11))
        hdr.setBackground(Color(0x1A1D23))
        hdr.setForeground(Color(0xADB5BD))
        hdr.setBorder(BorderFactory.createEmptyBorder())
        hdr.setReorderingAllowed(False)
        hdr.setPreferredSize(Dimension(0, 32))

        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)

        col_widths = [40, 150, 75, 9999, 70, 90]
        for i, w in enumerate(col_widths):
            col = self._table.getColumnModel().getColumn(i)
            if w != 9999:
                col.setMinWidth(w)
                col.setMaxWidth(w)
                col.setPreferredWidth(w)

        method_renderer = MethodCellRenderer()
        self._table.getColumnModel().getColumn(2).setCellRenderer(method_renderer)

        status_renderer = StatusCellRenderer()
        self._table.getColumnModel().getColumn(4).setCellRenderer(status_renderer)

        alt_renderer = AlternatingRowRenderer()
        self._table.getColumnModel().getColumn(0).setCellRenderer(alt_renderer)
        self._table.getColumnModel().getColumn(1).setCellRenderer(alt_renderer)
        self._table.getColumnModel().getColumn(3).setCellRenderer(alt_renderer)
        self._table.getColumnModel().getColumn(5).setCellRenderer(alt_renderer)

        scroll = JScrollPane(self._table)
        scroll.setBorder(BorderFactory.createLineBorder(Color(0xDEE2E6), 1))
        scroll.getViewport().setBackground(Color.WHITE)

        table_header_lbl = JPanel(BorderLayout())
        table_header_lbl.setBackground(C_BG)
        table_header_lbl.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0))

        left = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        left.setBackground(C_BG)
        tl = JLabel("Captured Requests")
        tl.setFont(Font("SansSerif", Font.BOLD, 13))
        tl.setForeground(Color(0x212529))
        left.add(tl)
        table_header_lbl.add(left, BorderLayout.WEST)

        panel = JPanel(BorderLayout())
        panel.setBackground(C_BG)
        panel.add(table_header_lbl, BorderLayout.NORTH)
        panel.add(scroll, BorderLayout.CENTER)
        return panel

    def _browse(self):
        fc = JFileChooser()
        fc.setDialogTitle("Select output file")
        if self._fmt_jsonl.isSelected():
            fc.setFileFilter(FileNameExtensionFilter("JSON Lines files (*.jsonl)", ["jsonl"]))
        else:
            fc.setFileFilter(FileNameExtensionFilter("JSON files (*.json)", ["json"]))
        if fc.showSaveDialog(self._root) == JFileChooser.APPROVE_OPTION:
            path = str(fc.getSelectedFile().getAbsolutePath())
            # Auto-append correct extension if missing
            if self._fmt_jsonl.isSelected() and not path.endswith(".jsonl"):
                path = path + ".jsonl"
            elif self._fmt_json.isSelected() and not path.endswith(".json"):
                path = path + ".json"
            self._output_field.setText(path)

    def _project(self):
        if self._running:
            return
        self._project_btn.setEnabled(False)
        self._project_btn.setText("Searching...")

        def _work():
            path = None
            try:
                path = find_scan_results_dir()
            except Exception as e:
                _log_error("project search: " + str(e))

            def _done():
                self._project_btn.setText("Project")
                self._project_btn.setEnabled(not self._running)
                if not path:
                    JOptionPane.showMessageDialog(
                        self._root,
                        "Could not find the folder:\n"
                        "  " + _PROJECT_DIR + "\\Main\\Scan-Results\\\n\n"
                        "Make sure Oxsium-Web-Framework exists on this machine, "
                        "or choose the file manually with Browse.",
                        "Project", JOptionPane.WARNING_MESSAGE)
                    return
                out = os.path.join(path, _PROJECT_FILE)
                try:
                    if not os.path.exists(out):
                        f = open(out, "w")
                        try:
                            f.write("[]\n")
                        finally:
                            f.close()
                except Exception as e:
                    _log_error("project file create: " + str(e))
                self._fmt_json.setSelected(True)
                self._output_field.setText(out)
                _log_info("Project output: " + out)
            SwingUtilities.invokeLater(_done)

        t = threading.Thread(target=_work)
        t.setDaemon(True)
        t.start()

    def _start(self):
        if self._running:
            return
        domain   = self._domain_field.getText().strip() or None   # glob pattern
        fmt_default = "burp_traffic.jsonl" if self._fmt_jsonl.isSelected() else "burp_traffic.json"
        output   = self._output_field.getText().strip() or fmt_default
        methods  = [m for m, cb in self._method_checks.items() if cb.isSelected()] or None
        statuses = [s for s, cb in self._status_checks.items() if cb.isSelected()] or None
        preview  = int(self._body_spinner.getValue())

        fmt = "jsonl" if self._fmt_jsonl.isSelected() else "json"
        self._exporter = JsonExporter(output_path=output, fmt=fmt)
        self._engine   = Engine(
            exporter=self._exporter, domain=domain,
            methods=methods, status_filter=statuses,
            body_preview=preview, on_entry=self._add_row
        )
        self._listener = BurpHttpListener(helpers=self._helpers, engine=self._engine)
        self._callbacks.registerHttpListener(self._listener)

        self._running = True
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._domain_field.setEnabled(False)
        self._output_field.setEnabled(False)
        self._body_spinner.setEnabled(False)
        self._fmt_jsonl.setEnabled(False)
        self._fmt_json.setEnabled(False)
        self._project_btn.setEnabled(False)
        for cb in self._method_checks.values(): cb.setEnabled(False)
        for cb in self._status_checks.values(): cb.setEnabled(False)

        self._status_dot.setForeground(self._C_GREEN)
        self._status_text.setText("Running")
        self._status_text.setForeground(self._C_GREEN)
        _log_info("Started. domain={} output={} format={}".format(domain, output, fmt.upper()))

    def _stop(self):
        if not self._running:
            return
        if self._listener:
            self._callbacks.removeHttpListener(self._listener)
        self._running = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._domain_field.setEnabled(True)
        self._output_field.setEnabled(True)
        self._body_spinner.setEnabled(True)
        self._fmt_jsonl.setEnabled(True)
        self._fmt_json.setEnabled(True)
        self._project_btn.setEnabled(True)
        for cb in self._method_checks.values(): cb.setEnabled(True)
        for cb in self._status_checks.values(): cb.setEnabled(True)

        self._status_dot.setForeground(self._C_RED)
        self._status_text.setText("Stopped")
        self._status_text.setForeground(Color(0x495057))
        _log_info("Stopped.")

    def _clear(self):
        self._table_model.setRowCount(0)
        self._counter_lbl.setText("0 requests captured")
        self._target_lbl.setText("")
        if self._engine:   self._engine.reset()
        if self._exporter: self._exporter.clear()

    def _add_row(self, entry):
        req  = entry["request"]
        resp = entry.get("response") or {}
        row  = [
            entry["id"],
            entry["timestamp"],
            req["method"],
            req["url"],
            resp.get("status_code", "-"),
            entry.get("elapsed_seconds", "-")
        ]
        target = self._exporter.target if self._exporter else ""
        def _do():
            self._table_model.addRow(row)
            n = self._table_model.getRowCount()
            self._counter_lbl.setText("{} request{} captured".format(n, "s" if n != 1 else ""))
            if target:
                self._target_lbl.setText(target)
            self._table.scrollRectToVisible(
                self._table.getCellRect(n - 1, 0, True)
            )
        SwingUtilities.invokeLater(_do)