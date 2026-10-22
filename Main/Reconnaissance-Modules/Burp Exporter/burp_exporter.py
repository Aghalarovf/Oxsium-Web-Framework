# -*- coding: utf-8 -*-
import os
import sys
import time
import json
import fnmatch
import threading
from datetime import datetime

from burp import IBurpExtender, ITab, IHttpListener

from javax.swing import (JPanel, JLabel, JTextField, JButton, JCheckBox,
                         JTable, JScrollPane, JSpinner, SpinnerNumberModel,
                         BorderFactory, Box, BoxLayout, JFileChooser, SwingUtilities,
                         JRadioButton, ButtonGroup, JSeparator, JToggleButton)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import (Dimension, Font, Color, FlowLayout, Cursor, RenderingHints,
                      GridBagLayout, GridBagConstraints, Insets, BorderLayout)
from java.awt.event import ComponentAdapter
from java.net import URL
from java.io import BufferedReader, InputStreamReader, File

try:
    import Queue as _queue
except ImportError:
    import queue as _queue


def _ts():
    return datetime.utcnow().strftime("%H:%M:%S")

def _log_info(msg):
    sys.stdout.write("[{}] {}\n".format(_ts(), msg))

def _log_error(msg):
    sys.stderr.write("[{}] ERROR: {}\n".format(_ts(), msg))


TOOL_NAMES = {
    1: "Suite", 2: "Target", 4: "Proxy", 8: "Spider", 16: "Scanner",
    32: "Intruder", 64: "Repeater", 128: "Sequencer", 256: "Extender",
}

def _tool_name(flag):
    try:
        return TOOL_NAMES.get(int(flag), "Tool-{}".format(int(flag)))
    except Exception:
        return "Unknown"

def build_entry(entry_id, method, url, headers, body, http_version, status_code,
                resp_headers, body_preview, content_type, preview_len, source, elapsed,
                include_body=True):
    if not include_body:
        # Body Preview off: keep the keys, but leave the bodies empty
        # so only the headers are written.
        body = ""
        body_preview = ""
    return {
        "id": entry_id,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "http_version": http_version,
        "is_sse": "text/event-stream" in content_type,
        "source": source,
        "request": {"method": method, "url": url,
                    "headers": headers, "body": body},
        "response": {
            "status_code": status_code,
            "headers": resp_headers,
            "body_preview": body_preview[:preview_len] if body_preview else ""
        },
        "elapsed_seconds": elapsed
    }


class JsonExporter(object):

    FORMAT_JSONL = "jsonl"
    FORMAT_JSON  = "json"

    def __init__(self, output_path, fmt=FORMAT_JSONL):
        self.output_path = output_path
        self.fmt         = fmt
        self.target      = ""
        self._lock       = threading.Lock()
        self._entries    = []
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


class JsExtractor(object):

    FOLDER_NAME = "JS-Files"
    FILE_NAME   = "javascript_files.json"

    def __init__(self, output_path, on_new=None):
        base = os.path.dirname(os.path.abspath(output_path))
        self.folder = os.path.join(base, self.FOLDER_NAME)
        if not os.path.isdir(self.folder):
            os.makedirs(self.folder)
        self.file_path = os.path.join(self.folder, self.FILE_NAME)
        self._on_new   = on_new
        self._lock     = threading.Lock()
        self._entries  = []
        self._seen     = set()
        self._write()

    @staticmethod
    def looks_like_js(url, content_type):
        ct = (content_type or "").lower()
        if "text/html" in ct:
            return False
        if "javascript" in ct or "ecmascript" in ct:
            return True
        path = url.split("?")[0].split("#")[0].lower()
        return path.endswith(".js") or path.endswith(".mjs")

    @staticmethod
    def file_name(url):
        path = url.split("?")[0].split("#")[0].rstrip("/")
        name = path.split("/")[-1]
        return name if name else "unknown.js"

    def consider(self, url, content_type, body):
        if not body or not self.looks_like_js(url, content_type):
            return False
        name = self.file_name(url)
        key  = (name, hash(body))
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._entries.append({"js_name": name, "js_content": body})
            self._write()
            total = len(self._entries)
        if self._on_new:
            self._on_new(total)
        return True

    def count(self):
        with self._lock:
            return len(self._entries)

    def clear(self):
        with self._lock:
            self._entries = []
            self._seen    = set()
            self._write()

    def _write(self):
        content = json.dumps(self._entries, ensure_ascii=True, indent=2)
        f = open(self.file_path, "w")
        try:
            f.write(content + "\n")
        finally:
            f.close()


class Engine(object):
    def __init__(self, exporter, domain=None, methods=None,
                 status_filter=None, body_preview=2000, on_entry=None,
                 js_extractor=None, include_body=True):
        self._exporter      = exporter
        self._methods       = [m.upper() for m in methods] if methods else None
        self._status_filter = status_filter
        self._body_preview  = body_preview
        self._include_body  = include_body
        self._on_entry      = on_entry
        self._js            = js_extractor
        self._pending       = {}
        self._lock          = threading.Lock()
        self._counter       = 0

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

    def matches_filter(self, method, url, host, status_code):
        """True if an entry passes this engine's domain/method/status
        filters -- i.e. it's the same test that decides whether a request
        shows up in the Captured Requests table."""
        if not self._allow_host(host, url):     return False
        if not self._allow_method(method):      return False
        if not self._allow_status(status_code): return False
        return True

    def on_complete(self, method, url, headers, body, http_version, host, protocol,
                    status_code, resp_headers, body_preview, content_type,
                    source=None, elapsed=None):
        if self._js is not None and 200 <= int(status_code) < 300 and self._allow_host(host, url):
            try:
                self._js.consider(url, content_type, body_preview)
            except Exception as e:
                _log_error("js extraction: " + str(e))

        if not self.matches_filter(method, url, host, status_code):
            return

        self._exporter.set_target("{}://{}".format(protocol, host))
        with self._lock:
            self._counter += 1
            entry_id = self._counter

        entry = build_entry(
            entry_id, method, url, headers, body, http_version, status_code,
            resp_headers, body_preview, content_type, self._body_preview,
            source, elapsed, include_body=self._include_body
        )
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


class ApiClient(object):

    # Consecutive failed heartbeats (~5s apart) before we declare the link
    # actually dead instead of silently sitting on a stale "Connected" state.
    HEARTBEAT_FAIL_LIMIT = 3

    def __init__(self, host, port, on_status=None):
        self.host      = host
        self.port      = port
        self.job_id    = None
        self._queue    = _queue.Queue()
        self._worker   = None
        self._stop     = threading.Event()
        self._on_status = on_status
        self._degraded  = False

    def _notify(self, state, detail=None):
        if self._on_status:
            try:
                self._on_status(state, detail)
            except Exception as e:
                _log_error("api status callback: " + str(e))

    @property
    def base_url(self):
        return "http://{}:{}".format(self.host, self.port)

    def _post(self, path, payload):
        url  = self.base_url + path
        data = json.dumps(payload)
        conn = URL(url).openConnection()
        conn.setRequestMethod("POST")
        conn.setDoOutput(True)
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setConnectTimeout(3000)
        conn.setReadTimeout(5000)
        out = conn.getOutputStream()
        try:
            out.write(data)
        finally:
            out.close()

        status = conn.getResponseCode()
        stream = conn.getInputStream() if status < 400 else conn.getErrorStream()
        reader = BufferedReader(InputStreamReader(stream))
        lines  = []
        line   = reader.readLine()
        while line is not None:
            lines.append(line)
            line = reader.readLine()
        reader.close()

        body = "\n".join(lines)
        if status >= 400:
            raise IOError("HTTP {}: {}".format(status, body))
        return json.loads(body)

    def start(self):
        result      = self._post("/api/burp/push/start", {"client": "exporter"})
        self.job_id = result.get("job_id")
        if not self.job_id:
            raise IOError("Burp API did not return a job_id")
        self._stop.clear()
        self._worker = threading.Thread(target=self._run)
        self._worker.daemon = True
        self._worker.start()
        return self.job_id

    def stop(self):
        self._stop.set()
        self._queue.put(None)
        job_id = self.job_id
        self.job_id = None
        if job_id:
            try:
                self._post("/api/burp/push/stop/{}".format(job_id), {})
            except Exception as e:
                _log_error("burp api stop: " + str(e))

    def enqueue(self, entry):
        if self.job_id:
            self._queue.put(entry)

    def _rejoin(self):
        result = self._post("/api/burp/push/start", {"client": "exporter"})
        new_id = result.get("job_id")
        if not new_id:
            raise IOError("Burp API did not return a job_id")
        self.job_id = new_id

    def _beat(self):
        job_id = self.job_id
        if not job_id:
            return
        try:
            self._post("/api/burp/exporter/heartbeat", {"job_id": job_id})
        except Exception as e:
            msg = str(e)
            if "HTTP 409" in msg or "HTTP 404" in msg:
                self._rejoin()
            else:
                raise

    def _send(self, entry):
        job_id = self.job_id
        if not job_id:
            return
        try:
            self._post("/api/burp/ingest", {"job_id": job_id, "entry": entry})
        except Exception as e:
            msg = str(e)
            if "HTTP 409" not in msg and "HTTP 404" not in msg:
                raise
            self._rejoin()
            self._post("/api/burp/ingest", {"job_id": self.job_id, "entry": entry})

    def _run(self):
        last_beat   = 0
        fail_count  = 0
        self._notify("alive")
        while not self._stop.is_set():
            if time.time() - last_beat >= 5:
                last_beat = time.time()
                try:
                    self._beat()
                except Exception as e:
                    fail_count += 1
                    _log_error("burp api heartbeat: " + str(e))
                    if fail_count >= self.HEARTBEAT_FAIL_LIMIT:
                        # The link has been down long enough that reporting
                        # "Connected" would be a lie. Surface it and let the
                        # panel drop back to Connect / auto-reconnect fresh.
                        self._degraded = True
                        self._notify("lost", str(e))
                        break
                    self._degraded = True
                    self._notify("degraded", str(e))
                else:
                    if fail_count or self._degraded:
                        self._degraded = False
                        self._notify("alive")
                    fail_count = 0
            try:
                entry = self._queue.get(timeout=1)
            except _queue.Empty:
                continue
            if entry is None:
                break
            try:
                self._send(entry)
            except Exception as e:
                _log_error("burp api ingest: " + str(e))
                # Transient network hiccup: put it back instead of silently
                # dropping captured traffic, unless the queue is already
                # backing up a lot (then we'd rather stay live than stall).
                if self._queue.qsize() < 2000:
                    self._queue.put(entry)
                self._degraded = True
                self._notify("degraded", str(e))


class BurpHttpListener(IHttpListener):
    MAX_PENDING = 5000

    def __init__(self, helpers, get_api):
        self._helpers  = helpers
        self._get_api  = get_api
        self._engine   = None
        self._starts   = {}
        self._lock     = threading.Lock()
        self._api_id   = 0

    def set_engine(self, engine):
        self._engine = engine

    def _next_api_id(self):
        with self._lock:
            self._api_id += 1
            return self._api_id

    def processHttpMessage(self, tool_flag, is_request, message_info):
        if is_request:
            with self._lock:
                if len(self._starts) >= self.MAX_PENDING:
                    self._starts.clear()
                self._starts[message_info] = time.time()
            return
        try:
            raw_resp = message_info.getResponse()
            if not raw_resp:
                return

            with self._lock:
                started = self._starts.pop(message_info, None)
            elapsed = round(time.time() - started, 3) if started else None
            source  = _tool_name(tool_flag)

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
            status_code  = analyzed_r.getStatusCode()
            content_type = resp_headers.get("content-type", "")

            # Only forward to the Burp API (and therefore to the OxsProxy
            # GUI) requests that actually pass the Burp Exporter filter --
            # i.e. the same requests that land in Captured Requests. If the
            # local engine isn't running, or the entry doesn't match the
            # configured domain/method/status filter, it stays out of the
            # GUI entirely instead of showing unfiltered traffic there.
            engine = self._engine
            passes_filter = (
                engine is not None
                and engine.matches_filter(method, url, host, status_code)
            )

            api = self._get_api()
            if api is not None and passes_filter:
                api.enqueue(build_entry(
                    self._next_api_id(), method, url, headers, body, version,
                    status_code, resp_headers, rbody, content_type, 2000,
                    source, elapsed
                ))

            if engine is not None:
                engine.on_complete(
                    method=method, url=url, headers=headers, body=body,
                    http_version=version, host=host, protocol=protocol,
                    status_code=status_code,
                    resp_headers=resp_headers, body_preview=rbody,
                    content_type=content_type,
                    source=source, elapsed=elapsed
                )
        except Exception as e:
            _log_error("processHttpMessage: " + str(e))


class ViewportResizer(ComponentAdapter):

    def __init__(self, callback):
        self._callback = callback

    def componentResized(self, event):
        self._callback()


class ChipToggle(JToggleButton):

    def __init__(self, text, color, extra_width=0):
        JToggleButton.__init__(self, text)
        self._color = color
        self.setFont(Font("SansSerif", Font.BOLD, 10))
        self.setFocusPainted(False)
        self.setContentAreaFilled(False)
        self.setBorderPainted(False)
        self.setOpaque(False)
        self.setMargin(Insets(0, 0, 0, 0))
        self.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        fm = self.getFontMetrics(self.getFont())
        size = Dimension(fm.stringWidth(text) + 32 + extra_width, 24)
        self.setPreferredSize(size)
        self.setMinimumSize(size)
        self.setMaximumSize(size)

    def paintComponent(self, g):
        g2 = g.create()
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                            RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        w = self.getWidth()
        h = self.getHeight()
        base = self._color
        selected = self.isSelected()
        enabled = self.isEnabled()
        alpha = 255 if enabled else 130

        if selected:
            fill = Color(base.getRed(), base.getGreen(), base.getBlue(), 34 if enabled else 20)
            border = Color(base.getRed(), base.getGreen(), base.getBlue(), alpha)
            fg = border
        else:
            fill = Color(0xF8, 0xF9, 0xFA, alpha)
            border = Color(0xCE, 0xD4, 0xDA, alpha)
            fg = Color(0x86, 0x8E, 0x96, alpha)

        g2.setColor(fill)
        g2.fillRoundRect(0, 0, w - 1, h - 1, h, h)
        g2.setColor(border)
        g2.drawRoundRect(0, 0, w - 1, h - 1, h, h)

        d = 8
        dx = 10
        dy = (h - d) // 2
        if selected:
            g2.setColor(fg)
            g2.fillOval(dx, dy, d, d)
        else:
            g2.setColor(border)
            g2.drawOval(dx, dy, d - 1, d - 1)

        g2.setFont(self.getFont())
        fm = g2.getFontMetrics()
        ty = (h - fm.getHeight()) // 2 + fm.getAscent()
        g2.setColor(fg)
        g2.drawString(self.getText(), dx + d + 6, ty)
        g2.dispose()


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
                if 200 <= code < 300:
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

    URL_MIN_WIDTH = 500

    PROJECT_PATH_PARTS = ("Oxsium-Web-Framework", "Main", "Scan-Results")

    PROJECT_SKIP_DIR_NAMES = set([
        "$Recycle.Bin", "System Volume Information", "Windows", "WINDOWS",
        "ProgramData", "Program Files", "Program Files (x86)", "AppData",
        "node_modules", ".git", ".svn", "$WinREAgent", "Recovery",
        "PerfLogs", "Config.Msi",
    ])

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._engine    = None
        self._exporter  = None
        self._js        = None
        self._api_client = None
        self._api_lock  = threading.Lock()
        self._api_manual_off = False
        self._api_auto_stop  = False
        self._running   = False
        self._locked    = []

        callbacks.setExtensionName("Burp Exporter")
        self._listener = BurpHttpListener(helpers=self._helpers, get_api=lambda: self._api_client)
        callbacks.registerHttpListener(self._listener)
        self._build_ui()
        callbacks.addSuiteTab(self)
        self._start_api_autoconnect()
        self._start_project_autodetect()
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

    def _small_btn(self, text):
        b = JButton(text)
        b.setFont(Font("SansSerif", Font.PLAIN, 11))
        b.setFocusPainted(False)
        b.setBackground(Color(0xF8F9FA))
        b.setForeground(Color(0x495057))
        b.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(Color(0xDEE2E6), 1),
            BorderFactory.createEmptyBorder(2, 10, 2, 10)
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
        self._C_GREEN  = Color(0x28A745)
        self._C_RED    = Color(0xDC3545)
        self._C_AMBER  = Color(0xE8A33D)
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
        self._counter_lbl = JLabel("0 requests captured")
        self._counter_lbl.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._counter_lbl.setForeground(Color(0x6C757D))
        self._js_lbl = JLabel("0 JS files extracted")
        self._js_lbl.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._js_lbl.setForeground(Color(0x6C757D))
        self._target_lbl = JLabel("")
        self._target_lbl.setFont(Font("SansSerif", Font.PLAIN, 11))
        self._target_lbl.setForeground(Color(0xADB5BD))

        def _sep():
            s = JLabel("|")
            s.setForeground(Color(0xDEE2E6))
            s.setFont(Font("SansSerif", Font.PLAIN, 16))
            return s

        bar.add(self._status_dot)
        bar.add(self._status_text)
        bar.add(_sep())
        bar.add(self._counter_lbl)
        bar.add(_sep())
        bar.add(self._js_lbl)
        bar.add(_sep())
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

    def _filter_row(self, panel, y, label, component, trailing=None, C_PANEL=None):
        g = GridBagConstraints()
        g.gridy = y
        g.anchor = GridBagConstraints.WEST
        g.insets = Insets(4, 0, 4, 12)

        g.gridx = 0
        lbl = self._lbl(label, bold=True, size=11, color=Color(0x495057))
        lbl.setPreferredSize(Dimension(105, 26))
        panel.add(lbl, g)

        g.gridx = 1
        g.weightx = 1.0
        g.fill = GridBagConstraints.HORIZONTAL
        panel.add(component, g)

        g.gridx = 2
        g.weightx = 0
        g.fill = GridBagConstraints.NONE
        g.insets = Insets(4, 0, 4, 0)
        if trailing is not None:
            panel.add(trailing, g)
        else:
            panel.add(Box.createRigidArea(Dimension(1, 1)), g)

    def _filter_divider(self, panel, y):
        g = GridBagConstraints()
        g.gridx = 0
        g.gridy = y
        g.gridwidth = 3
        g.fill = GridBagConstraints.HORIZONTAL
        g.insets = Insets(2, 0, 2, 0)
        sep = JSeparator()
        sep.setForeground(Color(0xE9ECEF))
        sep.setBackground(Color(0xE9ECEF))
        panel.add(sep, g)

    def _bulk_buttons(self, checks, C_PANEL):
        holder = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        holder.setBackground(C_PANEL)
        all_btn  = self._small_btn("All")
        none_btn = self._small_btn("None")

        def _set(value):
            for cb in checks.values():
                if cb.isEnabled():
                    cb.setSelected(value)

        all_btn.addActionListener(lambda e: _set(True))
        none_btn.addActionListener(lambda e: _set(False))
        holder.add(all_btn)
        holder.add(none_btn)
        self._locked.append(all_btn)
        self._locked.append(none_btn)
        return holder

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
        output_btns = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        output_btns.setBackground(C_PANEL)
        self._browse_btn = self._btn("Browse")
        self._browse_btn.addActionListener(lambda e: self._browse())
        self._project_btn = self._btn("Project")
        self._project_btn.addActionListener(lambda e: self._use_project_dir(manual=True))
        output_btns.add(self._browse_btn)
        output_btns.add(self._project_btn)
        c1.add(output_btns, g)

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

        self._fmt_json.setSelected(True)
        self._fmt_jsonl.setForeground(Color(0x27AE60))
        self._fmt_json.setForeground(Color(0x2980B9))

        fmt_group = ButtonGroup()
        fmt_group.add(self._fmt_jsonl)
        fmt_group.add(self._fmt_json)

        def _on_fmt_change(e):
            txt = self._output_field.getText().strip()
            if self._fmt_jsonl.isSelected():
                if txt.endswith(".json") and not txt.endswith(".jsonl"):
                    self._output_field.setText(txt[:-5] + ".jsonl")
            else:
                if txt.endswith(".jsonl"):
                    self._output_field.setText(txt[:-6] + ".json")
        self._fmt_jsonl.addActionListener(_on_fmt_change)
        self._fmt_json.addActionListener(_on_fmt_change)

        fmt_row.add(self._fmt_jsonl)
        fmt_row.add(self._fmt_json)

        g.gridx = 1; g.gridwidth = 2; g.fill = GridBagConstraints.HORIZONTAL
        c1.add(fmt_row, g)
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE

        sep1 = GridBagConstraints()
        sep1.gridx = 0
        sep1.gridy = 3
        sep1.gridwidth = 3
        sep1.fill = GridBagConstraints.HORIZONTAL
        sep1.insets = Insets(10, 0, 10, 0)
        api_sep = JSeparator()
        api_sep.setForeground(Color(0xE9ECEF))
        api_sep.setBackground(Color(0xE9ECEF))
        c1.add(api_sep, sep1)

        g.gridx, g.gridy = 0, 4; g.fill = GridBagConstraints.NONE
        c1.add(self._lbl("Burp API", bold=True, size=11, color=Color(0x495057)), g)
        api_row = JPanel(BorderLayout(8, 0))
        api_row.setBackground(C_PANEL)
        self._burp_api_field = self._field("127.0.0.1:30302", 16)
        self._burp_api_connect_btn = self._btn("Connect")
        self._burp_api_connect_btn.addActionListener(lambda e: self._toggle_burp_api())
        api_row.add(self._burp_api_field, BorderLayout.CENTER)
        api_row.add(self._burp_api_connect_btn, BorderLayout.EAST)
        g.gridx = 1; g.gridwidth = 2; g.fill = GridBagConstraints.HORIZONTAL
        c1.add(api_row, g)
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE

        g.gridx, g.gridy = 0, 5
        c1.add(self._lbl("API Status", bold=True, size=11, color=Color(0x495057)), g)
        self._burp_api_status_lbl = self._lbl("Disconnected", size=11, color=Color(0xADB5BD))
        g.gridx = 1; g.gridwidth = 2; g.fill = GridBagConstraints.HORIZONTAL
        c1.add(self._burp_api_status_lbl, g)
        g.gridwidth = 1; g.fill = GridBagConstraints.NONE

        fill1 = GridBagConstraints()
        fill1.gridx = 0
        fill1.gridy = 6
        fill1.gridwidth = 3
        fill1.weighty = 1.0
        c1.add(Box.createGlue(), fill1)

        oc.gridx = 0; oc.weightx = 0.36
        wrapper.add(c1w, oc)

        c2w, c2 = self._card(C_PANEL, "Filters")

        METHOD_COLORS = {
            "GET": Color(0x27AE60), "POST": Color(0x2980B9),
            "PUT": Color(0xF39C12), "PATCH": Color(0x8E44AD),
            "DELETE": Color(0xC0392B), "OPTIONS": Color(0x7F8C8D),
            "HEAD": Color(0x16A085)
        }
        mrow = JPanel()
        mrow.setLayout(BoxLayout(mrow, BoxLayout.X_AXIS))
        mrow.setBackground(C_PANEL)
        self._method_checks = {}
        for i, m in enumerate(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]):
            cb = ChipToggle(m, METHOD_COLORS.get(m, Color(0x495057)))
            cb.setSelected(True)
            self._method_checks[m] = cb
            if i:
                mrow.add(Box.createRigidArea(Dimension(8, 0)))
            mrow.add(cb)
        mrow.add(Box.createHorizontalGlue())
        mrow.setMinimumSize(Dimension(1, 24))
        self._filter_row(c2, 0, "Methods", mrow,
                         self._bulk_buttons(self._method_checks, C_PANEL))

        self._filter_divider(c2, 1)

        STATUS_COLORS = {
            "1xx": Color(0x7F8C8D), "2xx": Color(0x27AE60),
            "3xx": Color(0x2980B9), "4xx": Color(0xE67E22),
            "5xx": Color(0xC0392B)
        }
        STATUS_LABELS = {
            "1xx": "1xx Info", "2xx": "2xx Success", "3xx": "3xx Redirect",
            "4xx": "4xx Client", "5xx": "5xx Server"
        }
        srow = JPanel()
        srow.setLayout(BoxLayout(srow, BoxLayout.X_AXIS))
        srow.setBackground(C_PANEL)
        self._status_checks = {}
        for i, s in enumerate(["1xx", "2xx", "3xx", "4xx", "5xx"]):
            cb = ChipToggle(STATUS_LABELS[s], STATUS_COLORS.get(s, Color(0x495057)))
            cb.setSelected(True)
            self._status_checks[s] = cb
            if i:
                srow.add(Box.createRigidArea(Dimension(8, 0)))
            srow.add(cb)
        srow.add(Box.createHorizontalGlue())
        srow.setMinimumSize(Dimension(1, 24))
        self._filter_row(c2, 2, "Status Codes", srow,
                         self._bulk_buttons(self._status_checks, C_PANEL))

        self._filter_divider(c2, 3)

        prow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 3))
        prow.setBackground(C_PANEL)
        self._body_spinner = JSpinner(SpinnerNumberModel(1000000, 100, 10000000, 10000))
        self._body_spinner.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._body_spinner.setPreferredSize(Dimension(150, 32))
        self._body_spinner.setMinimumSize(Dimension(150, 32))
        prow.add(self._body_spinner)
        prow.add(self._lbl("characters per response body", size=11, color=Color(0x6C757D)))
        self._filter_row(c2, 4, "Body Preview", prow)

        self._filter_divider(c2, 5)

        jrow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        jrow.setBackground(C_PANEL)
        self._js_check = JCheckBox("Extract JS files")
        self._js_check.setFont(Font("SansSerif", Font.BOLD, 11))
        self._js_check.setForeground(Color(0xFF6633))
        self._js_check.setBackground(C_PANEL)
        self._js_check.setFocusPainted(False)
        jrow.add(self._js_check)
        jrow.add(self._lbl("Saves to JS-Files/javascript_files.json next to the output file",
                           size=11, color=Color(0x6C757D)))
        self._filter_row(c2, 6, "JavaScript", jrow)

        bprow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        bprow.setBackground(C_PANEL)
        self._body_preview_check = JCheckBox("Body Preview", True)
        self._body_preview_check.setFont(Font("SansSerif", Font.BOLD, 11))
        self._body_preview_check.setForeground(Color(0xFF6633))
        self._body_preview_check.setBackground(C_PANEL)
        self._body_preview_check.setFocusPainted(False)
        bprow.add(self._body_preview_check)
        bprow.add(self._lbl("Off: only headers are written, body / body_preview stay empty in the JSON",
                            size=11, color=Color(0x6C757D)))
        self._filter_row(c2, 7, "", bprow)

        fill2 = GridBagConstraints()
        fill2.gridx = 0
        fill2.gridy = 8
        fill2.gridwidth = 3
        fill2.weighty = 1.0
        c2.add(Box.createGlue(), fill2)

        oc.gridx = 1; oc.weightx = 0.52
        wrapper.add(c2w, oc)

        c3w, c3 = self._card(C_PANEL, "Actions")
        c3.setLayout(BoxLayout(c3, BoxLayout.Y_AXIS))
        SZ = Dimension(180, 48)

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

        for b in (self._start_btn, self._stop_btn, self._clear_btn):
            b.setFont(Font("SansSerif", Font.BOLD, 15))
            b.setMinimumSize(SZ)
            b.setAlignmentX(0.0)

        c3.add(self._start_btn)
        c3.add(Box.createRigidArea(Dimension(0, 10)))
        c3.add(self._stop_btn)
        c3.add(Box.createRigidArea(Dimension(0, 10)))
        c3.add(self._clear_btn)
        c3.add(Box.createVerticalGlue())

        oc.gridx = 2; oc.weightx = 0.0
        oc.insets = Insets(0, 0, 0, 0)
        wrapper.add(c3w, oc)

        self._locked.extend([
            self._domain_field, self._output_field, self._browse_btn, self._project_btn,
            self._body_spinner, self._fmt_jsonl, self._fmt_json, self._js_check,
            self._body_preview_check, self._burp_api_field
        ])
        self._locked.extend(self._method_checks.values())
        self._locked.extend(self._status_checks.values())

        return wrapper

    def _build_table(self, C_DARK, C_BG):
        self._url_needed = 0
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

        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)

        col_widths = [50, 160, 80, self.URL_MIN_WIDTH, 70, 100]
        for i, w in enumerate(col_widths):
            col = self._table.getColumnModel().getColumn(i)
            col.setMinWidth(w)
            col.setPreferredWidth(w)
            col.setWidth(w)
            if i != 3:
                col.setMaxWidth(w)

        self._table.getColumnModel().getColumn(2).setCellRenderer(MethodCellRenderer())
        self._table.getColumnModel().getColumn(4).setCellRenderer(StatusCellRenderer())

        alt_renderer = AlternatingRowRenderer()
        for idx in (0, 1, 3, 5):
            self._table.getColumnModel().getColumn(idx).setCellRenderer(alt_renderer)

        scroll = JScrollPane(self._table)
        scroll.setBorder(BorderFactory.createLineBorder(Color(0xDEE2E6), 1))
        scroll.getViewport().setBackground(Color.WHITE)
        self._scroll = scroll
        scroll.getViewport().addComponentListener(ViewportResizer(self._apply_url_width))

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

    def _apply_url_width(self):
        model = self._table.getColumnModel()
        fixed = 0
        for i in (0, 1, 2, 4, 5):
            fixed += model.getColumn(i).getWidth()
        avail = self._scroll.getViewport().getWidth() - fixed
        width = max(self._url_needed, avail, self.URL_MIN_WIDTH)
        col = model.getColumn(3)
        if col.getWidth() != width:
            col.setMinWidth(width)
            col.setPreferredWidth(width)
            col.setWidth(width)
            self._table.revalidate()
            self._table.repaint()

    def _fit_url_column(self, url):
        fm = self._table.getFontMetrics(self._table.getFont())
        needed = fm.stringWidth(url) + 24
        if needed > self._url_needed:
            self._url_needed = needed
        self._apply_url_width()

    def _reset_url_column(self):
        self._url_needed = 0
        self._apply_url_width()

    def _browse(self):
        fc = JFileChooser()
        fc.setDialogTitle("Select output file")
        if self._fmt_jsonl.isSelected():
            fc.setFileFilter(FileNameExtensionFilter("JSON Lines files (*.jsonl)", ["jsonl"]))
        else:
            fc.setFileFilter(FileNameExtensionFilter("JSON files (*.json)", ["json"]))
        if fc.showSaveDialog(self._root) == JFileChooser.APPROVE_OPTION:
            path = str(fc.getSelectedFile().getAbsolutePath())
            if self._fmt_jsonl.isSelected() and not path.endswith(".jsonl"):
                path = path + ".jsonl"
            elif self._fmt_json.isSelected() and not path.endswith(".json"):
                path = path + ".json"
            self._output_field.setText(path)

    def _own_dir(self):
        try:
            return os.path.dirname(os.path.abspath(__file__))
        except Exception:
            return os.getcwd()

    def _default_output_filename(self):
        current = self._output_field.getText().strip() if hasattr(self, "_output_field") else ""
        name = os.path.basename(current) if current else ""
        if name:
            return name
        if hasattr(self, "_fmt_jsonl") and self._fmt_jsonl.isSelected():
            return "burp_traffic.jsonl"
        return "burp_traffic.json"

    def _project_dir_should_skip(self, name):
        return name in self.PROJECT_SKIP_DIR_NAMES or name.startswith("$")

    def _matches_project_path(self, dirpath):
        norm = dirpath.replace("/", os.sep).replace("\\", os.sep)
        parts = [p for p in norm.split(os.sep) if p]
        if len(parts) < len(self.PROJECT_PATH_PARTS):
            return False
        return tuple(parts[-len(self.PROJECT_PATH_PARTS):]) == self.PROJECT_PATH_PARTS

    def _list_roots(self):
        try:
            roots = File.listRoots()
            paths = [str(r.getAbsolutePath()) for r in roots]
            if paths:
                return paths
        except Exception as e:
            _log_error("listing system roots: " + str(e))
        return [os.sep]

    def _search_project_dir_under(self, root):
        try:
            for dirpath, dirnames, _filenames in os.walk(root, topdown=True):
                dirnames[:] = [d for d in dirnames if not self._project_dir_should_skip(d)]
                if self._matches_project_path(dirpath):
                    return dirpath
        except Exception as e:
            _log_error("project dir search under {}: {}".format(root, e))
        return None

    def _search_project_dir(self):
        for root in self._list_roots():
            found = self._search_project_dir_under(root)
            if found:
                return found
        return None

    def _apply_project_dir(self, directory, created):
        def _do():
            filename = self._default_output_filename()
            path = os.path.join(directory, filename)
            self._output_field.setText(path)
        SwingUtilities.invokeLater(_do)
        if created:
            _log_info("Scan-Results folder not found anywhere on this system, created: " + directory)
        else:
            _log_info("Project Scan-Results folder found: " + directory)

    def _use_project_dir(self, manual=False):
        if self._running:
            return

        def _set_project_btn(text, enabled):
            if hasattr(self, "_project_btn"):
                def _do():
                    self._project_btn.setText(text)
                    self._project_btn.setEnabled(enabled)
                SwingUtilities.invokeLater(_do)

        def _worker():
            if manual:
                _set_project_btn("Searching...", False)
            try:
                found = self._search_project_dir()
                created = False
                if not found:
                    fallback = os.path.join(self._own_dir(), "Scan-Results")
                    try:
                        if not os.path.isdir(fallback):
                            os.makedirs(fallback)
                    except Exception as e:
                        _log_error("creating fallback Scan-Results dir: " + str(e))
                    found = fallback
                    created = True
                self._apply_project_dir(found, created)
            finally:
                if manual:
                    _set_project_btn("Project", True)

        t = threading.Thread(target=_worker)
        t.daemon = True
        t.start()

    def _start_project_autodetect(self):
        self._use_project_dir(manual=True)

    def _set_api_status(self, text, color, button):
        def _do():
            self._burp_api_status_lbl.setText(text)
            self._burp_api_status_lbl.setForeground(color)
            self._burp_api_connect_btn.setText(button)
        SwingUtilities.invokeLater(_do)

    def _parse_api_addr(self):
        addr = self._burp_api_field.getText().strip()
        if ":" in addr:
            host, port = addr.rsplit(":", 1)
        else:
            host, port = addr, "30302"
        return host.strip() or "127.0.0.1", port.strip() or "30302"

    def _on_api_status(self, client, state, detail):
        # Fired from the ApiClient's background thread. Only act on it if
        # this is still the client currently in charge -- otherwise it's a
        # stale notification from a connection we already replaced.
        with self._api_lock:
            current = self._api_client
        if current is not client:
            return

        if state == "alive":
            self._set_api_status(
                "Connected (job={})".format(client.job_id), self._C_GREEN, "Disconnect")
            return

        if state == "degraded":
            self._set_api_status(
                "Reconnecting... ({})".format(detail or "heartbeat failed"),
                self._C_AMBER, "Disconnect")
            return

        if state == "lost":
            # The link is actually dead: drop it so the status stops lying
            # about being connected, and let auto-reconnect pick it back up
            # (unless the user explicitly disconnected).
            with self._api_lock:
                if self._api_client is client:
                    self._api_client = None
            self._set_api_status(
                "Disconnected (connection lost)", self._C_RED, "Connect")
            _log_error("Burp API connection lost: " + str(detail))

    def _connect_api(self):
        with self._api_lock:
            if self._api_client:
                return True
            host, port = self._parse_api_addr()
            client = ApiClient(host, port)
            client._on_status = lambda state, detail: self._on_api_status(client, state, detail)
            try:
                job_id = client.start()
            except Exception as e:
                self._set_api_status("Connection failed: " + str(e), self._C_RED, "Connect")
                _log_error("Burp API connect: " + str(e))
                return False
            self._api_client = client
        self._set_api_status("Connected (job={})".format(job_id), self._C_GREEN, "Disconnect")
        _log_info("Burp API connected. host={} port={} job_id={}".format(host, port, job_id))
        return True

    def _disconnect_api(self):
        with self._api_lock:
            client = self._api_client
            self._api_client = None
        if client:
            client.stop()
        self._set_api_status("Disconnected", Color(0xADB5BD), "Connect")
        _log_info("Burp API disconnected.")

    def _toggle_burp_api(self):
        if self._api_client:
            self._api_manual_off = True
            self._disconnect_api()
            return
        self._api_manual_off = False
        self._connect_api()

    def _start_api_autoconnect(self):
        def _loop():
            while not self._api_auto_stop:
                if self._api_client is None and not self._api_manual_off:
                    try:
                        self._connect_api()
                    except Exception as e:
                        _log_error("api auto-connect: " + str(e))
                time.sleep(5)
        t = threading.Thread(target=_loop)
        t.daemon = True
        t.start()

    def _set_locked(self, locked):
        for c in self._locked:
            c.setEnabled(not locked)

    def _on_js_found(self, total):
        def _do():
            self._js_lbl.setText("{} JS file{} extracted".format(total, "s" if total != 1 else ""))
        SwingUtilities.invokeLater(_do)

    def _start(self):
        if self._running:
            return
        domain   = self._domain_field.getText().strip() or None
        fmt_default = "burp_traffic.jsonl" if self._fmt_jsonl.isSelected() else "burp_traffic.json"
        output   = self._output_field.getText().strip() or fmt_default
        methods  = [m for m, cb in self._method_checks.items() if cb.isSelected()] or None
        statuses = [s for s, cb in self._status_checks.items() if cb.isSelected()] or None
        preview  = int(self._body_spinner.getValue())
        fmt = "jsonl" if self._fmt_jsonl.isSelected() else "json"

        try:
            self._exporter = JsonExporter(output_path=output, fmt=fmt)
            self._js = None
            if self._js_check.isSelected():
                self._js = JsExtractor(output_path=output, on_new=self._on_js_found)
        except Exception as e:
            _log_error("start: " + str(e))
            self._status_text.setText("Error: " + str(e))
            self._status_text.setForeground(self._C_RED)
            return

        self._engine = Engine(
            exporter=self._exporter, domain=domain,
            methods=methods, status_filter=statuses,
            body_preview=preview, on_entry=self._add_row,
            js_extractor=self._js,
            include_body=self._body_preview_check.isSelected()
        )
        self._listener.set_engine(self._engine)

        self._running = True
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._set_locked(True)

        self._js_lbl.setText("0 JS files extracted")
        self._status_dot.setForeground(self._C_GREEN)
        self._status_text.setText("Running")
        self._status_text.setForeground(self._C_GREEN)
        _log_info("Started. domain={} output={} format={} js={} body_preview={}".format(
            domain, output, fmt.upper(), "on" if self._js else "off",
            "on" if self._body_preview_check.isSelected() else "off"))

    def _stop(self):
        if not self._running:
            return
        self._listener.set_engine(None)
        self._running = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._set_locked(False)

        self._status_dot.setForeground(self._C_RED)
        self._status_text.setText("Stopped")
        self._status_text.setForeground(Color(0x495057))
        _log_info("Stopped.")

    def _clear(self):
        self._table_model.setRowCount(0)
        self._reset_url_column()
        self._counter_lbl.setText("0 requests captured")
        self._js_lbl.setText("0 JS files extracted")
        self._target_lbl.setText("")
        if self._engine:   self._engine.reset()
        if self._exporter: self._exporter.clear()
        if self._js:       self._js.clear()

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
            self._fit_url_column(req["url"])
            n = self._table_model.getRowCount()
            self._counter_lbl.setText("{} request{} captured".format(n, "s" if n != 1 else ""))
            if target:
                self._target_lbl.setText(target)
            self._table.scrollRectToVisible(
                self._table.getCellRect(n - 1, 0, True)
            )
        SwingUtilities.invokeLater(_do)