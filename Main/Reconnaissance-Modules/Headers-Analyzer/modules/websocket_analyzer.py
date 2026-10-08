import base64
import binascii
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

from .base import BaseHeaderModule
from core.engine import ModuleResult
from core.intercept_reader import HTTPResponse


MODULE_NAME = "WebSocket Handshake Analyzer"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "OK": 5}

REJECTION_MEANINGS: Dict[int, Tuple[str, str]] = {
    200: ("LOW", "the server answered with a regular 200 response; the endpoint may not speak WebSocket, or an intermediary stripped the Upgrade headers"),
    301: ("LOW", "redirect; WebSocket clients do not follow redirects during the handshake, so the connection fails"),
    302: ("LOW", "redirect; WebSocket clients do not follow redirects during the handshake, so the connection fails"),
    307: ("LOW", "redirect; WebSocket clients do not follow redirects during the handshake, so the connection fails"),
    308: ("LOW", "redirect; WebSocket clients do not follow redirects during the handshake, so the connection fails"),
    400: ("MEDIUM", "Bad Request; the handshake headers are malformed or missing (Sec-WebSocket-Key, Sec-WebSocket-Version, Upgrade, Connection) or the version is unsupported"),
    401: ("INFO", "authentication is required before the upgrade is allowed"),
    403: ("INFO", "the handshake was refused, typically by Origin validation or an authorization check"),
    404: ("LOW", "no WebSocket endpoint exists at this path"),
    405: ("LOW", "Method Not Allowed; the WebSocket handshake must use GET"),
    426: ("INFO", "Upgrade Required; the server demands a different protocol or Sec-WebSocket-Version"),
    429: ("LOW", "the handshake was rate limited"),
    500: ("MEDIUM", "the server failed while processing the handshake"),
    502: ("MEDIUM", "the reverse proxy could not reach a WebSocket-capable backend"),
    503: ("LOW", "the WebSocket service is unavailable"),
    504: ("LOW", "the backend timed out during the handshake"),
}

KNOWN_SUBPROTOCOLS: Dict[str, Tuple[str, str, str]] = {
    "graphql-ws": ("GraphQL over WebSocket (legacy subscriptions-transport-ws)", "INFO", "test whether connection_init authentication is enforced and whether introspection is enabled"),
    "graphql-transport-ws": ("GraphQL over WebSocket (graphql-ws)", "INFO", "test whether connection_init authentication is enforced and whether introspection is enabled"),
    "v10.stomp": ("STOMP 1.0", "INFO", "test SUBSCRIBE and SEND destinations for missing authorization"),
    "v11.stomp": ("STOMP 1.1", "INFO", "test SUBSCRIBE and SEND destinations for missing authorization"),
    "v12.stomp": ("STOMP 1.2", "INFO", "test SUBSCRIBE and SEND destinations for missing authorization"),
    "mqtt": ("MQTT over WebSocket", "INFO", "check broker authentication and topic ACLs"),
    "mqttv3.1": ("MQTT 3.1 over WebSocket", "INFO", "check broker authentication and topic ACLs"),
    "wamp.2.json": ("WAMP v2 (JSON)", "INFO", "check realm, procedure and topic authorization"),
    "wamp.2.msgpack": ("WAMP v2 (MessagePack)", "INFO", "check realm, procedure and topic authorization"),
    "vite-hmr": ("Vite HMR", "MEDIUM", "a development server socket is exposed; dev tooling should not be reachable outside local environments"),
    "xmpp": ("XMPP over WebSocket", "INFO", "check authentication mechanisms offered by the server"),
}

FRAMEWORK_SIGNATURES: List[Tuple[Any, str, str, str]] = [
    (re.compile(r"/socket\.io(/|$)"), "Socket.IO", "INFO", "the HTTP long-polling fallback on the same path usually exposes the same events and may bypass WebSocket-only controls"),
    (re.compile(r"/sockjs-node(/|$)"), "webpack-dev-server (SockJS)", "MEDIUM", "a development server socket is exposed; dev tooling should not be reachable outside local environments"),
    (re.compile(r"/sockjs(/|$)|/\d{1,3}/[a-z0-9_]{8}/websocket"), "SockJS", "INFO", "SockJS also exposes xhr and eventsource fallbacks on the same prefix"),
    (re.compile(r"/_next/webpack-hmr"), "Next.js HMR", "MEDIUM", "a development server socket is exposed; dev tooling should not be reachable outside local environments"),
    (re.compile(r"/_blazor(/|$|\?)"), "Blazor Server (SignalR)", "INFO", "circuit state lives server-side; test message tampering and circuit hijacking"),
    (re.compile(r"/signalr(/|$)|/negotiate"), "SignalR", "INFO", "review hub authorization and the connection token issued by /negotiate"),
    (re.compile(r"/cable(/|$|\?)"), "Rails Action Cable", "INFO", "verify allowed_request_origins and channel-level authorization"),
    (re.compile(r"/graphql"), "GraphQL over WebSocket", "INFO", "test authentication on connection_init and subscription authorization"),
    (re.compile(r"/stomp(/|$)|/gs-guide-websocket"), "STOMP / Spring messaging", "INFO", "test SUBSCRIBE and SEND destinations for missing authorization"),
    (re.compile(r"/mqtt(/|$|\?)"), "MQTT over WebSocket", "INFO", "check broker authentication and topic ACLs"),
    (re.compile(r"/cometd(/|$)"), "CometD", "INFO", "review channel authorization"),
    (re.compile(r"/faye(/|$)"), "Faye", "INFO", "review channel authorization and extension-based authentication"),
    (re.compile(r"/connection/websocket"), "Centrifugo", "INFO", "review channel permissions and token expiry"),
    (re.compile(r"/livereload"), "LiveReload", "MEDIUM", "a development server socket is exposed; dev tooling should not be reachable outside local environments"),
]

CREDENTIAL_PARAM = re.compile(
    r"(^|[_\-])(token|jwt|access_?token|id_?token|auth|authorization|bearer|api_?key|apikey|key|secret|password|passwd|sid|session|sessionid|sig|signature)($|[_\-])",
    re.IGNORECASE,
)
ANTI_CSRF_PARAM = re.compile(r"csrf|xsrf|nonce", re.IGNORECASE)
JWT_LIKE = re.compile(r"^eyJ[\w\-]+\.[\w\-]+\.[\w\-]*$")


def _tokens(value: Optional[str]) -> List[str]:
    return [item.strip().lower() for item in (value or "").split(",") if item.strip()]


def _extension_names(value: Optional[str]) -> List[str]:
    return [part.split(";")[0].strip().lower() for part in (value or "").split(",") if part.strip()]


def _host_port(value: Optional[str], default_port: int) -> Tuple[str, int]:
    text = (value or "").strip().lower()
    port_text = ""
    if text.startswith("["):
        end = text.find("]")
        host = text[1:end] if end != -1 else text
        rest = text[end + 1:] if end != -1 else ""
        port_text = rest[1:] if rest.startswith(":") else ""
    elif text.count(":") == 1:
        host, _, port_text = text.partition(":")
    else:
        host = text
    return host, int(port_text) if port_text.isdigit() else default_port


def _site_key(host: str) -> str:
    labels = host.split(".")
    if len(labels) < 2 or all(label.isdigit() for label in labels):
        return host
    return ".".join(labels[-2:])


def _cookie_names(cookie_header: Optional[str]) -> List[str]:
    names = []
    for part in (cookie_header or "").split(";"):
        name = part.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


class Handshake:
    def __init__(self, response: HTTPResponse):
        self.response = response
        self.req = response.request_headers
        self.res = response.headers
        self.method = (response.method or "GET").upper()
        self.status = response.status_code
        self.http_version = response.http_version or ""

        parts = urlsplit(response.url or "")
        raw_scheme = parts.scheme.lower()
        self.scheme = {"https": "wss", "http": "ws", "wss": "wss", "ws": "ws"}.get(raw_scheme, raw_scheme or "ws")
        default_port = 443 if self.scheme == "wss" else 80
        self.host, self.port = _host_port(self.req.get("host") or parts.netloc, default_port)
        self.path = parts.path or "/"
        self.query = parts.query
        self.query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        self.endpoint = f"{self.scheme}://{self.host}{'' if self.port == default_port else ':' + str(self.port)}{self.path}"

        self.is_extended_connect = self.method == "CONNECT" and self.req.get(":protocol", "").lower() == "websocket"
        self.accepted = self.status == 101 or (self.is_extended_connect and self.status == 200)

        self.origin = self.req.get("origin")
        self.origin_relation = self._origin_relation()

        self.offered_protocols = [item.strip() for item in (self.req.get("sec-websocket-protocol") or "").split(",") if item.strip()]
        selected = (self.res.get("sec-websocket-protocol") or "").strip()
        self.selected_protocol = selected or None
        self.offered_extensions = _extension_names(self.req.get("sec-websocket-extensions"))
        self.selected_extensions = _extension_names(self.res.get("sec-websocket-extensions"))

        self.cookie_names = _cookie_names(self.req.get("cookie"))
        self.credential_params = [name for name, _ in self.query_pairs if CREDENTIAL_PARAM.search(name) and not ANTI_CSRF_PARAM.search(name)]
        self.csrf_params = [name for name, _ in self.query_pairs if ANTI_CSRF_PARAM.search(name)]
        self.csrf_headers = [name for name in self.req if ANTI_CSRF_PARAM.search(name)]
        self.has_authorization = "authorization" in self.req

    def _origin_relation(self) -> str:
        if not self.origin:
            return "absent"
        text = self.origin.strip()
        if text.lower() == "null":
            return "null"
        try:
            parsed = urlsplit(text)
            origin_host = (parsed.hostname or "").lower()
            origin_scheme = parsed.scheme.lower()
            origin_port = parsed.port or (443 if origin_scheme == "https" else 80)
        except ValueError:
            return "malformed"
        if not origin_host:
            return "malformed"
        page_scheme = "https" if self.scheme == "wss" else "http"
        if origin_host == self.host and origin_port == self.port:
            return "same-origin" if origin_scheme == page_scheme else "same-host-different-scheme"
        if _site_key(origin_host) == _site_key(self.host):
            return "sibling-host"
        return "cross-origin"

    def authentication_modes(self) -> List[str]:
        modes = []
        if self.cookie_names:
            modes.append("cookie")
        if self.has_authorization:
            modes.append("authorization-header")
        if self.credential_params:
            modes.append("url-token")
        if self.csrf_params or self.csrf_headers:
            modes.append("anti-csrf-token")
        if any(JWT_LIKE.match(item) for item in self.offered_protocols):
            modes.append("subprotocol-token")
        return modes


class WebSocketModule(BaseHeaderModule):
    name = MODULE_NAME
    description = "Detects WebSocket upgrade handshakes (101 Switching Protocols and related outcomes) and audits transport, Origin validation, authentication model, negotiated protocols and RFC 6455 conformance."

    def applies_to(self, response: HTTPResponse) -> bool:
        return self._classify(response) is not None

    def _classify(self, response: HTTPResponse) -> Optional[str]:
        req = response.request_headers
        res = response.headers
        url = (response.url or "").lower()
        signals = (
            "websocket" in _tokens(req.get("upgrade"))
            or "sec-websocket-key" in req
            or "sec-websocket-version" in req
            or req.get(":protocol", "").lower() == "websocket"
            or "websocket" in _tokens(res.get("upgrade"))
            or "sec-websocket-accept" in res
            or url.startswith(("ws://", "wss://"))
        )
        if signals:
            return "websocket"
        if response.status_code == 101:
            return "upgrade"
        return None

    def run(self, response: HTTPResponse) -> ModuleResult:
        result = ModuleResult(self.name)
        kind = self._classify(response)
        if kind is None:
            result.add_finding("INFO", "WebSocket", "No WebSocket handshake detected in this entry")
            return result

        hs = Handshake(response)

        if kind == "upgrade":
            self._check_other_upgrade(hs, result)
            result.metadata["websocket"] = self._metadata(hs, kind, None)
            return result

        self._check_outcome(hs, result)
        self._check_transport(hs, result)
        self._check_request(hs, result)
        accept_valid = None
        if hs.accepted and not hs.is_extended_connect:
            accept_valid = self._check_accept(hs, result)
            self._check_response_headers(hs, result)
        self._check_origin(hs, result)
        if hs.accepted:
            self._check_authentication(hs, result)
        self._check_url_credentials(hs, result)
        if hs.accepted:
            self._check_subprotocol(hs, result)
            self._check_extensions(hs, result)
            self._check_set_cookie(hs, result)
        self._check_fingerprint(hs, result)

        result.metadata["websocket"] = self._metadata(hs, kind, accept_valid)
        return result

    def _plain_endpoint(self, hs: Handshake) -> str:
        parts = urlsplit(hs.response.url or "")
        return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}" if parts.scheme else hs.endpoint

    def _metadata(self, hs: Handshake, kind: str, accept_valid: Optional[bool]) -> Dict[str, Any]:
        framework = self._fingerprint(hs)
        plain = kind == "upgrade"
        return {
            "kind": kind,
            "endpoint": self._plain_endpoint(hs) if plain else hs.endpoint,
            "scheme": (urlsplit(hs.response.url or "").scheme or hs.scheme) if plain else hs.scheme,
            "host": hs.host,
            "port": hs.port,
            "path": hs.path,
            "method": hs.method,
            "status_code": hs.status,
            "http_version": hs.http_version,
            "outcome": ("accepted" if hs.accepted else "rejected") if kind == "websocket" else "protocol-switch",
            "origin": hs.origin,
            "origin_relation": hs.origin_relation,
            "subprotocols_offered": hs.offered_protocols,
            "subprotocol_selected": hs.selected_protocol,
            "extensions_offered": hs.offered_extensions,
            "extensions_selected": hs.selected_extensions,
            "authentication": hs.authentication_modes(),
            "framework": framework[0] if framework else None,
            "accept_valid": accept_valid,
        }

    def _check_other_upgrade(self, hs: Handshake, result: ModuleResult):
        target = ", ".join(_tokens(hs.res.get("upgrade"))) or "unspecified protocol"
        result.add_finding("INFO", "Upgrade", f"101 Switching Protocols to '{target}' on {self._plain_endpoint(hs)}; this is not a WebSocket upgrade")
        if "h2c" in _tokens(hs.res.get("upgrade")):
            result.add_finding("LOW", "Upgrade", "h2c (cleartext HTTP/2) upgrade accepted; behind a reverse proxy this can enable h2c smuggling and access-control bypass")

    def _check_outcome(self, hs: Handshake, result: ModuleResult):
        if hs.accepted:
            if hs.is_extended_connect:
                result.add_finding("OK", "Upgrade", f"WebSocket over HTTP/2 accepted via extended CONNECT (RFC 8441), status {hs.status}, on {hs.endpoint}")
            else:
                result.add_finding("OK", "Upgrade", f"Handshake accepted: 101 Switching Protocols, connection upgraded to WebSocket on {hs.endpoint}")
            return

        severity, meaning = REJECTION_MEANINGS.get(hs.status, self._generic_rejection(hs.status))
        result.add_finding(severity, "Upgrade", f"Handshake NOT completed: status {hs.status}; {meaning}")
        if hs.status == 426 and hs.res.get("sec-websocket-version"):
            result.add_finding("INFO", "Sec-WebSocket-Version", f"Server advertises supported version(s): {hs.res['sec-websocket-version']}")
        if 300 <= hs.status < 400 and hs.res.get("location"):
            result.add_finding("INFO", "Location", f"Redirect target: {hs.res['location']}")
        if hs.status == 101:
            result.add_finding("MEDIUM", "Upgrade", "101 returned without a WebSocket upgrade context; verify the negotiated protocol")

    def _generic_rejection(self, status: int) -> Tuple[str, str]:
        if 500 <= status < 600:
            return "MEDIUM", "server-side failure during the handshake"
        if 400 <= status < 500:
            return "LOW", "the server refused the handshake"
        if 200 <= status < 300:
            return "LOW", "the server answered with a regular success response instead of switching protocols"
        if 100 <= status < 200:
            return "INFO", "informational response; not a completed upgrade"
        return "LOW", "unexpected status for a WebSocket handshake"

    def _check_transport(self, hs: Handshake, result: ModuleResult):
        if hs.scheme == "ws":
            result.add_finding("HIGH", "Transport", "Cleartext ws:// endpoint; frames, cookies and tokens can be read or modified by a network attacker")
        elif hs.scheme == "wss":
            result.add_finding("OK", "Transport", "Encrypted transport (wss://)")

    def _check_request(self, hs: Handshake, result: ModuleResult):
        req = hs.req
        is_h1_handshake = not hs.is_extended_connect and hs.http_version != "HTTP/2"

        if hs.is_extended_connect:
            result.add_finding("INFO", "Method", "HTTP/2 extended CONNECT with :protocol websocket (RFC 8441)")
        elif hs.http_version == "HTTP/2":
            result.add_finding("LOW", "HTTP Version", "Upgrade-style handshake observed over HTTP/2; Connection/Upgrade headers are not valid in HTTP/2 and WebSocket over HTTP/2 requires extended CONNECT")
        elif hs.method != "GET":
            result.add_finding("MEDIUM", "Method", f"Handshake used {hs.method}; RFC 6455 requires GET")

        if is_h1_handshake:
            missing = []
            if "websocket" not in _tokens(req.get("upgrade")):
                missing.append("Upgrade: websocket")
            if "upgrade" not in _tokens(req.get("connection")):
                missing.append("Connection: Upgrade")
            if "sec-websocket-key" not in req:
                missing.append("Sec-WebSocket-Key")
            if "sec-websocket-version" not in req:
                missing.append("Sec-WebSocket-Version")
            if missing:
                if hs.accepted:
                    result.add_finding("LOW", "Request Headers", f"Server accepted a handshake missing: {', '.join(missing)} (lenient parser)")
                else:
                    result.add_finding("MEDIUM", "Request Headers", f"Request is not a valid RFC 6455 handshake, missing: {', '.join(missing)}")

            key = req.get("sec-websocket-key")
            if key:
                try:
                    valid_key = len(base64.b64decode(key, validate=True)) == 16
                except (binascii.Error, ValueError):
                    valid_key = False
                if not valid_key:
                    result.add_finding("LOW", "Sec-WebSocket-Key", "Key is not a base64-encoded 16-byte value as required by RFC 6455")

        version = req.get("sec-websocket-version")
        if version and version.strip() != "13":
            result.add_finding("LOW", "Sec-WebSocket-Version", f"Client requested version {version.strip()}; RFC 6455 defines version 13")

    def _check_accept(self, hs: Handshake, result: ModuleResult) -> Optional[bool]:
        accept = hs.res.get("sec-websocket-accept")
        key = hs.req.get("sec-websocket-key")
        if not accept:
            result.add_finding("MEDIUM", "Sec-WebSocket-Accept", "101 response has no Sec-WebSocket-Accept header; compliant clients will reject the handshake")
            return False
        if not key:
            result.add_finding("INFO", "Sec-WebSocket-Accept", "Present, but the request key is unavailable so the value cannot be verified")
            return None
        expected = base64.b64encode(hashlib.sha1((key.strip() + WS_GUID).encode("ascii", "ignore")).digest()).decode("ascii")
        if accept.strip() == expected:
            result.add_finding("OK", "Sec-WebSocket-Accept", "Value is valid: base64(SHA-1(Sec-WebSocket-Key + RFC 6455 GUID)) verified")
            return True
        result.add_finding("MEDIUM", "Sec-WebSocket-Accept", f"Value does not match the request key (expected {expected}); the response may have been altered or produced by a non-compliant server")
        return False

    def _check_response_headers(self, hs: Handshake, result: ModuleResult):
        res = hs.res
        if "websocket" not in _tokens(res.get("upgrade")):
            result.add_finding("MEDIUM", "Upgrade", "101 response lacks 'Upgrade: websocket'")
        if "upgrade" not in _tokens(res.get("connection")):
            result.add_finding("MEDIUM", "Connection", "101 response lacks 'Connection: Upgrade'")
        length = res.get("content-length")
        if length is not None:
            if length.strip() == "0":
                result.add_finding("INFO", "Content-Length", "Content-Length: 0 sent on a 101 response; servers should not send Content-Length in 1xx responses, though most clients tolerate it")
            else:
                result.add_finding("MEDIUM", "Content-Length", f"101 response declares a body (Content-Length: {length.strip()}); the connection switches protocols immediately so this can desynchronize intermediaries")
        if "transfer-encoding" in res:
            result.add_finding("LOW", "Transfer-Encoding", "Transfer-Encoding on a 101 response is invalid and can confuse intermediaries")

    def _check_origin(self, hs: Handshake, result: ModuleResult):
        relation = hs.origin_relation
        origin = hs.origin
        if hs.accepted:
            if relation == "absent":
                result.add_finding("LOW", "Origin", "Accepted handshake carries no Origin header; a non-browser client, or Origin validation cannot be assumed")
            elif relation == "same-origin":
                result.add_finding("INFO", "Origin", f"Origin {origin} matches the endpoint; cross-origin behavior is not proven, replay the handshake with a foreign Origin to test for Cross-Site WebSocket Hijacking")
            elif relation == "same-host-different-scheme":
                result.add_finding("LOW", "Origin", f"Origin {origin} shares the host but not the scheme and was accepted")
            elif relation == "sibling-host":
                result.add_finding("MEDIUM", "Origin", f"Handshake from sibling host Origin {origin} was accepted; any XSS or takeover on a sibling host can hijack this socket")
            elif relation == "cross-origin":
                result.add_finding("HIGH", "Origin", f"Cross-Site WebSocket Hijacking: handshake from foreign Origin {origin} was accepted")
            elif relation == "null":
                result.add_finding("HIGH", "Origin", "Handshake from Origin: null was accepted; sandboxed iframes and data: documents can open this socket")
            else:
                result.add_finding("LOW", "Origin", f"Origin header is malformed: {origin}")
        elif relation in ("cross-origin", "sibling-host", "null") and hs.status in (400, 401, 403):
            result.add_finding("OK", "Origin", f"Origin validation appears enforced: handshake from {origin} was rejected with {hs.status}")

    def _check_authentication(self, hs: Handshake, result: ModuleResult):
        modes = hs.authentication_modes()
        hijackable = hs.origin_relation in ("cross-origin", "null")
        if hs.cookie_names and not (set(modes) - {"cookie"}):
            severity = "HIGH" if hijackable else "MEDIUM"
            result.add_finding(
                severity,
                "Authentication",
                f"Handshake is authenticated by cookies only ({', '.join(hs.cookie_names)}); no anti-CSRF token, Authorization header or URL token was found, so it is exposed to Cross-Site WebSocket Hijacking unless the cookies are SameSite=Lax/Strict or Origin is validated",
            )
        elif hs.cookie_names:
            result.add_finding("INFO", "Authentication", f"Handshake combines cookies with {', '.join(m for m in modes if m != 'cookie')}")
        elif modes:
            result.add_finding("OK", "Authentication", f"Handshake authenticated via {', '.join(modes)}; browsers do not attach these cross-site automatically")
        else:
            result.add_finding("LOW", "Authentication", "Handshake carries no cookies or credentials; the endpoint is unauthenticated, or authentication happens inside the first frames")

    def _check_url_credentials(self, hs: Handshake, result: ModuleResult):
        if hs.credential_params:
            result.add_finding("MEDIUM", "URL", f"Credential-like parameter(s) in the WebSocket URL: {', '.join(sorted(set(hs.credential_params)))}; URLs leak through access logs, proxies and browser history")
        if hs.csrf_params:
            result.add_finding("OK", "URL", f"Anti-CSRF style parameter(s) present in the handshake URL: {', '.join(sorted(set(hs.csrf_params)))}")

    def _check_subprotocol(self, hs: Handshake, result: ModuleResult):
        offered = hs.offered_protocols
        selected = hs.selected_protocol
        if any(JWT_LIKE.match(item) for item in offered):
            result.add_finding("MEDIUM", "Sec-WebSocket-Protocol", "A JWT-like value is passed through Sec-WebSocket-Protocol; tokens smuggled through subprotocol slots are logged and echoed by servers")
        if selected and not offered:
            result.add_finding("MEDIUM", "Sec-WebSocket-Protocol", f"Server selected subprotocol '{selected}' although the client offered none (RFC 6455 violation)")
        elif selected and selected.lower() not in [item.lower() for item in offered]:
            result.add_finding("MEDIUM", "Sec-WebSocket-Protocol", f"Server selected '{selected}' which the client did not offer: {', '.join(offered)}")
        elif selected:
            result.add_finding("INFO", "Sec-WebSocket-Protocol", f"Negotiated subprotocol: {selected}")
            known = KNOWN_SUBPROTOCOLS.get(selected.lower())
            if known:
                result.add_finding(known[1], "Sec-WebSocket-Protocol", f"{known[0]}; {known[2]}")
        elif offered:
            result.add_finding("INFO", "Sec-WebSocket-Protocol", f"Client offered {', '.join(offered)} but the server selected none")

    def _check_extensions(self, hs: Handshake, result: ModuleResult):
        unrequested = [name for name in hs.selected_extensions if name not in hs.offered_extensions]
        if unrequested:
            result.add_finding("MEDIUM", "Sec-WebSocket-Extensions", f"Server negotiated extension(s) the client never requested: {', '.join(unrequested)}")
        if "permessage-deflate" in hs.selected_extensions:
            result.add_finding("LOW", "Sec-WebSocket-Extensions", "permessage-deflate negotiated; compression side channels (CRIME/BREACH style) are possible when secrets and attacker-controlled data share one compressed stream")
        elif hs.selected_extensions:
            result.add_finding("INFO", "Sec-WebSocket-Extensions", f"Negotiated extension(s): {', '.join(hs.selected_extensions)}")

    def _check_set_cookie(self, hs: Handshake, result: ModuleResult):
        if "set-cookie" in hs.res:
            result.add_finding("INFO", "Set-Cookie", "Server sets cookies during the upgrade response; review Secure, HttpOnly and SameSite attributes")

    def _path_fingerprint(self, hs: Handshake) -> Optional[Tuple[str, str, str]]:
        haystack = hs.path.lower() + ("?" + hs.query.lower() if hs.query else "")
        for pattern, name, severity, note in FRAMEWORK_SIGNATURES:
            if pattern.search(haystack):
                return name, severity, note
        return None

    def _fingerprint(self, hs: Handshake) -> Optional[Tuple[str, str, str]]:
        match = self._path_fingerprint(hs)
        if match:
            return match
        info = KNOWN_SUBPROTOCOLS.get((hs.selected_protocol or "").lower())
        return info if info else None

    def _check_fingerprint(self, hs: Handshake, result: ModuleResult):
        match = self._path_fingerprint(hs)
        if match:
            result.add_finding(match[1], "Fingerprint", f"{match[0]}; {match[2]}")


def build_overview(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    endpoints: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    totals = {"handshakes": 0, "accepted": 0, "rejected": 0, "other_upgrades": 0}

    for entry in entries:
        module = entry.get("modules", {}).get(MODULE_NAME)
        if not module or module.get("error"):
            continue
        meta = module.get("metadata", {}).get("websocket")
        if not meta:
            continue

        if meta["outcome"] == "protocol-switch":
            totals["other_upgrades"] += 1
        else:
            totals["handshakes"] += 1
            totals["accepted" if meta["outcome"] == "accepted" else "rejected"] += 1

        key = (meta["scheme"], meta["host"], meta["path"])
        bucket = endpoints.setdefault(key, {
            "endpoint": meta["endpoint"],
            "attempts": 0,
            "accepted": 0,
            "rejected": 0,
            "statuses": {},
            "origins": set(),
            "subprotocols": set(),
            "extensions": set(),
            "authentication": set(),
            "frameworks": set(),
            "entry_ids": [],
            "worst_severity": "OK",
        })
        bucket["attempts"] += 1
        if meta["outcome"] == "accepted":
            bucket["accepted"] += 1
        elif meta["outcome"] == "rejected":
            bucket["rejected"] += 1
        status_key = str(meta["status_code"])
        bucket["statuses"][status_key] = bucket["statuses"].get(status_key, 0) + 1
        if meta.get("origin"):
            bucket["origins"].add(f"{meta['origin']} ({meta['origin_relation']})")
        if meta.get("subprotocol_selected"):
            bucket["subprotocols"].add(meta["subprotocol_selected"])
        bucket["extensions"].update(meta.get("extensions_selected", []))
        bucket["authentication"].update(meta.get("authentication", []))
        if meta.get("framework"):
            bucket["frameworks"].add(meta["framework"])
        bucket["entry_ids"].append(entry["id"])
        for finding in module.get("findings", []):
            severity = finding.get("severity", "INFO")
            if SEVERITY_RANK.get(severity, 99) < SEVERITY_RANK.get(bucket["worst_severity"], 99):
                bucket["worst_severity"] = severity

    rows = []
    for bucket in endpoints.values():
        rows.append({
            "endpoint": bucket["endpoint"],
            "attempts": bucket["attempts"],
            "accepted": bucket["accepted"],
            "rejected": bucket["rejected"],
            "statuses": bucket["statuses"],
            "origins": sorted(bucket["origins"]),
            "subprotocols": sorted(bucket["subprotocols"]),
            "extensions": sorted(bucket["extensions"]),
            "authentication": sorted(bucket["authentication"]),
            "frameworks": sorted(bucket["frameworks"]),
            "entry_ids": bucket["entry_ids"],
            "worst_severity": bucket["worst_severity"],
        })
    rows.sort(key=lambda row: (SEVERITY_RANK.get(row["worst_severity"], 99), row["endpoint"]))

    return {
        "totals": totals,
        "endpoints": rows,
        "notes": ["Only handshakes can be analyzed from HTTP history exports; WebSocket frame contents are not part of the intercept file"],
    }


def print_overview(logger: Any, overview: Dict[str, Any]):
    totals = overview["totals"]
    logger.section("WebSocket Overview")
    if not overview["endpoints"]:
        logger.info("No WebSocket handshakes were detected in the intercept files.")
        return

    logger.info(
        f"Handshakes: {totals['handshakes']} (accepted={totals['accepted']}, rejected={totals['rejected']}); "
        f"other protocol switches: {totals['other_upgrades']}; endpoints: {len(overview['endpoints'])}"
    )
    for row in overview["endpoints"]:
        logger.subsection(row["endpoint"])
        statuses = ", ".join(f"{code} x{count}" for code, count in sorted(row["statuses"].items()))
        logger.result_line("Attempts", f"{row['attempts']} (accepted={row['accepted']}, rejected={row['rejected']})")
        logger.result_line("Statuses", statuses, highlight="101" in row["statuses"])
        logger.result_line("Worst severity", row["worst_severity"])
        if row["origins"]:
            logger.result_line("Origins", "; ".join(row["origins"]))
        if row["authentication"]:
            logger.result_line("Authentication", ", ".join(row["authentication"]))
        if row["subprotocols"]:
            logger.result_line("Subprotocols", ", ".join(row["subprotocols"]))
        if row["extensions"]:
            logger.result_line("Extensions", ", ".join(row["extensions"]))
        if row["frameworks"]:
            logger.result_line("Fingerprint", ", ".join(row["frameworks"]))
        logger.result_line("Entries", ", ".join(str(i) for i in row["entry_ids"]))
    for note in overview["notes"]:
        logger.warn(note)
