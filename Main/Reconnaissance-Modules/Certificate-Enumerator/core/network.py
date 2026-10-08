import ssl
import socket
import select
import time as _time
from dataclasses import dataclass, field
from typing import Optional, Tuple, List


STARTTLS_GREETINGS = {
    "smtp": (b"220", b"EHLO tls-scanner\r\n", b"250", b"STARTTLS\r\n", b"220"),
    "ftp":  (b"220", b"AUTH TLS\r\n", b"234"),
    "imap": (b"* OK", b"a001 STARTTLS\r\n", b"a001 OK"),
    "pop3": (b"+OK", b"STLS\r\n", b"+OK"),
    "xmpp": (None,),
}

TLS_VERSION_MAP = {
    "SSLv2":   None,
    "SSLv3":   ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, "OP_NO_SSLv3") else None,
    "TLSv1.0": ssl.TLSVersion.TLSv1   if hasattr(ssl.TLSVersion, "TLSv1") else None,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None,
}


@dataclass
class ConnectionResult:
    success: bool
    version: Optional[str] = None
    cipher: Optional[Tuple] = None
    peer_cert_der: Optional[bytes] = None
    peer_cert_chain: List[bytes] = field(default_factory=list)
    alpn_protocol: Optional[str] = None
    error: Optional[str] = None
    handshake_time_ms: Optional[float] = None
    headers: Optional[dict] = None


class TLSConnection:
    def __init__(self, host: str, port: int, sni: str, timeout: float = 10.0,
                 starttls: Optional[str] = None):
        self.host = host
        self.port = port
        self.sni = sni
        self.timeout = timeout
        self.starttls = starttls

    def _resolve_host(self) -> str:
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror as e:
            raise ConnectionError(f"DNS resolution failed for {self.host}: {e}")

    def _do_starttls(self, sock: socket.socket, protocol: str) -> None:
        protocol = protocol.lower()
        if protocol == "smtp":
            self._read_until(sock, b"220")
            sock.sendall(b"EHLO tls-scanner\r\n")
            self._read_until(sock, b"250")
            sock.sendall(b"STARTTLS\r\n")
            self._read_until(sock, b"220")
        elif protocol == "ftp":
            self._read_until(sock, b"220")
            sock.sendall(b"AUTH TLS\r\n")
            self._read_until(sock, b"234")
        elif protocol == "imap":
            self._read_until(sock, b"* OK")
            sock.sendall(b"a001 STARTTLS\r\n")
            self._read_until(sock, b"a001 OK")
        elif protocol == "pop3":
            self._read_until(sock, b"+OK")
            sock.sendall(b"STLS\r\n")
            self._read_until(sock, b"+OK")

    def _read_until(self, sock: socket.socket, marker: bytes, max_bytes: int = 4096) -> bytes:
        data = b""
        while marker not in data:
            ready = select.select([sock], [], [], self.timeout)
            if not ready[0]:
                raise TimeoutError(f"Timeout waiting for {marker!r}")
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
        return data

    def connect(self,
                min_version: Optional[ssl.TLSVersion] = None,
                max_version: Optional[ssl.TLSVersion] = None,
                ciphers: Optional[str] = None,
                alpn_protocols: Optional[List[str]] = None,
                verify: bool = False) -> ConnectionResult:
        import time

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE if not verify else ssl.CERT_REQUIRED

        if min_version is not None:
            try:
                ctx.minimum_version = min_version
            except (AttributeError, ssl.SSLError):
                pass

        if max_version is not None:
            try:
                ctx.maximum_version = max_version
            except (AttributeError, ssl.SSLError):
                pass

        legacy_versions = set()
        if hasattr(ssl, "TLSVersion"):
            if hasattr(ssl.TLSVersion, "TLSv1"):
                legacy_versions.add(ssl.TLSVersion.TLSv1)
            if hasattr(ssl.TLSVersion, "TLSv1_1"):
                legacy_versions.add(ssl.TLSVersion.TLSv1_1)

        if min_version in legacy_versions or max_version in legacy_versions:
            ciphers = ciphers or "DEFAULT:@SECLEVEL=0"

        if ciphers:
            try:
                ctx.set_ciphers(ciphers)
            except ssl.SSLError:
                pass

        if alpn_protocols:
            try:
                ctx.set_alpn_protocols(alpn_protocols)
            except (AttributeError, ssl.SSLError):
                pass

        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return ConnectionResult(success=False, error=str(e))

        try:
            if self.starttls:
                self._do_starttls(raw_sock, self.starttls)

            t0 = time.monotonic()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
            handshake_ms = (time.monotonic() - t0) * 1000

            version = tls_sock.version()
            cipher = tls_sock.cipher()
            alpn = tls_sock.selected_alpn_protocol() if alpn_protocols else None

            cert_der = tls_sock.getpeercert(binary_form=True)

            chain = []
            try:
                import OpenSSL.SSL as ossl
                ossl_ctx = ossl.Context(ossl.TLS_CLIENT_METHOD)
                ossl_ctx.set_verify(ossl.VERIFY_NONE, lambda *a: True)
                ossl_conn = ossl.Connection(ossl_ctx, socket.create_connection(
                    (self.host, self.port), timeout=self.timeout))
                ossl_conn.set_tlsext_host_name(self.sni.encode())
                ossl_conn.set_connect_state()
                ossl_conn.do_handshake()
                for cert in ossl_conn.get_peer_cert_chain():
                    from OpenSSL.crypto import dump_certificate, FILETYPE_ASN1
                    chain.append(dump_certificate(FILETYPE_ASN1, cert))
                ossl_conn.close()
            except Exception:
                if cert_der:
                    chain = [cert_der]

            tls_sock.close()
            raw_sock.close()

            return ConnectionResult(
                success=True,
                version=version,
                cipher=cipher,
                peer_cert_der=cert_der,
                peer_cert_chain=chain,
                alpn_protocol=alpn,
                handshake_time_ms=round(handshake_ms, 2),
            )

        except ssl.SSLError as e:
            raw_sock.close()
            return ConnectionResult(success=False, error=f"SSL: {e.reason or str(e)}")
        except Exception as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=str(e))

    def fetch_http_headers(self) -> ConnectionResult:
        """Send an HTTP/1.1 GET request over TLS and return the response headers.

        Returns a :class:`ConnectionResult` where:
        - ``result.success`` is ``True`` if headers were retrieved.
        - ``result.headers`` is a ``dict`` of lowercased header names → values.
        - ``result.error`` contains a human-readable message on failure.
        """
        import time

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return ConnectionResult(success=False, error=str(e))

        try:
            t0 = time.monotonic()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
            handshake_ms = round((time.monotonic() - t0) * 1000, 2)

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Connection: close\r\n"
                f"User-Agent: TLS-Scanner/1.0\r\n"
                f"\r\n"
            )
            tls_sock.sendall(request.encode())

            # Read until the end of the headers section (\r\n\r\n)
            raw_response = b""
            while True:
                ready = select.select([tls_sock], [], [], self.timeout)
                if not ready[0]:
                    break
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                raw_response += chunk
                if b"\r\n\r\n" in raw_response:
                    break

            tls_sock.close()
            raw_sock.close()

            # Parse status line + headers
            header_section = raw_response.split(b"\r\n\r\n", 1)[0]
            lines = header_section.decode("utf-8", errors="replace").split("\r\n")

            if not lines or not lines[0].startswith("HTTP/"):
                return ConnectionResult(
                    success=False,
                    error=f"Unexpected response: {lines[0][:80] if lines else '(empty)'}",
                )

            headers: dict = {}
            for line in lines[1:]:
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()

            return ConnectionResult(
                success=True,
                headers=headers,
                handshake_time_ms=handshake_ms,
            )

        except ssl.SSLError as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=f"SSL: {e.reason or str(e)}")
        except Exception as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=str(e))

    def probe_cipher(self, cipher_name: str) -> ConnectionResult:
        """Probe whether a specific IANA cipher suite is accepted by the server.

        Strategy
        --------
        Python's ssl module uses OpenSSL cipher strings, not IANA names, so we
        try several translation approaches in order:

        1. TLS 1.3 ciphers  – passed via ``ctx.set_ciphers()`` using the
           OpenSSL TLS 1.3 name format (e.g. ``TLS_AES_256_GCM_SHA384``).
        2. TLS 1.2 and older – attempt an IANA-to-OpenSSL mapping via the
           ``ssl.IANA_to_OpenSSL_cipher_name`` helper (Python ≥ 3.10) or a
           built-in fallback table, then call ``ctx.set_ciphers()``.

        A successful handshake that negotiated *exactly* that cipher counts as
        supported.  If the cipher string is rejected by OpenSSL or the
        handshake fails, the method returns ``success=False``.
        """

        # ── Determine whether this is a TLS 1.3-only cipher ──────────────────
        _TLS13_PREFIX = ("TLS_AES_", "TLS_CHACHA20_")
        is_tls13 = any(cipher_name.upper().startswith(p) for p in _TLS13_PREFIX)

        # ── Translate IANA name → OpenSSL cipher string ───────────────────────
        openssl_name: Optional[str] = None

        # Python 3.10+ exposes the mapping directly
        if hasattr(ssl, "IANA_to_OpenSSL_cipher_name"):
            try:
                openssl_name = ssl.IANA_to_OpenSSL_cipher_name(cipher_name)
            except Exception:
                pass

        # Fallback: strip the IANA "TLS_" prefix and join with dashes
        # e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 → ECDHE-RSA-AES128-GCM-SHA256
        if not openssl_name:
            _IANA_REMAP = {
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       "ECDHE-RSA-AES256-GCM-SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       "ECDHE-RSA-AES128-GCM-SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":  "ECDHE-RSA-CHACHA20-POLY1305",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":     "ECDHE-ECDSA-AES256-GCM-SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":     "ECDHE-ECDSA-AES128-GCM-SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":"ECDHE-ECDSA-CHACHA20-POLY1305",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CCM":            "ECDHE-ECDSA-AES256-CCM",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CCM":            "ECDHE-ECDSA-AES128-CCM",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":     "ECDHE-ECDSA-AES256-SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":     "ECDHE-ECDSA-AES128-SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":       "ECDHE-RSA-AES256-SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":       "ECDHE-RSA-AES128-SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":        "ECDHE-ECDSA-AES256-SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":        "ECDHE-ECDSA-AES128-SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":          "ECDHE-RSA-AES256-SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":          "ECDHE-RSA-AES128-SHA",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384":         "DHE-RSA-AES256-GCM-SHA384",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":         "DHE-RSA-AES128-GCM-SHA256",
                "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   "DHE-RSA-CHACHA20-POLY1305",
                "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384":         "DHE-DSS-AES256-GCM-SHA384",
                "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256":         "DHE-DSS-AES128-GCM-SHA256",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256":         "DHE-RSA-AES256-SHA256",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256":         "DHE-RSA-AES128-SHA256",
                "TLS_DHE_RSA_WITH_AES_256_CBC_SHA":            "DHE-RSA-AES256-SHA",
                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA":            "DHE-RSA-AES128-SHA",
                "TLS_DHE_DSS_WITH_AES_256_CBC_SHA":            "DHE-DSS-AES256-SHA",
                "TLS_DHE_DSS_WITH_AES_128_CBC_SHA":            "DHE-DSS-AES128-SHA",
                "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA":           "EDH-DSS-DES-CBC3-SHA",
                "TLS_RSA_WITH_AES_256_GCM_SHA384":             "AES256-GCM-SHA384",
                "TLS_RSA_WITH_AES_128_GCM_SHA256":             "AES128-GCM-SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA256":             "AES256-SHA256",
                "TLS_RSA_WITH_AES_128_CBC_SHA256":             "AES128-SHA256",
                "TLS_RSA_WITH_AES_256_CBC_SHA":                "AES256-SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA":                "AES128-SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA":               "DES-CBC3-SHA",
                "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA":         "ECDH-ECDSA-AES256-SHA",
                "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA":         "ECDH-ECDSA-AES128-SHA",
                "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA":           "ECDH-RSA-AES256-SHA",
                "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA":           "ECDH-RSA-AES128-SHA",
                "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384":      "ECDH-ECDSA-AES256-GCM-SHA384",
                "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256":      "ECDH-ECDSA-AES128-GCM-SHA256",
                "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384":        "ECDH-RSA-AES256-GCM-SHA384",
                "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256":        "ECDH-RSA-AES128-GCM-SHA256",
                "TLS_RSA_WITH_RC4_128_SHA":                    "RC4-SHA",
                "TLS_RSA_WITH_RC4_128_MD5":                    "RC4-MD5",
                "TLS_RSA_WITH_NULL_SHA":                       "NULL-SHA",
                "TLS_RSA_WITH_NULL_MD5":                       "NULL-MD5",
                "TLS_RSA_EXPORT_WITH_RC4_40_MD5":              "EXP-RC4-MD5",
                "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA":           "EXP-DES-CBC-SHA",
                "TLS_RSA_WITH_DES_CBC_SHA":                    "DES-CBC-SHA",
                "SSL_RSA_WITH_RC4_128_SHA":                    "RC4-SHA",
                "SSL_RSA_WITH_RC4_128_MD5":                    "RC4-MD5",
                "SSL_RSA_WITH_3DES_EDE_CBC_SHA":               "DES-CBC3-SHA",
                "SSL_RSA_WITH_DES_CBC_SHA":                    "DES-CBC-SHA",
                "SSL_RSA_EXPORT_WITH_RC4_40_MD5":              "EXP-RC4-MD5",
                "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA":           "EXP-DES-CBC-SHA",
                "SSL_RSA_WITH_NULL_SHA":                       "NULL-SHA",
                "SSL_RSA_WITH_NULL_MD5":                       "NULL-MD5",
            }
            openssl_name = _IANA_REMAP.get(cipher_name)

        # ── Build the SSL context ─────────────────────────────────────────────
        import time as _time

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if is_tls13:
            # Python's ssl module generally has no portable set_ciphersuites()
            # API. We therefore cannot force a single TLS 1.3 suite here.
            # We still perform a TLS 1.3-only handshake, but the result is
            # considered a positive match only when the server actually
            # negotiates the requested suite. This avoids false positives.
            try:
                if not hasattr(ssl.TLSVersion, "TLSv1_3"):
                    return ConnectionResult(
                        success=False,
                        error="TLS 1.3 is unavailable in this Python/OpenSSL build",
                    )
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            except Exception as e:
                return ConnectionResult(success=False, error=f"TLS 1.3 probe unavailable: {e}")
        else:
            if openssl_name:
                # Disable TLS 1.3 so only the requested TLS ≤1.2 cipher is used.
                try:
                    if hasattr(ssl.TLSVersion, "TLSv1_3"):
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                except Exception:
                    ctx.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)

                cipher_str = openssl_name
                # Weak / legacy ciphers need a lower security level
                if any(k in cipher_name.upper() for k in ("RC4", "NULL", "EXPORT", "DES", "3DES")):
                    cipher_str = f"{openssl_name}:@SECLEVEL=0"
                try:
                    ctx.set_ciphers(cipher_str)
                except ssl.SSLError:
                    return ConnectionResult(
                        success=False,
                        error=f"OpenSSL rejected cipher string: {cipher_str}",
                    )
            else:
                return ConnectionResult(
                    success=False,
                    error=f"No OpenSSL mapping for cipher: {cipher_name}",
                )

        # ── Attempt the handshake ─────────────────────────────────────────────
        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return ConnectionResult(success=False, error=str(e))

        try:
            t0 = _time.monotonic()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
            handshake_ms = round((_time.monotonic() - t0) * 1000, 2)

            negotiated_cipher = tls_sock.cipher()   # (name, protocol, bits)
            version = tls_sock.version()
            cert_der = tls_sock.getpeercert(binary_form=True)
            tls_sock.close()
            raw_sock.close()

            if is_tls13 and (not negotiated_cipher or negotiated_cipher[0].upper() != cipher_name.upper()):
                return ConnectionResult(
                    success=False,
                    version=version,
                    cipher=negotiated_cipher,
                    peer_cert_der=cert_der,
                    error=(
                        f"TLS 1.3 handshake negotiated {negotiated_cipher[0] if negotiated_cipher else 'none'}, "
                        f"not requested {cipher_name}"
                    ),
                )

            return ConnectionResult(
                success=True,
                version=version,
                cipher=negotiated_cipher,
                peer_cert_der=cert_der,
                handshake_time_ms=handshake_ms,
            )

        except ssl.SSLError as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=f"SSL: {e.reason or str(e)}")
        except Exception as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=str(e))

    def probe_version(self, version_name: str) -> ConnectionResult:
        version_enum = TLS_VERSION_MAP.get(version_name)
        if version_enum is None and version_name not in ("SSLv2", "SSLv3"):
            return ConnectionResult(success=False, error=f"Version {version_name} not supported by this Python build")

        if version_name == "SSLv2":
            return ConnectionResult(success=False, error="SSLv2 probing not supported in this Python build")

        if version_name == "SSLv3":
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
                ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
                ctx.options |= getattr(ssl, "OP_NO_TLSv1_2", 0)
                ctx.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)
                raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
                tls_sock.close()
                return ConnectionResult(success=True, version="SSLv3")
            except Exception as e:
                return ConnectionResult(success=False, error=str(e))

        legacy = version_name in ("TLSv1.0", "TLSv1.1")
        ciphers = "DEFAULT:@SECLEVEL=0" if legacy else None
        return self.connect(min_version=version_enum, max_version=version_enum, ciphers=ciphers)

    # ── PFS probe methods ─────────────────────────────────────────────────────

    def probe_key_exchange(self, kex: str) -> "ConnectionResult":
        """Probe whether the server supports a given key-exchange algorithm.

        Tries to perform a TLS handshake using only cipher suites that use the
        requested key-exchange mechanism.  A successful handshake means the
        server accepted at least one such cipher.
        """
        # Map abstract KEX label → OpenSSL cipher filter string
        _KEX_TO_CIPHER: dict = {
            "ECDHE":    "ECDHE",
            "DHE":      "DHE:!ECDHE",
            "DHE_RSA":  "DHE-RSA",
            "DHE_DSS":  "DHE-DSS",
            "RSA":      "AES256-SHA:AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256",
            "ECDH":     "ECDH",
            "DH_DSS":   "DH-DSS",
            "DH_RSA":   "DH-RSA",
            "PSK":      "PSK",
            "SRP":      "SRP",
        }

        cipher_str = _KEX_TO_CIPHER.get(kex.upper(), kex)

        import time as _time
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # OpenSSL's set_ciphers() does not restrict TLS 1.3 cipher suites.
        # Keep this probe on TLS <= 1.2 so a TLS 1.3 ECDHE handshake cannot
        # be mistaken for the requested KEX.
        try:
            if hasattr(ssl.TLSVersion, "TLSv1_3"):
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass

        try:
            ctx.set_ciphers(cipher_str)
        except ssl.SSLError:
            return ConnectionResult(success=False, error=f"No ciphers for KEX: {kex}")

        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return ConnectionResult(success=False, error=str(e))

        try:
            t0 = _time.monotonic()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
            elapsed = round((_time.monotonic() - t0) * 1000, 2)
            cipher = tls_sock.cipher()
            version = tls_sock.version()
            cert_der = tls_sock.getpeercert(binary_form=True)
            tls_sock.close()
            raw_sock.close()
            return ConnectionResult(
                success=True,
                version=version,
                cipher=cipher,
                peer_cert_der=cert_der,
                handshake_time_ms=elapsed,
            )
        except ssl.SSLError as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=f"SSL: {e.reason or str(e)}")
        except Exception as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=str(e))

    def probe_ecdh_curve(self, curve: str) -> "ConnectionResult":
        """Probe whether the server accepts a specific named ECDHE curve.

        Uses OpenSSL's ``set_ecdh_auto`` (implicit) plus a targeted cipher list
        that forces ECDHE.  Where the Python ssl module exposes
        ``SSLContext.set_groups`` / ``set_curves`` (Python ≥ 3.10 / OpenSSL
        builds that expose that symbol) we restrict the curve explicitly;
        otherwise we fall back to just requesting ECDHE and checking the
        negotiated curve name in the handshake result.
        """
        import time as _time

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            ctx.set_ciphers("ECDHE")
        except ssl.SSLError:
            pass

        # Restrict to the requested curve where the API is available.
        # x25519 / x448 are modern Montgomery curves; OpenSSL's set_ecdh_curve
        # only knows legacy NIST names so we must use set_groups for those.
        _MONTGOMERY = {"x25519", "x448"}
        curve_lower = curve.lower()

        curve_set = False
        # Try set_groups first (Python ≥ 3.10 + OpenSSL 1.1+)
        if hasattr(ctx, "set_groups"):
            try:
                ctx.set_groups([curve_lower])
                curve_set = True
            except (ssl.SSLError, Exception):
                pass

        if not curve_set and curve_lower not in _MONTGOMERY:
            # Fall back to set_ecdh_curve for legacy NIST curves
            try:
                ctx.set_ecdh_curve(curve_lower)
                curve_set = True
            except (AttributeError, ssl.SSLError, Exception):
                pass

        if not curve_set:
            return ConnectionResult(
                success=False,
                error=f"Curve {curve!r} could not be set: not supported by this OpenSSL build",
            )

        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return ConnectionResult(success=False, error=str(e))

        try:
            t0 = _time.monotonic()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
            elapsed = round((_time.monotonic() - t0) * 1000, 2)
            cipher = tls_sock.cipher()
            version = tls_sock.version()
            cert_der = tls_sock.getpeercert(binary_form=True)

            negotiated_curve = None
            try:
                import OpenSSL.SSL as _ossl
                _octx = _ossl.Context(_ossl.TLS_CLIENT_METHOD)
                _octx.set_verify(_ossl.VERIFY_NONE, lambda *a: True)
                _osock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                _oconn = _ossl.Connection(_octx, _osock)
                _oconn.set_tlsext_host_name(self.sni.encode())
                _oconn.set_connect_state()
                _oconn.do_handshake()
                if hasattr(_oconn, "get_server_tmp_key"):
                    _tmp = _oconn.get_server_tmp_key()
                    if _tmp is not None and hasattr(_tmp, "type"):
                        negotiated_curve = getattr(_tmp, "name", None) or getattr(_tmp, "curve", None)
                try:
                    _oconn.shutdown()
                except Exception:
                    pass
                _oconn.close()
                _osock.close()
            except Exception:
                pass

            tls_sock.close()
            raw_sock.close()

            if negotiated_curve is not None:
                if negotiated_curve.lower() != curve_lower:
                    return ConnectionResult(
                        success=False,
                        version=version,
                        cipher=cipher,
                        peer_cert_der=cert_der,
                        error=f"Server negotiated {negotiated_curve!r} instead of requested {curve!r}",
                    )

            result = ConnectionResult(
                success=True,
                version=version,
                cipher=cipher,
                peer_cert_der=cert_der,
                handshake_time_ms=elapsed,
            )
            result.negotiated_group = negotiated_curve  # type: ignore[attr-defined]
            return result

        except ssl.SSLError as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=f"SSL: {e.reason or str(e)}")
        except Exception as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=str(e))

    def probe_dhe_handshake(self) -> "ConnectionResult":
        """Perform a DHE handshake and return the result.

        The DH parameter size (bits) is stored in ``result.extra["dhe_bits"]``
        when it can be determined from the negotiated cipher tuple.
        """
        import time as _time

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Force DHE-only cipher suites (no ECDHE)
        try:
            ctx.set_ciphers("DHE:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!SRP:!CAMELLIA")
        except ssl.SSLError:
            try:
                ctx.set_ciphers("DHE")
            except ssl.SSLError:
                return ConnectionResult(success=False, error="No DHE ciphers available in this OpenSSL build")

        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return ConnectionResult(success=False, error=str(e))

        try:
            t0 = _time.monotonic()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
            elapsed = round((_time.monotonic() - t0) * 1000, 2)
            cipher = tls_sock.cipher()   # (name, protocol, bits)
            version = tls_sock.version()
            cert_der = tls_sock.getpeercert(binary_form=True)
            tls_sock.close()
            raw_sock.close()

            # ``SSLSocket.cipher()[2]`` is symmetric-key strength, NOT the
            # finite-field DH parameter size.  Never label it as DH bits.
            dhe_bits = None
            try:
                from OpenSSL import SSL as _ossl_ssl
                from OpenSSL import crypto as _ossl_crypto

                octx = _ossl_ssl.Context(_ossl_ssl.TLS_CLIENT_METHOD)
                octx.set_verify(_ossl_ssl.VERIFY_NONE, lambda *a: True)
                osock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                oconn = _ossl_ssl.Connection(octx, osock)
                oconn.set_tlsext_host_name(self.sni.encode())
                oconn.set_connect_state()
                oconn.do_handshake()
                if hasattr(oconn, "get_server_tmp_key"):
                    tmp = oconn.get_server_tmp_key()
                    if tmp is not None and hasattr(tmp, "bits"):
                        bits = tmp.bits()
                        if isinstance(bits, int) and bits > 0:
                            dhe_bits = bits
                try:
                    oconn.shutdown()
                except Exception:
                    pass
                oconn.close()
                osock.close()
            except Exception:
                # Runtime/OpenSSL may not expose temporary-key inspection.
                # Keep the value unknown rather than guessing from cipher[2].
                dhe_bits = None

            result = ConnectionResult(
                success=True,
                version=version,
                cipher=cipher,
                peer_cert_der=cert_der,
                handshake_time_ms=elapsed,
            )
            # Attach extra data the PFS module expects
            result.extra = {"dhe_bits": dhe_bits}  # type: ignore[attr-defined]
            return result

        except ssl.SSLError as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=f"SSL: {e.reason or str(e)}")
        except Exception as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=str(e))

    def probe_ffdhe_group(self, group_name: str) -> "ConnectionResult":
        """Probe a specific finite-field DH named group when the runtime supports it.

        Important: ``SSLContext.set_ecdh_curve()`` only controls EC groups; it must
        not be used as a finite-field DH group selector.  On builds exposing
        ``set_groups()`` we use it, otherwise the method returns an explicit
        ``unsupported`` result instead of pretending that the requested FFDHE
        group was tested.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            if hasattr(ssl.TLSVersion, "TLSv1_3"):
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass

        try:
            ctx.set_ciphers("DHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0")
        except ssl.SSLError as e:
            return ConnectionResult(success=False, error=f"OpenSSL rejected DHE cipher: {e}")

        # Do not misuse set_ecdh_curve() for finite-field DH.
        if not hasattr(ctx, "set_groups"):
            return ConnectionResult(
                success=False,
                error=(
                    f"FFDHE group probing is unsupported by this Python/OpenSSL build; "
                    f"group {group_name!r} was not tested"
                ),
            )

        try:
            ctx.set_groups([group_name])
        except Exception as e:
            return ConnectionResult(
                success=False,
                error=f"Could not restrict TLS groups to {group_name!r}: {e}",
            )

        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return ConnectionResult(success=False, error=str(e))

        try:
            t0 = _time.monotonic()
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
            hs_ms = round((_time.monotonic() - t0) * 1000, 2)
            negotiated = tls_sock.cipher()
            version = tls_sock.version()
            cert_der = tls_sock.getpeercert(binary_form=True)

            # A successful DHE handshake under the restricted group is meaningful
            # only if a DHE cipher was actually negotiated.
            if not negotiated or "DHE" not in negotiated[0].upper() and "EDH" not in negotiated[0].upper():
                tls_sock.close()
                raw_sock.close()
                return ConnectionResult(
                    success=False,
                    error=f"Server did not negotiate DHE for group {group_name}",
                )

            tls_sock.close()
            raw_sock.close()
            result = ConnectionResult(
                success=True,
                version=version,
                cipher=negotiated,
                peer_cert_der=cert_der,
                handshake_time_ms=hs_ms,
            )
            result.extra = {"ffdhe_group": group_name}  # type: ignore[attr-defined]
            return result
        except ssl.SSLError as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=f"SSL: {e.reason or str(e)}")
        except Exception as e:
            try:
                raw_sock.close()
            except Exception:
                pass
            return ConnectionResult(success=False, error=str(e))

    def probe_cipher_preference(self) -> "ConnectionResult":
        """Determine the server's cipher preference order.

        Performs multiple handshakes, each time offering a single cipher from
        the full supported list, to infer which ciphers the server accepts and
        in what order it prefers them.

        The negotiated preference list is stored as ``result.preference``
        (a ``List[str]`` of cipher names in server-preferred order).
        """
        import time as _time

        # Collect all ciphers the server accepts
        _PROBE_CIPHERS = [
            # TLS 1.3
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            # ECDHE
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA",
            # DHE
            "DHE-RSA-AES256-GCM-SHA384",
            "DHE-RSA-AES128-GCM-SHA256",
            "DHE-RSA-AES256-SHA256",
            "DHE-RSA-AES128-SHA256",
            "DHE-RSA-AES256-SHA",
            "DHE-RSA-AES128-SHA",
            # RSA (non-PFS)
            "AES256-GCM-SHA384",
            "AES128-GCM-SHA256",
            "AES256-SHA256",
            "AES128-SHA256",
            "AES256-SHA",
            "AES128-SHA",
        ]

        accepted: list = []

        for cipher_name in _PROBE_CIPHERS:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # TLS 1.3 ciphers need special handling
            is_tls13 = cipher_name.startswith("TLS_")
            if not is_tls13:
                try:
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                except AttributeError:
                    pass
                try:
                    ctx.set_ciphers(cipher_name)
                except ssl.SSLError:
                    continue

            try:
                raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.sni)
                negotiated = tls_sock.cipher()
                tls_sock.close()
                raw_sock.close()
                if negotiated:
                    accepted.append(negotiated[0])
            except Exception:
                try:
                    raw_sock.close()
                except Exception:
                    pass

        if not accepted:
            return ConnectionResult(success=False, error="No ciphers accepted by server")

        result = ConnectionResult(success=True)
        result.preference = accepted  # type: ignore[attr-defined]
        return result

    def test_session_resumption(self, mode: str = "session_id") -> "ConnectionResult":
        """Test whether the server supports TLS session resumption.

        Parameters
        ----------
        mode:
            ``"session_id"``     – classic session-ID resumption (TLS ≤1.2)
            ``"session_ticket"`` – RFC 5077 session-ticket resumption (TLS ≤1.2)

        A successful result means the server resumed (or issued a ticket for)
        the second connection.  Extra data is stored in ``result.extra``:

        * For ``session_ticket``:
          ``{"ticket_present": bool, "ticket_lifetime_hours": int|None}``
        * For ``session_id``:
          ``{"session_id_present": bool}``
        """
        import time as _time

        if mode not in ("session_id", "session_ticket"):
            return ConnectionResult(success=False, error=f"Unknown resumption mode: {mode}")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Session tickets require TLS ≤1.2 (TLS 1.3 uses PSK, not RFC 5077)
        try:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            pass

        if mode == "session_ticket":
            # Enable session tickets (default in OpenSSL; just make sure it's on)
            ctx.options &= ~getattr(ssl, "OP_NO_TICKET", 0)
        else:
            # Disable tickets so the server falls back to session IDs
            ctx.options |= getattr(ssl, "OP_NO_TICKET", 0)

        # ── First handshake ───────────────────────────────────────────────────
        try:
            raw1 = socket.create_connection((self.host, self.port), timeout=self.timeout)
            tls1 = ctx.wrap_socket(raw1, server_hostname=self.sni)
            session1 = tls1.session  # ssl.SSLSession object (Python ≥ 3.6)
            tls1.close()
            raw1.close()
        except Exception as e:
            return ConnectionResult(success=False, error=f"First handshake failed: {e}")

        if session1 is None:
            return ConnectionResult(success=False, error="No session established on first handshake")

        # ── Second handshake — attempt resumption ────────────────────────────
        try:
            raw2 = socket.create_connection((self.host, self.port), timeout=self.timeout)
            tls2 = ctx.wrap_socket(raw2, server_hostname=self.sni, session=session1)
            resumed = tls2.session_reused
            cipher = tls2.cipher()
            version = tls2.version()
            tls2.close()
            raw2.close()
        except Exception as e:
            return ConnectionResult(success=False, error=f"Second handshake failed: {e}")

        if not resumed:
            return ConnectionResult(success=False, error="Session not resumed by server")

        # ── Build result ──────────────────────────────────────────────────────
        extra: dict = {}
        if mode == "session_ticket":
            ticket_hint = getattr(session1, "ticket_lifetime_hint", None)
            lifetime_h = round(ticket_hint / 3600) if ticket_hint else None
            extra = {
                "ticket_present": True,
                "ticket_lifetime_hours": lifetime_h,
            }
        else:
            extra = {"session_id_present": True}

        result = ConnectionResult(
            success=True,
            version=version,
            cipher=cipher,
            handshake_time_ms=None,
        )
        result.extra = extra  # type: ignore[attr-defined]
        return result