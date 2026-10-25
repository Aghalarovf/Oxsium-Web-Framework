import hashlib
import socket
import struct
import threading

from core.exceptions import ConnectionTimeout, TransportError
from protocol.smb.smb_constants import SMB2_FLAGS_SIGNED
from protocol.smb.smb_packet_parser import read_netbios_frame, wrap_netbios_frame
from protocol.smb.signing import compute_signature, derive_signing_key

PREAUTH_HASH_INITIAL = b"\x00" * 64


class SMBTransport:
    def __init__(self, host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self._sock = None
        self._lock = threading.Lock()
        self.message_id = 0
        self.session_id = 0
        self.tree_id = 0
        self.process_id = 0xFEFF
        self.negotiated_dialect = None
        self.max_transact_size = 0
        self.max_read_size = 0
        self.max_write_size = 0
        self.security_mode = 0
        self.server_guid = b""
        self.server_capabilities = 0
        self.signing_required = False
        self.signing_enabled = False

        # Preauthentication integrity (SMB 3.1.1): running SHA-512 hash over
        # the Negotiate and Session Setup exchange, accumulated regardless
        # of the negotiated dialect (it is simply unused when not 3.1.1).
        self.preauth_hash = PREAUTH_HASH_INITIAL

        # Populated once a session is fully established; while empty, no
        # outgoing packet is signed (matches pre-session-setup behavior).
        self.session_key = b""
        self.signing_key = b""

    def update_preauth_hash(self, data: bytes):
        self.preauth_hash = hashlib.sha512(self.preauth_hash + data).digest()

    def activate_signing(self, session_key: bytes):
        """Derive and store the per-dialect signing key for this session.

        Called once Session Setup completes successfully. Does nothing if
        the session has no usable session key (e.g. a true anonymous/null
        session established without an NTLM exchange), since there is no
        key material to sign with.
        """
        if not session_key:
            return
        self.session_key = session_key
        self.signing_key = derive_signing_key(
            self.negotiated_dialect, session_key, self.preauth_hash
        )

    def _sign(self, payload: bytes) -> bytes:
        if not self.signing_key:
            return payload

        packet = bytearray(payload)
        if len(packet) < 64:
            return payload

        flags = struct.unpack_from("<I", packet, 16)[0]
        flags |= SMB2_FLAGS_SIGNED
        struct.pack_into("<I", packet, 16, flags)
        packet[48:64] = b"\x00" * 16

        signature = compute_signature(self.negotiated_dialect, self.signing_key, bytes(packet))
        packet[48:64] = signature

        return bytes(packet)

    def connect(self):
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.connect_timeout
            )
            self._sock.settimeout(self.read_timeout)
        except socket.timeout as exc:
            raise ConnectionTimeout(f"Timeout connecting to {self.host}:{self.port}") from exc
        except OSError as exc:
            raise TransportError(f"Failed to connect to {self.host}:{self.port}: {exc}") from exc

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def next_message_id(self) -> int:
        with self._lock:
            current = self.message_id
            self.message_id += 1
            return current

    def send_raw(self, payload: bytes):
        if self._sock is None:
            raise TransportError("Transport is not connected")
        frame = wrap_netbios_frame(payload)
        try:
            self._sock.sendall(frame)
        except socket.timeout as exc:
            raise ConnectionTimeout("Timeout sending data") from exc
        except OSError as exc:
            raise TransportError(f"Send failed: {exc}") from exc

    def recv_raw(self) -> bytes:
        if self._sock is None:
            raise TransportError("Transport is not connected")
        try:
            return read_netbios_frame(self._sock, timeout=self.read_timeout)
        except socket.timeout as exc:
            raise ConnectionTimeout("Timeout receiving data") from exc
        except OSError as exc:
            raise TransportError(f"Receive failed: {exc}") from exc

    def send_and_recv(self, payload: bytes) -> bytes:
        self.send_raw(self._sign(payload))
        return self.recv_raw()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
