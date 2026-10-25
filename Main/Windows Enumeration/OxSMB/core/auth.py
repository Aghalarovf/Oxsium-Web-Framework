import re
from dataclasses import dataclass
from typing import Optional

from core.exceptions import AuthError, OxSMBError, SMBSessionSetupError

HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$")


@dataclass
class Credentials:
    username: str = ""
    password: str = ""
    domain: str = ""
    lm_hash: str = ""
    nt_hash: str = ""

    @property
    def is_anonymous(self) -> bool:
        return not self.username

    @property
    def is_null_session(self) -> bool:
        return not self.username and not self.password and not self.nt_hash

    @property
    def uses_hash(self) -> bool:
        return bool(self.nt_hash)

    @classmethod
    def from_args(cls, username, password, ntlm_hash, domain=""):
        lm_hash = ""
        nt_hash = ""
        if ntlm_hash:
            if not HASH_PATTERN.match(ntlm_hash):
                raise AuthError("Invalid NTLM hash format, expected LM:NT or NT")
            if ":" in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(":", 1)
            else:
                lm_hash = "0" * 32
                nt_hash = ntlm_hash
        return cls(
            username=username or "",
            password=password or "",
            domain=domain or "",
            lm_hash=lm_hash,
            nt_hash=nt_hash,
        )


class CredentialStore:
    def __init__(self):
        self._store = {}

    def add(self, target: str, credentials: Credentials):
        self._store[target] = credentials

    def get(self, target: str) -> Credentials:
        return self._store.get(target, Credentials())

    def __contains__(self, target: str) -> bool:
        return target in self._store


@dataclass
class AuthSession:
    host: str
    port: int
    credentials: Credentials
    transport: Optional[object] = None
    session_id: int = 0
    session_flags: int = 0
    is_guest: bool = False
    is_null: bool = False
    raw_status: Optional[int] = None
    authenticated: bool = False
    error: Optional[str] = None


def establish_session(
    host: str,
    port: int,
    credentials: Credentials,
    connect_timeout: float = 5.0,
    read_timeout: float = 5.0,
) -> AuthSession:
    from core.smb_transport import SMBTransport
    from protocol.smb.smb_negotiate import negotiate
    from protocol.smb.smb_session_setup import session_setup

    transport = SMBTransport(
        host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout
    )

    try:
        transport.connect()
        negotiate(transport)
    except (OxSMBError, OSError) as exc:
        transport.close()
        return AuthSession(host=host, port=port, credentials=credentials, error=str(exc))

    try:
        result = session_setup(transport, credentials)
    except SMBSessionSetupError as exc:
        transport.close()
        return AuthSession(
            host=host,
            port=port,
            credentials=credentials,
            raw_status=exc.status,
            error=str(exc),
        )
    except (OxSMBError, OSError) as exc:
        transport.close()
        return AuthSession(host=host, port=port, credentials=credentials, error=str(exc))

    return AuthSession(
        host=host,
        port=port,
        credentials=credentials,
        transport=transport,
        session_id=result.session_id,
        session_flags=result.session_flags,
        is_guest=result.is_guest,
        is_null=result.is_null,
        raw_status=0,
        authenticated=True,
    )


def close_session(auth_session: Optional[AuthSession]):
    if auth_session is not None and auth_session.transport is not None:
        auth_session.transport.close()
        auth_session.transport = None
