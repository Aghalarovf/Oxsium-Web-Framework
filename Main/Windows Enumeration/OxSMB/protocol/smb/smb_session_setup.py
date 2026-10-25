import struct
from dataclasses import dataclass

from core.auth import Credentials
from core.exceptions import SMBSessionSetupError
from core.smb_transport import SMBTransport
from protocol.smb.ntlm import (
    build_authenticate_message,
    build_negotiate_message,
    parse_challenge_message,
)
from protocol.smb.smb_constants import (
    SMB2_COM_SESSION_SETUP,
    SMB2_SESSION_FLAG_IS_GUEST,
    SMB2_SESSION_FLAG_IS_NULL,
    STATUS_MORE_PROCESSING_REQUIRED,
    STATUS_SUCCESS,
)
from protocol.smb.smb_packet_parser import build_smb2_header, split_header_and_body

GSS_SPNEGO_NEG_TOKEN_INIT_PREFIX = bytes.fromhex(
    "604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a0428"
)
NTLMSSP_OID = bytes.fromhex("2b06010401823702020a")


@dataclass
class SessionSetupResult:
    session_id: int
    session_flags: int
    is_guest: bool
    is_null: bool
    session_key: bytes


def _wrap_spnego_init(ntlm_token: bytes) -> bytes:
    mech_type = b"\x06" + _der_len(len(NTLMSSP_OID)) + NTLMSSP_OID
    mech_list = b"\x30" + _der_len(len(mech_type)) + mech_type
    mech_type_tagged = b"\xa0" + _der_len(len(mech_list)) + mech_list
    ntlm_token_tlv = b"\x04" + _der_len(len(ntlm_token)) + ntlm_token
    token_tagged = b"\xa2" + _der_len(len(ntlm_token_tlv)) + ntlm_token_tlv
    neg_token_init = mech_type_tagged + token_tagged
    neg_token_init_seq = b"\x30" + _der_len(len(neg_token_init)) + neg_token_init
    neg_token_init_tagged = b"\xa0" + _der_len(len(neg_token_init_seq)) + neg_token_init_seq
    spnego_oid = bytes.fromhex("06062b0601050502")
    spnego_body = spnego_oid + neg_token_init_tagged
    spnego_app = b"\x60" + _der_len(len(spnego_body)) + spnego_body
    return spnego_app


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = []
    while length:
        encoded.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(encoded)]) + bytes(encoded)


def _extract_ntlm_from_spnego(blob: bytes) -> bytes:
    index = blob.find(b"NTLMSSP\x00")
    if index == -1:
        raise SMBSessionSetupError("No NTLMSSP token found inside SPNEGO response")
    return blob[index:]


def _wrap_spnego_auth(ntlm_token: bytes) -> bytes:
    ntlm_token_tlv = b"\x04" + _der_len(len(ntlm_token)) + ntlm_token
    token_tagged = b"\xa2" + _der_len(len(ntlm_token_tlv)) + ntlm_token_tlv
    neg_token_resp = token_tagged
    neg_token_resp_seq = b"\x30" + _der_len(len(neg_token_resp)) + neg_token_resp
    neg_token_resp_tagged = b"\xa1" + _der_len(len(neg_token_resp_seq)) + neg_token_resp_seq
    return neg_token_resp_tagged


def _build_session_setup_request(message_id: int, session_id: int, security_buffer: bytes) -> bytes:
    header = build_smb2_header(
        command=SMB2_COM_SESSION_SETUP, message_id=message_id, session_id=session_id
    )
    sec_buffer_offset = 64 + 24
    body = struct.pack("<HBBIIHHQ", 25, 0, 0, 0, 0, sec_buffer_offset, len(security_buffer), 0)
    return header + body + security_buffer


def _parse_session_setup_response(data: bytes):
    header, body = split_header_and_body(data)
    if len(body) < 8:
        raise SMBSessionSetupError("Session setup response body too short")
    structure_size, session_flags = struct.unpack("<HH", body[0:4])
    sec_offset, sec_length = struct.unpack("<HH", body[4:8])
    security_buffer = b""
    full_offset = sec_offset - 64
    if sec_length and 0 <= full_offset <= len(body):
        security_buffer = body[full_offset:full_offset + sec_length]
    return header, session_flags, security_buffer


def probe_ntlm_challenge(transport: SMBTransport) -> bytes:
    ntlm_negotiate = build_negotiate_message()
    spnego_init = _wrap_spnego_init(ntlm_negotiate)

    message_id = transport.next_message_id()
    request = _build_session_setup_request(message_id, 0, spnego_init)
    response = transport.send_and_recv(request)

    header, _, security_buffer = _parse_session_setup_response(response)

    if header.status != STATUS_MORE_PROCESSING_REQUIRED:
        raise SMBSessionSetupError(
            f"Expected STATUS_MORE_PROCESSING_REQUIRED, got 0x{header.status:08x}"
        )

    return _extract_ntlm_from_spnego(security_buffer)


def session_setup(transport: SMBTransport, credentials: Credentials) -> SessionSetupResult:
    ntlm_negotiate = build_negotiate_message()
    spnego_init = _wrap_spnego_init(ntlm_negotiate)

    message_id = transport.next_message_id()
    request = _build_session_setup_request(message_id, 0, spnego_init)
    transport.update_preauth_hash(request)
    response = transport.send_and_recv(request)

    header, session_flags, security_buffer = _parse_session_setup_response(response)

    if header.status != STATUS_MORE_PROCESSING_REQUIRED:
        raise SMBSessionSetupError(
            f"Expected STATUS_MORE_PROCESSING_REQUIRED, got 0x{header.status:08x}",
            status=header.status,
        )
    transport.update_preauth_hash(response)

    challenge_token = _extract_ntlm_from_spnego(security_buffer)
    challenge = parse_challenge_message(challenge_token)

    ntlm_auth, session_key = build_authenticate_message(credentials, challenge)
    spnego_auth = _wrap_spnego_auth(ntlm_auth)

    session_id = header.session_id
    message_id = transport.next_message_id()
    request = _build_session_setup_request(message_id, session_id, spnego_auth)
    transport.update_preauth_hash(request)
    response = transport.send_and_recv(request)

    header, session_flags, _ = _parse_session_setup_response(response)

    if header.status != STATUS_SUCCESS:
        raise SMBSessionSetupError(
            f"Authentication failed with status 0x{header.status:08x}", status=header.status
        )

    # The final (successful) Session Setup response is deliberately NOT
    # folded into the preauth hash: per [MS-SMB2] 3.2.5.3, the signing key
    # is derived from the hash state up to and including the final request,
    # so that the key can be used to verify/trust that very response.
    transport.session_id = header.session_id
    transport.activate_signing(session_key)

    return SessionSetupResult(
        session_id=header.session_id,
        session_flags=session_flags,
        is_guest=bool(session_flags & SMB2_SESSION_FLAG_IS_GUEST),
        is_null=bool(session_flags & SMB2_SESSION_FLAG_IS_NULL),
        session_key=session_key,
    )


def probe_authentication_status(transport: SMBTransport, credentials: Credentials) -> int:
    ntlm_negotiate = build_negotiate_message()
    spnego_init = _wrap_spnego_init(ntlm_negotiate)

    message_id = transport.next_message_id()
    request = _build_session_setup_request(message_id, 0, spnego_init)
    response = transport.send_and_recv(request)

    header, _, security_buffer = _parse_session_setup_response(response)

    if header.status != STATUS_MORE_PROCESSING_REQUIRED:
        return header.status

    challenge_token = _extract_ntlm_from_spnego(security_buffer)
    challenge = parse_challenge_message(challenge_token)

    ntlm_auth, _ = build_authenticate_message(credentials, challenge)
    spnego_auth = _wrap_spnego_auth(ntlm_auth)

    session_id = header.session_id
    message_id = transport.next_message_id()
    request = _build_session_setup_request(message_id, session_id, spnego_auth)
    response = transport.send_and_recv(request)

    header, _, _ = _parse_session_setup_response(response)
    return header.status


def null_session_setup(transport: SMBTransport) -> SessionSetupResult:
    empty_credentials = Credentials(username="", password="", domain="")
    ntlm_negotiate = build_negotiate_message()
    spnego_init = _wrap_spnego_init(ntlm_negotiate)

    message_id = transport.next_message_id()
    request = _build_session_setup_request(message_id, 0, spnego_init)
    transport.update_preauth_hash(request)
    response = transport.send_and_recv(request)

    header, session_flags, security_buffer = _parse_session_setup_response(response)

    if header.status != STATUS_MORE_PROCESSING_REQUIRED:
        if header.status == STATUS_SUCCESS:
            # True anonymous session, no NTLM exchange happened: there is
            # no session key, so there is nothing to sign with.
            transport.session_id = header.session_id
            return SessionSetupResult(
                session_id=header.session_id,
                session_flags=session_flags,
                is_guest=bool(session_flags & SMB2_SESSION_FLAG_IS_GUEST),
                is_null=bool(session_flags & SMB2_SESSION_FLAG_IS_NULL),
                session_key=b"",
            )
        raise SMBSessionSetupError(f"Null session negotiate failed with 0x{header.status:08x}")
    transport.update_preauth_hash(response)

    challenge_token = _extract_ntlm_from_spnego(security_buffer)
    challenge = parse_challenge_message(challenge_token)

    ntlm_auth, session_key = build_authenticate_message(empty_credentials, challenge)
    spnego_auth = _wrap_spnego_auth(ntlm_auth)

    session_id = header.session_id
    message_id = transport.next_message_id()
    request = _build_session_setup_request(message_id, session_id, spnego_auth)
    transport.update_preauth_hash(request)
    response = transport.send_and_recv(request)

    header, session_flags, _ = _parse_session_setup_response(response)

    if header.status != STATUS_SUCCESS:
        raise SMBSessionSetupError(f"Null session authentication failed with 0x{header.status:08x}")

    # Final response deliberately excluded from the preauth hash - see the
    # comment in session_setup() above.
    transport.session_id = header.session_id
    transport.activate_signing(session_key)

    return SessionSetupResult(
        session_id=header.session_id,
        session_flags=session_flags,
        is_guest=bool(session_flags & SMB2_SESSION_FLAG_IS_GUEST),
        is_null=bool(session_flags & SMB2_SESSION_FLAG_IS_NULL),
        session_key=session_key,
    )
