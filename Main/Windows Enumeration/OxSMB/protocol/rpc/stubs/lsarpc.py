from dataclasses import dataclass
from typing import List, Optional

from core.exceptions import NDRError, RPCCallError
from protocol.rpc.ndr import NDRReader, NDRWriter
from protocol.rpc.rpc_channel import RPCChannel
from protocol.rpc.rpc_constants import (
    LSAR_CLOSE,
    LSAR_OPEN_POLICY2,
    LSAR_QUERY_INFO_POLICY,
)

CONTEXT_HANDLE_LEN = 20

POLICY_VIEW_LOCAL_INFORMATION = 0x00000001
POLICY_VIEW_AUDIT_INFORMATION = 0x00000002
POLICY_GET_PRIVATE_INFORMATION = 0x00000004
POLICY_TRUST_ADMIN = 0x00000008
POLICY_CREATE_ACCOUNT = 0x00000010
POLICY_LOOKUP_NAMES = 0x00000800
MAXIMUM_ALLOWED = 0x02000000

POLICY_DEFAULT_ACCESS = (
    POLICY_VIEW_LOCAL_INFORMATION
    | POLICY_VIEW_AUDIT_INFORMATION
    | POLICY_LOOKUP_NAMES
)

POLICY_AUDIT_LOG_INFORMATION = 1
POLICY_AUDIT_EVENTS_INFORMATION = 2
POLICY_PRIMARY_DOMAIN_INFORMATION = 3
POLICY_ACCOUNT_DOMAIN_INFORMATION = 5
POLICY_LSA_SERVER_ROLE_INFORMATION = 6

STATUS_SUCCESS = 0x00000000


@dataclass
class AuditLogInfo:
    audit_log_percent_full: int
    maximum_log_size: int
    audit_retention_period_low: int
    audit_retention_period_high: int
    audit_log_full_shutdown_in_progress: bool
    next_audit_record_id: int


@dataclass
class PrimaryDomainInfo:
    domain_name: str
    domain_sid: Optional[str]


def _build_object_attributes() -> bytes:
    writer = NDRWriter()
    writer.uint32(24)
    writer.uint32(0)
    writer.uint32(0)
    writer.uint32(0)
    writer.uint32(0)
    writer.uint32(0)
    return writer.getvalue()


def _build_open_policy2_request(system_name: str, desired_access: int) -> bytes:
    writer = NDRWriter()
    writer.referent_id(0x00020000)
    writer.unicode_string_ptr(system_name)
    writer.raw(_build_object_attributes())
    writer.uint32(desired_access)
    return writer.getvalue()


def _parse_handle_response(data: bytes, call_name: str) -> bytes:
    reader = NDRReader(data)
    reader.align(4)
    handle = reader.raw(CONTEXT_HANDLE_LEN)
    return_code = reader.uint32()
    if return_code != STATUS_SUCCESS:
        raise RPCCallError(f"{call_name} returned NTSTATUS 0x{return_code:08x}")
    return handle


def open_policy2(
    channel: RPCChannel, system_name: str = "", desired_access: int = POLICY_DEFAULT_ACCESS
) -> bytes:
    request_stub = _build_open_policy2_request(system_name, desired_access)
    response_stub = channel.call(LSAR_OPEN_POLICY2, request_stub)
    try:
        return _parse_handle_response(response_stub, "LsarOpenPolicy2")
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse LsarOpenPolicy2 response: {exc}") from exc


def close_policy_handle(channel: RPCChannel, handle: bytes):
    writer = NDRWriter()
    writer.align(4)
    writer.raw(handle)
    try:
        channel.call(LSAR_CLOSE, writer.getvalue())
    except RPCCallError:
        pass


def _parse_rpc_sid(reader: NDRReader) -> str:
    reader.align(4)
    reader.uint32()
    revision = reader.uint8()
    sub_authority_count = reader.uint8()
    authority = reader.raw(6)
    identifier_authority = int.from_bytes(authority, "big")
    sub_authorities = [reader.uint32() for _ in range(sub_authority_count)]
    parts = "-".join(str(value) for value in sub_authorities)
    sid = f"S-{revision}-{identifier_authority}"
    if parts:
        sid = f"{sid}-{parts}"
    return sid


def _build_query_info_policy_request(handle: bytes, information_class: int) -> bytes:
    writer = NDRWriter()
    writer.align(4)
    writer.raw(handle)
    writer.uint16(information_class)
    return writer.getvalue()


def query_information_policy(
    channel: RPCChannel, handle: bytes, information_class: int
) -> NDRReader:
    request_stub = _build_query_info_policy_request(handle, information_class)
    response_stub = channel.call(LSAR_QUERY_INFO_POLICY, request_stub)
    reader = NDRReader(response_stub)
    info_referent = reader.uint32()
    if info_referent == 0:
        return_code = reader.uint32() if len(response_stub) >= 8 else 0
        raise RPCCallError(
            f"LsarQueryInformationPolicy returned a NULL PolicyInformation pointer, NTSTATUS 0x{return_code:08x}"
        )
    reader.uint16()
    reader.align(4)
    return reader


def query_audit_log_information(channel: RPCChannel, handle: bytes) -> AuditLogInfo:
    try:
        reader = query_information_policy(channel, handle, POLICY_AUDIT_LOG_INFORMATION)
        audit_log_percent_full = reader.uint32()
        maximum_log_size = reader.uint32()
        retention_low = reader.uint32()
        retention_high = reader.uint32()
        shutdown_flag = reader.uint8()
        reader.align(4)
        reader.uint32()
        reader.uint32()
        next_audit_record_id = reader.uint32()
        return_code = reader.uint32()
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse POLICY_AUDIT_LOG_INFO: {exc}") from exc

    if return_code != STATUS_SUCCESS:
        raise RPCCallError(f"LsarQueryInformationPolicy(AuditLog) returned NTSTATUS 0x{return_code:08x}")

    return AuditLogInfo(
        audit_log_percent_full=audit_log_percent_full,
        maximum_log_size=maximum_log_size,
        audit_retention_period_low=retention_low,
        audit_retention_period_high=retention_high,
        audit_log_full_shutdown_in_progress=bool(shutdown_flag),
        next_audit_record_id=next_audit_record_id,
    )


def query_primary_domain_information(channel: RPCChannel, handle: bytes) -> PrimaryDomainInfo:
    try:
        reader = query_information_policy(channel, handle, POLICY_PRIMARY_DOMAIN_INFORMATION)
        domain_name = reader.read_rrp_unicode_string()
        sid_referent = reader.uint32()
        domain_sid = _parse_rpc_sid(reader) if sid_referent != 0 else None
        return_code = reader.uint32()
    except NDRError as exc:
        raise RPCCallError(f"Failed to parse POLICY_PRIMARY_DOMAIN_INFO: {exc}") from exc

    if return_code != STATUS_SUCCESS:
        raise RPCCallError(f"LsarQueryInformationPolicy(PrimaryDomain) returned NTSTATUS 0x{return_code:08x}")

    return PrimaryDomainInfo(domain_name=domain_name, domain_sid=domain_sid)
