from core.exceptions import OxSMBError
from core.smb_transport import SMBTransport
from protocol.smb.smb_constants import ALL_SMB2_DIALECTS, DIALECT_NAMES, SMB2_DIALECT_2_0_2
from protocol.smb.smb_negotiate import negotiate

MODULE_NAME = "smbdialectdowngradechecker"

WEAK_DIALECTS = [SMB2_DIALECT_2_0_2]


def _classify(preferred_dialect: int, downgrade_accepted: bool) -> str:
    if preferred_dialect in WEAK_DIALECTS:
        return "not_applicable"
    if downgrade_accepted:
        return "downgradable"
    return "not_downgradable"


def run(host: str, port: int = 445, connect_timeout: float = 5.0, read_timeout: float = 5.0) -> dict:
    baseline_transport = SMBTransport(
        host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout
    )
    try:
        baseline_transport.connect()
        baseline_result = negotiate(baseline_transport, dialects=ALL_SMB2_DIALECTS)
    except (OxSMBError, OSError) as exc:
        return {
            "module": MODULE_NAME,
            "target": host,
            "status": "error",
            "data": None,
            "error": str(exc),
        }
    finally:
        baseline_transport.close()

    downgrade_accepted = False
    forced_dialect = ""

    downgrade_transport = SMBTransport(
        host=host, port=port, connect_timeout=connect_timeout, read_timeout=read_timeout
    )
    try:
        downgrade_transport.connect()
        downgrade_result = negotiate(downgrade_transport, dialects=WEAK_DIALECTS)
        downgrade_accepted = downgrade_result.dialect_revision in WEAK_DIALECTS
        forced_dialect = DIALECT_NAMES.get(
            downgrade_result.dialect_revision, hex(downgrade_result.dialect_revision)
        )
    except (OxSMBError, OSError):
        downgrade_accepted = False
    finally:
        downgrade_transport.close()

    downgrade_state = _classify(baseline_result.dialect_revision, downgrade_accepted)

    data = {
        "preferred_dialect": DIALECT_NAMES.get(
            baseline_result.dialect_revision, hex(baseline_result.dialect_revision)
        ),
        "offered_weak_dialects": [DIALECT_NAMES.get(d, hex(d)) for d in WEAK_DIALECTS],
        "downgrade_accepted": downgrade_accepted,
        "forced_dialect": forced_dialect,
        "downgrade_state": downgrade_state,
        "downgrade_possible": downgrade_state == "downgradable",
    }

    return {
        "module": MODULE_NAME,
        "target": host,
        "status": "ok",
        "data": data,
        "error": None,
    }
