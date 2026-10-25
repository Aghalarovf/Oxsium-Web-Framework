from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class EngineConfig:
    targets: List[str] = field(default_factory=list)
    port: int = 445
    username: str = ""
    password: str = ""
    ntlm_hash: str = ""
    domain: str = ""

    mode_name: str = "normal"
    threads: int = 10
    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    retries: int = 1
    jitter_min: float = 0.0
    jitter_max: float = 0.0

    run_common: bool = False
    run_info: bool = False
    run_dc: bool = False
    run_vuln: bool = False
    custom_modules: List[str] = field(default_factory=list)

    output_path: Optional[str] = None
    verbosity: int = 1
    log_level: int = 20

    def using_hash_auth(self) -> bool:
        return bool(self.ntlm_hash) and not self.password

    def has_credentials(self) -> bool:
        return bool(self.username) and (bool(self.password) or bool(self.ntlm_hash))
