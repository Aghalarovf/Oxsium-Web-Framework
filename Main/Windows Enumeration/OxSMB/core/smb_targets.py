import ipaddress
from dataclasses import dataclass
from typing import Iterator, List


@dataclass
class Target:
    host: str
    port: int = 445

    def __str__(self):
        return self.host


def expand_target_spec(spec: str) -> Iterator[str]:
    spec = spec.strip()
    if not spec:
        return
    if "/" in spec:
        network = ipaddress.ip_network(spec, strict=False)
        for address in network.hosts():
            yield str(address)
        return
    if "-" in spec and "." in spec:
        base, _, last = spec.rpartition(".")
        start_str, _, end_str = last.partition("-")
        start = int(start_str)
        end = int(end_str) if end_str else start
        for octet in range(start, end + 1):
            yield f"{base}.{octet}"
        return
    yield spec


def build_target_list(raw_targets: List[str], port: int) -> List[Target]:
    targets: List[Target] = []
    seen = set()
    for raw in raw_targets:
        for host in expand_target_spec(raw):
            if host in seen:
                continue
            seen.add(host)
            targets.append(Target(host=host, port=port))
    return targets


def load_targets_from_file(path: str) -> List[str]:
    with open(path, "r") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]
