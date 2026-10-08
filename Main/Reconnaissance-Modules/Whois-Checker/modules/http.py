from __future__ import annotations

from typing import List

from core.models import HttpProbe
from core.net import Net


def probe(net: Net, domain: str) -> List[HttpProbe]:
    probes: List[HttpProbe] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        code, headers, final = net.http_headers(url)
        probes.append(HttpProbe(url=url, status=code, final_url=final, headers=headers))
    return probes