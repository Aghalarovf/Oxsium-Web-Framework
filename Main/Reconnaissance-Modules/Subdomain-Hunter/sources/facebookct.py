from __future__ import annotations

from core import BaseSource, SourceError


class FacebookCT(BaseSource):
    name = "facebookct"
    description = "Facebook/Meta CT monitoring (DISCONTINUED upstream - always disabled)"
    enabled = False
    default_timeout = 10

    def fetch(self, domain: str) -> set[str]:
        raise SourceError(
            "Meta discontinued the Facebook CT API; this source can no longer be "
            "queried (removed from subfinder v2.14.0 as well). Consider crt.name "
            "or MerkleMap instead."
        )
