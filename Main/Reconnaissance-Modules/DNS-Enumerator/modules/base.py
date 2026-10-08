from abc import ABC
import dns.flags
import dns.resolver
import requests


class BaseDNSModule(ABC):
    def __init__(self, domain: str, resolver: dns.resolver.Resolver, session: requests.Session):
        self.domain   = domain
        self.resolver = resolver
        self.session  = session

        if not hasattr(self.resolver, '_custom_ns') or not self.resolver._custom_ns:
            self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        self.resolver.use_edns(0, dns.flags.DO, 4096)