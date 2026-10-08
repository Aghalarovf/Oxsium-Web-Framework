import dns.resolver
import requests
import urllib3

from core.ui import info

urllib3.disable_warnings()


def build_resolver(proxy: str = None, port: int = 53, nameservers: list = None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.port = port
    resolver.timeout = 5
    resolver.lifetime = 10
    if nameservers:
        resolver.nameservers = nameservers
        resolver._custom_ns  = True
        info(f"Using custom nameserver(s): {', '.join(nameservers)}")
    if port != 53:
        info(f"Using DNS port {port}")
    return resolver


def get_session(proxy: str = None) -> requests.Session:
    session = requests.Session()
    session.verify = False
    session.timeout = 10
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        info(f"HTTP proxy set: {proxy}")
    return session