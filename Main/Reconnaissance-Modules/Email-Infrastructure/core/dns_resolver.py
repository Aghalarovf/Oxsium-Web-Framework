import asyncio
from typing import Optional

import dns.asyncresolver
import dns.resolver
import dns.rdatatype
import dns.exception


class DnsResolver:

    def __init__(self, nameserver: Optional[str] = None, timeout: float = 10.0) -> None:
        self._timeout = timeout
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout
        if nameserver:
            self._resolver.nameservers = [nameserver]

    async def query(self, name: str, rdtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rdtype)
            return [r.to_text() for r in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            return []
        except Exception:
            return []

    async def mx(self, domain: str) -> list[dict]:
        try:
            answer = await self._resolver.resolve(domain, "MX")
            records = []
            for r in answer:
                records.append({
                    "priority": r.preference,
                    "host": r.exchange.to_text().rstrip("."),
                })
            return sorted(records, key=lambda x: x["priority"])
        except Exception:
            return []

    async def txt(self, domain: str) -> list[str]:
        records = await self.query(domain, "TXT")
        return [r.strip('"') for r in records]

    async def spf(self, domain: str) -> Optional[str]:
        txts = await self.txt(domain)
        for record in txts:
            if record.startswith("v=spf1"):
                return record
        return None

    async def dmarc(self, domain: str) -> Optional[str]:
        records = await self.query(f"_dmarc.{domain}", "TXT")
        for record in records:
            clean = record.strip('"')
            if clean.startswith("v=DMARC1"):
                return clean
        return None

    async def dkim(self, domain: str, selector: str) -> Optional[str]:
        records = await self.query(f"{selector}._domainkey.{domain}", "TXT")
        for record in records:
            clean = record.strip('"')
            if "v=DKIM1" in clean or "p=" in clean:
                return clean
        return None

    async def cname(self, name: str) -> Optional[str]:
        results = await self.query(name, "CNAME")
        return results[0].rstrip(".") if results else None

    async def a(self, name: str) -> list[str]:
        return await self.query(name, "A")

    async def aaaa(self, name: str) -> list[str]:
        return await self.query(name, "AAAA")

    async def ns(self, domain: str) -> list[str]:
        results = await self.query(domain, "NS")
        return [r.rstrip(".") for r in results]

    async def ptr(self, ip: str) -> Optional[str]:
        results = await self.query(dns.reversename.from_address(ip).to_text(), "PTR")
        return results[0].rstrip(".") if results else None

    async def caa(self, domain: str) -> list[dict]:
        try:
            answer = await self._resolver.resolve(domain, "CAA")
            return [
                {"flags": r.flags, "tag": r.tag.decode(), "value": r.value.decode()}
                for r in answer
            ]
        except Exception:
            return []

    async def tlsa(self, name: str) -> list[dict]:
        try:
            answer = await self._resolver.resolve(name, "TLSA")
            return [
                {
                    "usage": r.usage,
                    "selector": r.selector,
                    "matching_type": r.mtype,
                    "certificate_association": r.cert_association_data.hex(),
                }
                for r in answer
            ]
        except Exception:
            return []

    async def probe_dkim_selectors(self, domain: str, selectors: list[str]) -> dict[str, str]:
        found: dict[str, str] = {}
        tasks = {sel: self.dkim(domain, sel) for sel in selectors}
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for selector, result in zip(tasks.keys(), results):
            if isinstance(result, str) and result:
                found[selector] = result
        return found