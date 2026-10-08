import asyncio
import sys
import io
from typing import Optional

if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf-8-sig'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ('utf-8', 'utf-8-sig'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from .dns_resolver import DnsResolver
from .logger import Logger
from .requester import Requester
from .exporter import Exporter


class Engine:

    def __init__(
        self,
        domains: list[str],
        active_modules: dict[str, bool],
        output_file: Optional[str] = None,
        color: bool = True,
        timeout: float = 10.0,
        concurrency: int = 10,
        nameserver: Optional[str] = None,
    ) -> None:
        self._domains = domains
        self._active_modules = active_modules
        self._output_file = output_file
        self._timeout = timeout
        self._concurrency = concurrency
        self._logger = Logger(color=color)
        self._resolver = DnsResolver(nameserver=nameserver, timeout=timeout)
        self._requester = Requester(timeout=timeout, concurrency=concurrency)
        self._semaphore = asyncio.Semaphore(concurrency)
        self._results: dict[str, dict] = {}

    async def run(self) -> dict:
        try:
            self._logger.banner()
            self._logger.info(f"Starting enumeration for {len(self._domains)} domain(s)")

            tasks = [self._enumerate_domain(domain) for domain in self._domains]
            await asyncio.gather(*tasks)

            self._logger.report(self._results)

            if self._output_file:
                exporter = Exporter(self._results)
                exporter.export(self._output_file)
                self._logger.success(f"Results exported to {self._output_file}")

            return self._results
        finally:
            await self._requester.close()

    async def _enumerate_domain(self, domain: str) -> None:
        async with self._semaphore:
            self._logger.section(f"Domain: {domain}")
            domain_result: dict = {}

            module_tasks = []

            harvested_emails: list[str] = []
            if self._active_modules.get("harvest_recon"):
                try:
                    harvest_result = await self._run_harvest_recon(domain)
                except Exception as exc:
                    self._logger.error(f"[harvest_recon] Module failed: {exc}")
                    domain_result["harvest_recon"] = {"error": str(exc)}
                else:
                    domain_result["harvest_recon"] = harvest_result
                    harvested_emails = harvest_result.get("harvested_emails", [])

            if self._active_modules.get("dns_sec"):
                module_tasks.append(("dns_sec", self._run_dns_sec(domain)))
            if self._active_modules.get("provider_gateways"):
                module_tasks.append(("provider_gateways", self._run_provider_gateways(domain)))
            if self._active_modules.get("breaches"):
                module_tasks.append(("breaches", self._run_breaches(domain, harvested_emails)))
            if self._active_modules.get("service_config"):
                module_tasks.append(("service_config", self._run_service_config(domain)))
            if self._active_modules.get("history_subdomains"):
                module_tasks.append(("history_subdomains", self._run_history_subdomains(domain)))
            if self._active_modules.get("exchange"):
                module_tasks.append(("exchange", self._run_exchange_recon(domain)))

            if not module_tasks and not domain_result:
                self._logger.warning("No modules selected. Use --all or specify module flags.")
                return

            results = await asyncio.gather(
                *[task for _, task in module_tasks],
                return_exceptions=True,
            )

            exchange_findings: list[dict] = []
            for (module_name, _), result in zip(module_tasks, results):
                if isinstance(result, Exception):
                    self._logger.error(f"[{module_name}] Module failed: {result}")
                    domain_result[module_name] = {"error": str(result)}
                else:
                    domain_result[module_name] = result
                    if module_name == "exchange":
                        exchange_findings = result.get("findings", [])

            if self._active_modules.get("ntlm"):
                try:
                    ntlm_result = await self._run_exchange_ntlm_recon(domain, exchange_findings)
                except Exception as exc:
                    self._logger.error(f"[ntlm] Module failed: {exc}")
                    domain_result["ntlm"] = {"error": str(exc)}
                else:
                    domain_result["ntlm"] = ntlm_result

            test_emails: list[str] = self._active_modules.get("test_emails", [])
            if test_emails:
                try:
                    email_val_result = await self._run_email_validation(domain, test_emails)
                except Exception as exc:
                    self._logger.error(f"[email-validation] Module failed: {exc}")
                    domain_result["email_validation"] = {"error": str(exc)}
                else:
                    domain_result["email_validation"] = email_val_result

            self._results[domain] = domain_result

    async def _run_dns_sec(self, domain: str) -> dict:
        from modules.dns_security import DNSSecModule, DNSHardeningModule

        self._logger.info(f"[DNS-SEC] Running DNS security analysis for {domain}")
        sec_module = DNSSecModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        sec_result = await sec_module.run(domain)

        self._logger.info(f"[DNS-HARD] Running DNS hardening checks for {domain}")
        hard_module = DNSHardeningModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        hard_result = await hard_module.run(domain)

        return {**sec_result, **hard_result}

    async def _run_provider_gateways(self, domain: str) -> dict:
        from modules.provider_gateways import ProviderGatewaysModule
        self._logger.info(f"[PROVIDER-GW] Identifying providers and gateways for {domain}")
        module = ProviderGatewaysModule(resolver=self._resolver, logger=self._logger)
        return await module.run(domain)

    async def _run_harvest_recon(self, domain: str) -> dict:
        from modules.harvest_recon import HarvestReconModule
        self._logger.info(f"[HARVEST-RECON] Running public email harvest for {domain}")
        module = HarvestReconModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        return await module.run(domain)

    async def _run_breaches(self, domain: str, harvested_emails: list[str] | None = None) -> dict:
        from modules.email_breaches import BreachesModule
        self._logger.info(f"[BREACHES] Running email breach analysis for {domain}")
        module = BreachesModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        return await module.run(domain)

    async def _run_service_config(self, domain: str) -> dict:
        from modules.service_config import ServiceConfigModule
        self._logger.info(f"[SERVICE-CFG] Checking service configurations for {domain}")
        module = ServiceConfigModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        return await module.run(domain)

    async def _run_exchange_recon(self, domain: str) -> dict:
        from modules.exchange_recon import ExchangeReconModule
        self._logger.info(f"[EXCHANGE-RECON] Running Exchange & webmail recon for {domain}")
        module = ExchangeReconModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        return await module.run(domain)

    async def _run_exchange_ntlm_recon(self, domain: str, exchange_findings: list[dict] | None = None) -> dict:
        from modules.exchange_ntlm_recon import ExchangeNtlmReconModule
        self._logger.info(f"[NTLM-RECON] Running OWA/ECP fingerprinting for {domain}")
        module = ExchangeNtlmReconModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        return await module.run(domain, exchange_findings=exchange_findings)

    async def _run_email_validation(self, domain: str, emails: list[str]) -> dict:
        from modules.exchange_ntlm_recon import ExchangeNtlmReconModule
        self._logger.info(
            f"[EMAIL-VALIDATION] Validating {len(emails)} email(s) via Autodiscover v2 for {domain}"
        )
        module = ExchangeNtlmReconModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        return await module.run_email_validation(domain, emails)

    async def _run_history_subdomains(self, domain: str) -> dict:
        from modules.history_subdomains import HistorySubdomainsModule
        self._logger.info(f"[HISTORY-SD] Discovering subdomain mail history for {domain}")
        module = HistorySubdomainsModule(
            resolver=self._resolver,
            logger=self._logger,
            requester=self._requester,
        )
        return await module.run(domain, harvested_emails=harvested_emails)